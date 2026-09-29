//! Versioned, authenticated revocation snapshots with persisted rollback protection.
//!
//! Local accepted-state storage and the system clock are trusted. Restore the accepted
//! snapshot with its high-water state; rolling back the whole trusted volume requires
//! an external recovery checkpoint. Legacy unversioned lists require explicit reissue.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine as _;
use serde_json::{Map, Value, json};

use crate::canonical::canonicalize;
use crate::error::{Error, ErrorKind, Result};
use crate::json::{as_integer, strict_json};
use crate::keys::{key_id, public_from_private, sign, verify};
use crate::storage::{FileLock, atomic_json};
use crate::validation::{MAX_INTEGER, integer_value, mapping, string_value};

fn revocation_error(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::Revocation, message)
}

pub fn now_epoch() -> f64 {
    crate::isotime::timestamp(&chrono::Utc::now())
}

/// Strict standard base64 (`b64decode(..., validate=True)`).
pub fn b64_strict(text: &Value) -> Result<Vec<u8>> {
    let Value::String(text) = text else {
        return Err(Error::value(
            "argument should be a bytes-like object or ASCII string",
        ));
    };
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    );
    engine
        .decode(text)
        .map_err(|_| Error::value("Incorrect padding"))
}

fn field<'a>(doc: &'a Map<String, Value>, name: &str) -> Result<&'a Value> {
    doc.get(name)
        .ok_or_else(|| Error::value(format!("'{name}'")))
}

fn body_without_sig(doc: &Map<String, Value>) -> Value {
    Value::Object(
        doc.iter()
            .filter(|(k, _)| k.as_str() != "sig")
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    )
}

fn validate_inner(doc: &Value, public_str: &str, now: Option<f64>, fresh: bool) -> Result<()> {
    let doc = mapping(
        doc,
        &[
            "version",
            "domain",
            "seq",
            "issued_at",
            "next_update",
            "revoked",
            "sig",
        ],
        "revocation",
    )?;
    let body = body_without_sig(doc);
    let signature = b64_strict(field(doc, "sig")?)?;
    verify(public_str, &signature, &canonicalize(&body)?)?;
    let version_ok = as_integer(field(doc, "version")?) == Some(1)
        && crate::validation::is_int(field(doc, "version")?);
    if !version_ok || field(doc, "domain")?.as_str() != Some(key_id(public_str)?.as_str()) {
        return Err(Error::value("wrong revocation version or domain"));
    }
    integer_value(field(doc, "seq")?, "seq", 0, MAX_INTEGER)?;
    let issued = integer_value(field(doc, "issued_at")?, "issued_at", 0, MAX_INTEGER)?;
    let expiry = integer_value(field(doc, "next_update")?, "next_update", 0, MAX_INTEGER)?;
    if !(issued < expiry && expiry <= issued + 86400) {
        return Err(Error::value("invalid revocation freshness interval"));
    }
    let ids = match field(doc, "revoked")? {
        Value::Array(ids) if ids.len() <= 100_000 => ids,
        _ => return Err(Error::value("invalid revocation ids")),
    };
    let mut seen = HashSet::new();
    for id in ids {
        let id = string_value(Some(id), "revocation id", 512)?;
        if !seen.insert(id) {
            return Err(Error::value("duplicate revocation id"));
        }
    }
    if fresh {
        let now = now.unwrap_or_else(now_epoch);
        if issued as f64 > now + 30.0 || expiry as f64 <= now {
            return Err(Error::value(
                "revocation snapshot expired or from the future",
            ));
        }
    }
    Ok(())
}

/// Check a signed snapshot; `fresh` also requires it to be current at `now`.
pub fn validate_document(
    doc: &Value,
    public_str: &str,
    now: Option<f64>,
    fresh: bool,
) -> Result<()> {
    validate_inner(doc, public_str, now, fresh)
        .map_err(|e| revocation_error(format!("invalid revocation snapshot: {}", e.message)))
}

/// Sign a snapshot of `revoked` (sorted, deduplicated).
pub fn sign_revocation_list(
    revoked: &[String],
    signing_private_str: &str,
    seq: Option<i128>,
    now: Option<f64>,
    ttl_seconds: i128,
) -> Result<Value> {
    crate::validation::integer(ttl_seconds, "revocation ttl", 1, 86400)?;
    let issued = now.unwrap_or_else(now_epoch).floor() as i128;
    let public = public_from_private(signing_private_str)?;
    let mut ids: Vec<String> = revoked.to_vec();
    ids.sort();
    ids.dedup();
    let seq = seq
        .unwrap_or_else(|| (chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) / 1000) as i128);
    let body = json!({
        "version": 1,
        "domain": key_id(&public)?,
        "seq": crate::json::int(seq),
        "issued_at": crate::json::int(issued),
        "next_update": crate::json::int(issued + ttl_seconds),
        "revoked": ids,
    });
    let signature = sign(signing_private_str, &canonicalize(&body)?)?;
    let mut result = body.as_object().expect("object").clone();
    result.insert(
        "sig".into(),
        Value::String(base64::engine::general_purpose::STANDARD.encode(signature)),
    );
    let result = Value::Object(result);
    validate_document(&result, &public, Some(issued as f64), true)?;
    Ok(result)
}

/// Anything that can tell whether one of a mandate's identifiers is revoked.
pub trait RevocationSource: Send + Sync {
    /// The first revoked identifier, if any. Errors mean "cannot tell": fail closed.
    fn any_revoked(&self, identifiers: &[String]) -> Result<Option<String>>;
    /// The last reload failure while a still-fresh snapshot stays in force.
    fn last_error(&self) -> Option<String>;
}

struct ListState {
    revoked: HashSet<String>,
    doc: Option<Value>,
    last_error: Option<String>,
}

/// The hot-reloaded, signed revocation list the proxy consults on every call.
pub struct RevocationList {
    pub path: PathBuf,
    pub public_str: String,
    pub state_path: PathBuf,
    now_fn: Box<dyn Fn() -> f64 + Send + Sync>,
    state: Mutex<ListState>,
}

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut raw = path.as_os_str().to_owned();
    raw.push(suffix);
    PathBuf::from(raw)
}

impl RevocationList {
    pub fn new(
        path: impl Into<PathBuf>,
        public_str: &str,
        state_path: Option<PathBuf>,
        now_fn: Option<Box<dyn Fn() -> f64 + Send + Sync>>,
    ) -> Result<Self> {
        let path = path.into();
        let list = Self {
            state_path: state_path.unwrap_or_else(|| append_suffix(&path, ".accepted")),
            path,
            public_str: public_str.to_owned(),
            now_fn: now_fn.unwrap_or_else(|| Box::new(now_epoch)),
            state: Mutex::new(ListState {
                revoked: HashSet::new(),
                doc: None,
                last_error: None,
            }),
        };
        list.reload()?;
        Ok(list)
    }

    fn accept(&self) -> Result<Value> {
        let doc = strict_json(std::fs::read(&self.path)?)?;
        validate_document(&doc, &self.public_str, Some((self.now_fn)()), true)?;
        let _lock = FileLock::acquire(&self.state_path)?;
        let prior = if self.state_path.exists() {
            let prior = strict_json(std::fs::read(&self.state_path)?)?;
            validate_document(&prior, &self.public_str, None, false)?;
            Some(prior)
        } else {
            None
        };
        if let Some(prior) = &prior {
            let (new_seq, old_seq) = (as_integer(&doc["seq"]), as_integer(&prior["seq"]));
            if new_seq < old_seq {
                return Err(revocation_error("revocation rollback refused"));
            }
            if new_seq == old_seq && &doc != prior {
                return Err(revocation_error(
                    "revocation sequence reused for different content",
                ));
            }
        }
        if prior.as_ref() != Some(&doc) {
            atomic_json(&self.state_path, &doc)?;
        }
        Ok(doc)
    }

    /// Re-read the snapshot. A failure keeps the previous authenticated view only while
    /// it is still fresh; past its `next_update`, every check fails closed.
    pub fn reload(&self) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::runtime("revocation lock poisoned"))?;
        match self.accept() {
            Ok(doc) => {
                state.revoked = doc["revoked"]
                    .as_array()
                    .map(|ids| {
                        ids.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default();
                state.doc = Some(doc);
                state.last_error = None;
                Ok(())
            }
            Err(e) => {
                let message = format!("revocation reload failed: {}", e.message);
                state.last_error = Some(message.clone());
                let stale = match &state.doc {
                    None => true,
                    Some(doc) => {
                        let next = as_integer(&doc["next_update"]).unwrap_or(0) as f64;
                        (self.now_fn)() >= next
                    }
                };
                if stale {
                    Err(revocation_error(message))
                } else {
                    Ok(())
                }
            }
        }
    }
}

impl RevocationSource for RevocationList {
    fn any_revoked(&self, identifiers: &[String]) -> Result<Option<String>> {
        self.reload()?;
        let state = self
            .state
            .lock()
            .map_err(|_| Error::runtime("revocation lock poisoned"))?;
        Ok(identifiers
            .iter()
            .find(|id| state.revoked.contains(*id))
            .cloned())
    }

    fn last_error(&self) -> Option<String> {
        self.state.lock().ok().and_then(|s| s.last_error.clone())
    }
}

/// A fixed set of revoked identifiers (tests, embedding).
pub struct StaticRevocations(pub HashSet<String>);

impl RevocationSource for StaticRevocations {
    fn any_revoked(&self, identifiers: &[String]) -> Result<Option<String>> {
        Ok(identifiers.iter().find(|id| self.0.contains(*id)).cloned())
    }

    fn last_error(&self) -> Option<String> {
        None
    }
}

/// Serialize the entire read/verify/update/sign/replace operation.
pub fn update_revocation_list(
    path: impl AsRef<Path>,
    private_str: &str,
    additions: &[String],
) -> Result<Value> {
    let path = path.as_ref();
    let _lock = FileLock::acquire(path)?;
    let accepted = append_suffix(path, ".accepted");
    let candidate = if path.exists() {
        Some(path.to_path_buf())
    } else if accepted.exists() {
        Some(accepted)
    } else {
        None
    };
    let prior = match candidate {
        Some(file) => {
            let doc = strict_json(std::fs::read(file)?)?;
            validate_document(&doc, &public_from_private(private_str)?, None, false)?;
            Some(doc)
        }
        None => None,
    };
    let mut revoked: Vec<String> = prior
        .as_ref()
        .and_then(|p| p["revoked"].as_array())
        .map(|ids| {
            ids.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    revoked.extend(additions.iter().cloned());
    let now_micros = (chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) / 1000) as i128;
    let sequence = now_micros.max(
        prior
            .as_ref()
            .and_then(|p| as_integer(&p["seq"]))
            .map_or(0, |s| s + 1),
    );
    let doc = sign_revocation_list(&revoked, private_str, Some(sequence), None, 3600)?;
    atomic_json(path, &doc)?;
    Ok(doc)
}

/// Explicit conversion: authenticate every old entry before assigning fresh metadata.
pub fn migrate_legacy_list(document: &Value, old_public: &str, new_private: &str) -> Result<Value> {
    let doc = mapping(document, &["revoked", "sig"], "legacy revocation")?;
    let ids = match (doc.len(), doc.get("revoked")) {
        (2, Some(Value::Array(ids))) => ids,
        _ => return Err(revocation_error("not a legacy revocation document")),
    };
    let mut revoked = Vec::new();
    for id in ids {
        revoked.push(string_value(Some(id), "revocation id", 512)?.to_owned());
    }
    let signature = b64_strict(field(doc, "sig")?)?;
    verify(
        old_public,
        &signature,
        &canonicalize(&json!({"revoked": ids}))?,
    )?;
    sign_revocation_list(&revoked, new_private, None, None, 3600)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_and_reuse_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revoked.list");
        let kp = crate::keys::generate_keypair();
        let now = now_epoch();
        let doc =
            sign_revocation_list(&["a".into()], &kp.private_str, Some(5), Some(now), 3600).unwrap();
        atomic_json(&path, &doc).unwrap();
        let list = RevocationList::new(&path, &kp.public_str, None, None).unwrap();
        assert_eq!(
            list.any_revoked(&["a".into()]).unwrap().as_deref(),
            Some("a")
        );
        let older = sign_revocation_list(&[], &kp.private_str, Some(4), Some(now), 3600).unwrap();
        atomic_json(&path, &older).unwrap();
        // The previous snapshot is still fresh: the rollback is reported, not applied.
        assert_eq!(
            list.any_revoked(&["a".into()]).unwrap().as_deref(),
            Some("a")
        );
        assert!(list.last_error().unwrap().contains("rollback"));
    }
}
