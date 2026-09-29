//! Signed, append-only, hash-chained audit log.
//!
//! One JSON line per gateway decision — every enforced call, every refused method,
//! every rejected batch. Each entry embeds the previous entry's hash (chain) and is
//! Ed25519-signed with the proxy's own audit key. NOTE: a compromised proxy can
//! rewrite and re-sign its own log; production must anchor the head hash externally
//! at intervals (`audit-head`). The chain still detects silent tampering by any party
//! without the audit key.
//!
//! The detailed refusal reason lives HERE and only here: the client gets an opaque
//! correlation id, so an attacker cannot use denials as an oracle.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value, json};

use crate::canonical::{canonicalize, sha256_hex};
use crate::error::{Error, ErrorKind, Result, py_repr};
use crate::isotime::iso_z;
use crate::json::{dumps, strict_json};
use crate::keys::{key_id, public_from_private, sign, verify};
use crate::revocation::b64_strict;
use crate::storage::FileLock;

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Archived segments (`<name>.partNNNNNNNN`, sorted) then the active file.
pub fn segments(path: &Path) -> Vec<PathBuf> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let mut archives: Vec<PathBuf> = std::fs::read_dir(&parent)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    let file = e.file_name().to_string_lossy().into_owned();
                    file.strip_prefix(&name)
                        .and_then(|rest| rest.strip_prefix(".part"))
                        .is_some_and(|digits| {
                            digits.len() == 8 && digits.bytes().all(|b| b.is_ascii_digit())
                        })
                })
                .map(|e| parent.join(e.file_name()))
                .collect()
        })
        .unwrap_or_default();
    archives.sort();
    if path.exists() {
        archives.push(path.to_path_buf());
    }
    archives
}

/// Every line of every segment, numbered across segments from 1.
fn lines(path: &Path) -> Result<Vec<(usize, String)>> {
    let mut out = Vec::new();
    for segment in segments(path) {
        let reader = BufReader::new(std::fs::File::open(segment)?);
        for line in reader.lines() {
            out.push((out.len() + 1, line?));
        }
    }
    Ok(out)
}

/// Offline verification result (`tokencrumb audit-verify`).
#[derive(Debug, Clone, PartialEq)]
pub struct VerifyResult {
    pub entries: usize,
    pub ok: bool,
    /// (line number, reason)
    pub failures: Vec<(usize, String)>,
    pub head: String,
}

impl VerifyResult {
    fn fail(&mut self, line: usize, reason: impl Into<String>) {
        self.ok = false;
        self.failures.push((line, reason.into()));
    }

    /// Python's rendering of `failures[:1]`, used in refusal messages.
    pub fn first_failure_repr(&self) -> String {
        match self.failures.first() {
            Some((line, reason)) => format!("[({line}, {})]", py_repr(reason)),
            None => "[]".into(),
        }
    }
}

/// Trusted audit keys, by key id.
pub type TrustedKeys = HashMap<String, String>;

pub fn trusted_from(publics: &[String]) -> Result<TrustedKeys> {
    publics
        .iter()
        .map(|p| Ok((key_id(p)?, p.clone())))
        .collect()
}

fn value_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => dumps(other),
    }
}

/// Verify hash, signature and chain continuity of an audit log, line by line.
///
/// Tolerant of entries written before v0.1.1 (no `seq`): the sequence check is only
/// applied between two entries that both carry one.
pub fn verify_log(path: &Path, trusted: &TrustedKeys) -> Result<VerifyResult> {
    if segments(path).is_empty() {
        return Err(Error::new(ErrorKind::NotFound, path.display().to_string()));
    }
    let mut result = VerifyResult {
        entries: 0,
        ok: true,
        failures: Vec::new(),
        head: GENESIS.into(),
    };
    let mut prev_hash = Value::String(GENESIS.into());
    let mut prev_seq: Option<f64> = None;
    for (line_no, line) in lines(path)? {
        let line = crate::validation::py_strip(&line);
        if line.is_empty() {
            continue;
        }
        result.entries += 1;
        let parsed = strict_json(line).and_then(|record| {
            let entry = record
                .get("entry")
                .cloned()
                .ok_or_else(|| Error::value("'entry'"))?;
            if !entry.is_object() {
                return Err(Error::value("entry must be an object"));
            }
            let payload = canonicalize(&entry)?;
            Ok((record, entry, payload))
        });
        let (record, entry, payload) = match parsed {
            Ok(parts) => parts,
            Err(e) => {
                result.fail(line_no, format!("unreadable entry: {}", e.message));
                result.head = value_text(&prev_hash);
                return Ok(result); // the chain cannot be followed past a broken line
            }
        };
        if record.get("hash").and_then(Value::as_str) != Some(sha256_hex(&payload).as_str()) {
            result.fail(line_no, "entry hash does not match its content (tampered)");
        } else {
            let key = match entry.get("key_id") {
                Some(Value::String(id)) => trusted.get(id).cloned(),
                None if trusted.len() == 1 => trusted.values().next().cloned(),
                _ => None,
            };
            let valid = key.is_some_and(|key| {
                record
                    .get("sig")
                    .ok_or_else(|| Error::value("'sig'"))
                    .and_then(b64_strict)
                    .and_then(|sig| verify(&key, &sig, &payload))
                    .is_ok()
            });
            if !valid {
                result.fail(line_no, "invalid Ed25519 signature");
            }
        }
        if entry.get("prev_hash") != Some(&prev_hash) {
            result.fail(
                line_no,
                "chain break: prev_hash does not match previous entry",
            );
        }
        let seq = entry.get("seq").filter(|v| !v.is_null());
        if let (Some(seq), Some(previous)) = (seq, prev_seq) {
            let numeric = match seq {
                Value::Number(n) => crate::json::as_float(n),
                Value::Bool(b) => Some(f64::from(u8::from(*b))),
                _ => None,
            };
            if numeric != Some(previous + 1.0) {
                result.fail(
                    line_no,
                    format!(
                        "sequence gap: expected {}, got {}",
                        previous as i128 + 1,
                        py_value(seq)
                    ),
                );
            }
        }
        if let Some(seq) = seq {
            match crate::json::as_integer(seq) {
                Some(n) if n >= 0 && crate::validation::is_int(seq) => prev_seq = Some(n as f64),
                _ => {
                    result.fail(line_no, "invalid sequence type/value");
                    return Ok(result);
                }
            }
        }
        if let Some(hash) = record.get("hash") {
            prev_hash = hash.clone();
        }
    }
    result.head = value_text(&prev_hash);
    Ok(result)
}

/// Python's `str()` of a JSON value (for the sequence-gap message).
fn py_value(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Null => "None".into(),
        other => dumps(other),
    }
}

/// Fields of one audit entry. Unset fields are recorded as `null`, as before.
#[derive(Debug, Clone, Default)]
pub struct Record {
    pub decision: String,
    pub tool: Option<String>,
    pub method: Option<String>,
    pub agent_id: Option<String>,
    pub resource: Option<String>,
    pub reason: Option<String>,
    pub arguments_hash: Option<String>,
    /// Defaults to `native`.
    pub profile: Option<String>,
    pub correlation_id: Option<String>,
    /// Defaults to true. False when warn-only logged a denial but forwarded the call.
    pub enforced: Option<bool>,
    pub detail: Option<Map<String, Value>>,
    pub policy_digest: Option<String>,
    pub remaining_budget: Option<i128>,
    pub identity: Option<Map<String, Value>>,
}

type Stamp = Vec<(PathBuf, u64, u64, i64, i64)>;

struct Head {
    prev: String,
    seq: usize,
    stamp: Option<Stamp>,
}

pub struct AuditLog {
    pub path: PathBuf,
    private_str: String,
    pub public_str: String,
    pub key_id: String,
    pub gateway_id: String,
    pub policy_digest: String,
    pub verification_keys: TrustedKeys,
    pub max_bytes: u64,
    pub max_segments: usize,
    head: Mutex<Head>,
}

fn stat(path: &Path) -> Result<Stamp> {
    segments(path)
        .into_iter()
        .map(|p| {
            let meta = std::fs::metadata(&p)?;
            Ok((p, meta.ino(), meta.size(), meta.mtime(), meta.mtime_nsec()))
        })
        .collect()
}

impl AuditLog {
    pub fn new(
        path: impl Into<PathBuf>,
        audit_private_str: &str,
        gateway_id: &str,
        policy_digest: &str,
        verification_keys: TrustedKeys,
    ) -> Result<Self> {
        Self::with_bounds(
            path,
            audit_private_str,
            gateway_id,
            policy_digest,
            verification_keys,
            4 * 1024 * 1024,
            16,
        )
    }

    pub fn with_bounds(
        path: impl Into<PathBuf>,
        audit_private_str: &str,
        gateway_id: &str,
        policy_digest: &str,
        mut verification_keys: TrustedKeys,
        max_bytes: u64,
        max_segments: usize,
    ) -> Result<Self> {
        let public_str = public_from_private(audit_private_str)?;
        let key_id = key_id(&public_str)?;
        verification_keys.insert(key_id.clone(), public_str.clone());
        if max_bytes < 1024 || max_segments < 1 {
            return Err(Error::value("invalid audit storage bounds"));
        }
        let log = Self {
            path: path.into(),
            private_str: audit_private_str.to_owned(),
            public_str,
            key_id,
            gateway_id: gateway_id.to_owned(),
            policy_digest: policy_digest.to_owned(),
            verification_keys,
            max_bytes,
            max_segments,
            head: Mutex::new(Head {
                prev: GENESIS.into(),
                seq: 0,
                stamp: None,
            }),
        };
        {
            let mut head = log.head.lock().expect("audit lock");
            log.load_head(&mut head)?;
        }
        Ok(log)
    }

    /// Resume the chain from the last line: (head hash, next sequence number).
    fn load_head(&self, head: &mut Head) -> Result<()> {
        if segments(&self.path).is_empty() {
            if head.seq != 0 {
                return Err(Error::value("audit history disappeared"));
            }
            head.prev = GENESIS.into();
            head.stamp = Some(stat(&self.path)?);
            return Ok(());
        }
        let result = verify_log(&self.path, &self.verification_keys)?;
        if !result.ok {
            return Err(Error::value(format!(
                "refusing invalid audit history: {}",
                result.first_failure_repr()
            )));
        }
        if result.entries < head.seq {
            return Err(Error::value("audit history was truncated"));
        }
        head.stamp = Some(stat(&self.path)?);
        head.prev = result.head;
        head.seq = result.entries;
        Ok(())
    }

    /// Append one signed entry; returns the stored record.
    pub fn record(&self, fields: Record) -> Result<Value> {
        let mut head = self
            .head
            .lock()
            .map_err(|_| Error::runtime("audit lock poisoned"))?;
        let _lock = FileLock::acquire(&self.path)?;
        if Some(stat(&self.path)?) != head.stamp {
            self.load_head(&mut head)?;
        }
        let mut entry = Map::new();
        entry.insert("ts".into(), json!(iso_z(&chrono::Utc::now())));
        entry.insert("seq".into(), json!(head.seq));
        entry.insert("gateway_id".into(), json!(self.gateway_id));
        entry.insert(
            "policy_digest".into(),
            json!(
                fields
                    .policy_digest
                    .unwrap_or_else(|| self.policy_digest.clone())
            ),
        );
        entry.insert("key_id".into(), json!(self.key_id));
        entry.insert("method".into(), json!(fields.method));
        entry.insert("agent_id".into(), json!(fields.agent_id));
        entry.insert("tool".into(), json!(fields.tool));
        entry.insert("resource".into(), json!(fields.resource));
        entry.insert("decision".into(), json!(fields.decision));
        entry.insert("enforced".into(), json!(fields.enforced.unwrap_or(true)));
        entry.insert("reason".into(), json!(fields.reason));
        entry.insert("correlation_id".into(), json!(fields.correlation_id));
        entry.insert("arguments_hash".into(), json!(fields.arguments_hash));
        entry.insert(
            "profile".into(),
            json!(fields.profile.unwrap_or_else(|| "native".into())),
        );
        entry.insert("prev_hash".into(), json!(head.prev));
        if let Some(detail) = fields.detail.filter(|d| !d.is_empty()) {
            entry.insert("detail".into(), Value::Object(detail));
        }
        if let Some(identity) = fields.identity.filter(|i| !i.is_empty()) {
            entry.insert("identity".into(), Value::Object(identity));
        }
        if let Some(remaining) = fields.remaining_budget {
            entry.insert("remaining_budget".into(), crate::json::int(remaining));
        }
        let entry = Value::Object(entry);
        let payload = canonicalize(&entry)?; // JCS — deterministic bytes
        let entry_hash = sha256_hex(&payload);
        let signature = sign(&self.private_str, &payload)?;
        let record = json!({"hash": entry_hash, "sig": STANDARD.encode(signature), "entry": entry});
        let encoded = format!("{}\n", dumps(&record));
        if encoded.len() as u64 > self.max_bytes {
            return Err(Error::value("audit entry exceeds segment limit"));
        }
        if let Ok(meta) = std::fs::metadata(&self.path) {
            if meta.len() + encoded.len() as u64 > self.max_bytes {
                let archives = segments(&self.path).len() - 1;
                if archives >= self.max_segments - 1 {
                    return Err(Error::io(
                        "audit storage quota reached; archive/export required",
                    ));
                }
                let mut archived = self.path.as_os_str().to_owned();
                archived.push(format!(".part{archives:08}"));
                std::fs::rename(&self.path, archived)?;
            }
        }
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&self.path)?;
        file.write_all(encoded.as_bytes())?;
        file.flush()?;
        file.sync_all()?;
        head.prev = entry_hash;
        head.seq += 1;
        head.stamp = Some(stat(&self.path)?);
        Ok(record)
    }
}

/// Sign the current head of the chain, for publication to an external witness.
///
/// A compromised proxy can rewrite and re-sign its whole log — the chain alone does
/// not protect against the author. Publishing `{seq, head_hash}` signed, at intervals,
/// to somewhere the proxy cannot reach bounds that rewrite to the interval since the
/// last anchor: anything older would contradict a witness the attacker does not control.
pub fn head_attestation(
    path: &Path,
    audit_private_str: &str,
    gateway_id: Option<&str>,
    mut verification_keys: TrustedKeys,
) -> Result<Value> {
    let public = public_from_private(audit_private_str)?;
    verification_keys.insert(key_id(&public)?, public.clone());
    let (last, entries) = {
        let _lock = FileLock::acquire(path)?;
        let verified = verify_log(path, &verification_keys)?;
        if !verified.ok {
            return Err(Error::value(format!(
                "refusing to sign invalid audit history: {}",
                verified.first_failure_repr()
            )));
        }
        let mut last = None;
        let mut entries = 0usize;
        for (_, line) in lines(path)? {
            if !crate::validation::py_strip(&line).is_empty() {
                last = Some(strict_json(&line)?);
                entries += 1;
            }
        }
        (last, entries)
    };
    let entry = last
        .as_ref()
        .and_then(|l| l.get("entry"))
        .cloned()
        .unwrap_or(json!({}));
    let actual = entry.get("gateway_id").and_then(Value::as_str);
    if let (Some(wanted), Some(actual)) = (gateway_id, actual) {
        if wanted != actual {
            return Err(Error::value("audit gateway identity mismatch"));
        }
    }
    let gateway = actual.or(gateway_id).unwrap_or("gateway");
    let mut attestation = Map::new();
    attestation.insert("type".into(), json!("audit-head"));
    attestation.insert("gateway_id".into(), json!(gateway));
    attestation.insert("seq".into(), entry.get("seq").cloned().unwrap_or(json!(-1)));
    attestation.insert("entries".into(), json!(entries));
    attestation.insert(
        "head_hash".into(),
        last.as_ref()
            .and_then(|l| l.get("hash"))
            .cloned()
            .unwrap_or(json!(GENESIS)),
    );
    attestation.insert("ts".into(), json!(iso_z(&chrono::Utc::now())));
    attestation.insert("key_id".into(), json!(key_id(&public)?));
    let signature = sign(
        audit_private_str,
        &canonicalize(&Value::Object(attestation.clone()))?,
    )?;
    attestation.insert("signature".into(), json!(STANDARD.encode(signature)));
    Ok(Value::Object(attestation))
}

/// Check a head attestation against the audit public key.
pub fn verify_head_attestation(attestation: &Value, public_str: &str) -> bool {
    let Some(map) = attestation.as_object() else {
        return false;
    };
    let body: Map<String, Value> = map
        .iter()
        .filter(|(k, _)| k.as_str() != "signature")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let Some(signature) = map.get("signature") else {
        return false;
    };
    let Ok(signature) = b64_strict(signature) else {
        return false;
    };
    canonicalize(&Value::Object(body))
        .and_then(|m| verify(public_str, &signature, &m))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_detects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let kp = crate::keys::generate_keypair();
        let log = AuditLog::new(&path, &kp.private_str, "gw", "d", TrustedKeys::new()).unwrap();
        for decision in ["ALLOW", "DENY"] {
            log.record(Record {
                decision: decision.into(),
                ..Default::default()
            })
            .unwrap();
        }
        let trusted = trusted_from(std::slice::from_ref(&kp.public_str)).unwrap();
        assert!(verify_log(&path, &trusted).unwrap().ok);
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replace("DENY", "ALLO");
        std::fs::write(&path, text).unwrap();
        let result = verify_log(&path, &trusted).unwrap();
        assert!(!result.ok);
        assert_eq!(
            result.failures[0].1,
            "entry hash does not match its content (tampered)"
        );
        assert!(AuditLog::new(&path, &kp.private_str, "gw", "d", TrustedKeys::new()).is_err());
    }
}
