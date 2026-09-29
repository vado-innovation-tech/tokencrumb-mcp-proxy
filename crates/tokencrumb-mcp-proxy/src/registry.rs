//! Authenticated, signed agent registry with atomic local storage (profile 3a).
//!
//! In profile 3a the proxy trusts whatever public key this directory returns, so a
//! write is an identity assertion: registration takes a bearer write secret, a
//! registered key is never silently replaced, and every read is a short-lived record
//! signed by the registry's own persistent key. The proxy side ([`registry_resolver`])
//! verifies that signature, the identity, the freshness window and the sequence number
//! before it believes anything, and any failure refuses the operation.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::extract::{Path as UrlPath, Request, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use futures_util::StreamExt as _;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use regex::Regex;
use serde_json::{Map, Value, json};
use subtle::ConstantTimeEq as _;

use crate::canonical::canonicalize;
use crate::error::{Error, ErrorKind, Result};
use crate::json::{as_integer, strict_json};
use crate::keys::{key_id, public_from_private, sign, signing_key, verify};
use crate::revocation::b64_strict;
use crate::storage::{FileLock, atomic_json};
use crate::validation::{
    MAX_INTEGER, choice_value, integer, integer_value, is_int, mapping, public_key,
    public_key_value, string, string_value,
};
use crate::verifier::AgentKeyResolver;

pub const DOMAIN: &str = "biscuitmcp/agent-registry";
const STATUSES: &[&str] = &["active", "revoked", "suspended"];
const CAPACITY: usize = 100_000;
/// Request and response bodies on both sides of the registry are tiny records.
pub const MAX_BODY: usize = 8192;

static AGENT_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.-]*\z").expect("regex"));

/// A registry agent identifier: a bounded string that is also a safe path segment.
pub fn agent_name(value: &str) -> Result<&str> {
    string(value, "agent_id", 128)?;
    if !AGENT_NAME_RE.is_match(value) {
        return Err(Error::value("invalid agent_id"));
    }
    Ok(value)
}

/// [`agent_name`] for an untyped JSON value (a non-string fails like an empty one).
pub fn agent_name_value(value: Option<&Value>) -> Result<&str> {
    agent_name(string_value(value, "agent_id", 128)?)
}

fn now_micros() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i128)
        .unwrap_or(0)
}

fn now_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn field<'a>(record: &'a Map<String, Value>, name: &str) -> Result<&'a Value> {
    record
        .get(name)
        .ok_or_else(|| Error::value(format!("'{name}'")))
}

// --------------------------------------------------------------------------- //
// Store
// --------------------------------------------------------------------------- //

/// The registry's JSON file: `{agent_id: {agent_pubkey, status, owner_ref, seq}}`.
///
/// Every access holds an in-process mutex and an exclusive `flock` on `<path>.lock`,
/// and every write is an atomic replacement, so concurrent writers — threads or
/// processes — never lose each other's records.
pub struct Store {
    pub path: PathBuf,
    lock: Mutex<()>,
}

impl Store {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Mutex::new(()),
        }
    }

    fn read(&self) -> Result<Map<String, Value>> {
        let data = if self.path.exists() {
            strict_json(std::fs::read(&self.path)?)?
        } else {
            Value::Object(Map::new())
        };
        let data = match data {
            Value::Object(map) if map.len() <= CAPACITY => map,
            _ => return Err(Error::value("invalid registry storage")),
        };
        for (agent_id, record) in &data {
            agent_name(agent_id)?;
            let Value::Object(record) = record else {
                return Err(Error::value("invalid registry storage"));
            };
            public_key_value(Some(field(record, "agent_pubkey")?))?;
            choice_value(field(record, "status")?, STATUSES, "status")?;
        }
        Ok(data)
    }

    /// Register or update one agent.
    ///
    /// Fields absent from `record` keep their stored value (status, owner), so a
    /// replayed registration cannot silently reactivate a suspended agent. Changing
    /// the public key of an existing agent is an [`ErrorKind::Exists`] error unless
    /// `replace_key` says the rotation is intended.
    pub fn put(&self, agent_id: &str, record: Map<String, Value>, replace_key: bool) -> Result<()> {
        agent_name(agent_id)?;
        public_key_value(Some(field(&record, "agent_pubkey")?))?;
        let _guard = self
            .lock
            .lock()
            .map_err(|_| Error::runtime("registry lock poisoned"))?;
        let _lock = FileLock::acquire(&self.path)?;
        let mut data = self.read()?;
        let old = data.get(agent_id).and_then(Value::as_object).cloned();
        let mut merged = Map::new();
        merged.insert("status".into(), json!("active"));
        merged.insert("owner_ref".into(), Value::Null);
        for (k, v) in old.iter().flatten().chain(record.iter()) {
            merged.insert(k.clone(), v.clone());
        }
        merged.shift_remove("seq");
        choice_value(field(&merged, "status")?, STATUSES, "status")?;
        match merged.get("owner_ref") {
            None | Some(Value::Null) => {}
            owner => {
                string_value(owner, "owner_ref", 256)?;
            }
        }
        if let Some(old) = &old {
            if old.get("agent_pubkey") != merged.get("agent_pubkey") && !replace_key {
                return Err(Error::new(
                    ErrorKind::Exists,
                    "agent already registered with a different public key",
                ));
            }
        }
        if old.is_none() && data.len() >= CAPACITY {
            return Err(Error::value("registry capacity reached"));
        }
        let previous_seq = match old.as_ref().and_then(|o| o.get("seq")) {
            None => 0,
            Some(seq) => as_integer(seq).ok_or_else(|| Error::value("invalid registry storage"))?,
        };
        merged.insert(
            "seq".into(),
            crate::json::int(now_micros().max(previous_seq + 1)),
        );
        data.insert(agent_id.to_owned(), Value::Object(merged));
        atomic_json(&self.path, &Value::Object(data))
    }

    pub fn get(&self, agent_id: &str) -> Result<Option<Map<String, Value>>> {
        agent_name(agent_id)?;
        let _guard = self
            .lock
            .lock()
            .map_err(|_| Error::runtime("registry lock poisoned"))?;
        let _lock = FileLock::acquire(&self.path)?;
        Ok(self
            .read()?
            .get(agent_id)
            .and_then(Value::as_object)
            .cloned())
    }
}

// --------------------------------------------------------------------------- //
// Signed records
// --------------------------------------------------------------------------- //

/// The record the registry serves: the stored fields plus identity and a 30-second
/// validity window, Ed25519-signed over its JCS form.
pub fn signed_record(
    agent_id: &str,
    record: &Map<String, Value>,
    private_str: &str,
    now: Option<i64>,
) -> Result<Value> {
    let now = now.unwrap_or_else(|| now_seconds() as i64);
    let mut body = Map::new();
    body.insert("version".into(), json!(1));
    body.insert("domain".into(), json!(DOMAIN));
    body.insert(
        "key_id".into(),
        json!(key_id(&public_from_private(private_str)?)?),
    );
    body.insert("agent_id".into(), json!(agent_id));
    for (k, v) in record {
        body.insert(k.clone(), v.clone());
    }
    body.insert("issued_at".into(), json!(now));
    body.insert("expires_at".into(), json!(now + 30));
    let signature = sign(private_str, &canonicalize(&Value::Object(body.clone()))?)?;
    body.insert("signature".into(), json!(STANDARD.encode(signature)));
    Ok(Value::Object(body))
}

/// Check a served record; returns `(agent public key, expires_at, seq)`.
///
/// The record must be signed by `public` (the separately provisioned registry key),
/// name the requested agent, be inside its (at most 30 s) validity window and active.
pub fn verify_record(
    document: &Value,
    agent_id: &str,
    public: &str,
    now: Option<f64>,
) -> Result<(String, i128, i128)> {
    let now = now.unwrap_or_else(now_seconds);
    let document = mapping(
        document,
        &[
            "version",
            "domain",
            "key_id",
            "agent_id",
            "agent_pubkey",
            "status",
            "owner_ref",
            "seq",
            "issued_at",
            "expires_at",
            "signature",
        ],
        "signed registry record",
    )?;
    let body: Map<String, Value> = document
        .iter()
        .filter(|(k, _)| k.as_str() != "signature")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let version_ok = body
        .get("version")
        .is_some_and(|v| is_int(v) && as_integer(v) == Some(1));
    if !version_ok || body.get("domain").and_then(Value::as_str) != Some(DOMAIN) {
        return Err(Error::value("unsupported registry record"));
    }
    let wanted = agent_name(agent_id)?;
    if body.get("agent_id").and_then(Value::as_str) != Some(wanted)
        || body.get("key_id").and_then(Value::as_str) != Some(key_id(public)?.as_str())
    {
        return Err(Error::value("registry identity mismatch"));
    }
    let integer_field = |name: &str, place: &str| {
        integer_value(
            body.get(name).unwrap_or(&Value::Null),
            place,
            0,
            MAX_INTEGER,
        )
    };
    let seq = integer_field("seq", "registry sequence")?;
    let issued = integer_field("issued_at", "registry timestamp")?;
    let expires = integer_field("expires_at", "registry expiry")?;
    let fresh = (issued - 5) as f64 <= now && now < expires as f64;
    let window = 0 < expires - issued && expires - issued <= 30;
    if !fresh || !window || body.get("status").and_then(Value::as_str) != Some("active") {
        return Err(Error::value("stale or inactive registry record"));
    }
    let agent_pubkey = public_key_value(body.get("agent_pubkey"))?;
    let signature = b64_strict(field(document, "signature")?)?;
    verify(
        public,
        &signature,
        &canonicalize(&Value::Object(body.clone()))?,
    )?;
    Ok((agent_pubkey, expires, seq))
}

// --------------------------------------------------------------------------- //
// Resolver (proxy side)
// --------------------------------------------------------------------------- //

/// Python's `quote(value, safe="")`: everything but the unreserved set is escaped.
const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'_')
    .remove(b'.')
    .remove(b'-')
    .remove(b'~');

/// The HTTP client the resolver uses: 5 s timeouts, no redirects, no proxy taken
/// from the environment (ureq only uses one when told to).
pub fn resolver_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout_read(Duration::from_secs(5))
        .timeout_write(Duration::from_secs(5))
        .redirects(0)
        .build()
}

struct Cache {
    capacity: usize,
    tick: u64,
    /// agent_id -> ((public key, expires_at, seq), insertion tick)
    entries: HashMap<String, ((String, i128, i128), u64)>,
    order: BTreeMap<u64, String>,
}

impl Cache {
    fn insert(&mut self, agent_id: &str, record: (String, i128, i128)) {
        self.tick += 1;
        if let Some((_, tick)) = self.entries.remove(agent_id) {
            self.order.remove(&tick);
        }
        self.entries
            .insert(agent_id.to_owned(), (record, self.tick));
        self.order.insert(self.tick, agent_id.to_owned());
        while self.entries.len() > self.capacity {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }
}

fn fetch(agent: &ureq::Agent, url: &str) -> Result<Vec<u8>> {
    use std::io::Read as _;
    let response = agent
        .get(url)
        .call()
        .map_err(|e| Error::io(e.to_string()))?;
    if !(200..300).contains(&response.status()) {
        return Err(Error::io(format!("registry status {}", response.status())));
    }
    let mut body = Vec::new();
    response
        .into_reader()
        .take(MAX_BODY as u64 + 1)
        .read_to_end(&mut body)?;
    if body.len() > MAX_BODY {
        return Err(Error::value("registry response too large"));
    }
    Ok(body)
}

/// Resolve an agent's public key through a registry (profile 3a).
///
/// Records are cached until their signed `expires_at`; a record with a lower `seq`
/// than the one cached is a rollback and is refused. Any failure — network, size,
/// signature, identity, freshness — returns `None`, and a failed read never reuses an
/// expired positive entry.
pub fn registry_resolver(url: &str, public: &str, capacity: usize) -> Result<AgentKeyResolver> {
    registry_resolver_with_agent(url, public, capacity, resolver_agent())
}

/// [`registry_resolver`] with an explicit HTTP client (tests, custom trust).
pub fn registry_resolver_with_agent(
    url: &str,
    public: &str,
    capacity: usize,
    agent: ureq::Agent,
) -> Result<AgentKeyResolver> {
    public_key(public)?;
    integer(capacity as i128, "registry cache capacity", 1, MAX_INTEGER)?;
    let base = url.trim_end_matches('/').to_owned();
    let public = public.to_owned();
    let cache = Mutex::new(Cache {
        capacity,
        tick: 0,
        entries: HashMap::new(),
        order: BTreeMap::new(),
    });
    Ok(Box::new(move |agent_id: &str| {
        let resolved = (|| -> Result<String> {
            agent_name(agent_id)?;
            let mut cache = cache
                .lock()
                .map_err(|_| Error::runtime("registry cache poisoned"))?;
            let now = now_seconds();
            let previous = cache.entries.get(agent_id).map(|(r, _)| r.clone());
            if let Some((key, expires, _)) = &previous {
                if *expires as f64 > now {
                    return Ok(key.clone());
                }
            }
            let target = format!(
                "{base}/agents/{}",
                utf8_percent_encode(agent_id, PATH_SEGMENT)
            );
            let body = fetch(&agent, &target)?;
            let record = verify_record(&strict_json(body)?, agent_id, &public, Some(now))?;
            if let Some((_, _, previous_seq)) = previous {
                if record.2 < previous_seq {
                    return Err(Error::value("registry rollback"));
                }
            }
            let key = record.0.clone();
            cache.insert(agent_id, record);
            Ok(key)
        })();
        resolved.ok()
    }))
}

// --------------------------------------------------------------------------- //
// HTTP application (registry side)
// --------------------------------------------------------------------------- //

struct AppState {
    store: Arc<Store>,
    write_token: String,
    signing_private_str: String,
}

fn json_response(status: StatusCode, body: Value) -> Response {
    // Starlette's JSONResponse: compact separators, non-ASCII kept as UTF-8.
    let bytes = serde_json::to_vec(&body).unwrap_or_default();
    (status, [(header::CONTENT_TYPE, "application/json")], bytes).into_response()
}

fn internal_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "Internal Server Error",
    )
        .into_response()
}

/// Failures that are the server's own (storage, locking) rather than a bad request.
fn is_server_fault(error: &Error) -> bool {
    matches!(
        error.kind,
        ErrorKind::Io | ErrorKind::NotFound | ErrorKind::Runtime
    )
}

async fn register(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .map(|v| v.as_bytes())
        .unwrap_or(b"");
    let expected = format!("Bearer {}", state.write_token);
    if !bool::from(presented.ct_eq(expected.as_bytes())) {
        return json_response(StatusCode::UNAUTHORIZED, json!({"error": "unauthorized"}));
    }
    let mut data: Vec<u8> = Vec::new();
    let mut stream = request.into_body().into_data_stream();
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid registration"}),
            );
        };
        if data.len() + chunk.len() > MAX_BODY {
            return json_response(StatusCode::PAYLOAD_TOO_LARGE, json!({"error": "too large"}));
        }
        data.extend_from_slice(&chunk);
    }
    let parsed = (|| -> Result<(String, Map<String, Value>, bool)> {
        let document = strict_json(&data)?;
        let body = mapping(
            &document,
            &[
                "agent_id",
                "agent_pubkey",
                "status",
                "owner_ref",
                "replace_key",
            ],
            "agent",
        )?;
        let replace = match body.get("replace_key") {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(Error::value("replace_key must be boolean")),
        };
        let agent_id = agent_name_value(body.get("agent_id"))?.to_owned();
        let mut record = Map::new();
        record.insert(
            "agent_pubkey".into(),
            json!(public_key_value(body.get("agent_pubkey"))?),
        );
        for name in ["status", "owner_ref"] {
            if let Some(value) = body.get(name) {
                record.insert(name.into(), value.clone());
            }
        }
        Ok((agent_id, record, replace))
    })();
    let (agent_id, record, replace) = match parsed {
        Ok(parts) => parts,
        Err(_) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid registration"}),
            );
        }
    };
    let store = state.store.clone();
    let id = agent_id.clone();
    let outcome = tokio::task::spawn_blocking(move || store.put(&id, record, replace)).await;
    match outcome {
        Ok(Ok(())) => json_response(StatusCode::OK, json!({"ok": true, "agent_id": agent_id})),
        Ok(Err(e)) if e.is(ErrorKind::Exists) => json_response(
            StatusCode::CONFLICT,
            json!({"error": "key replacement requires replace_key=true"}),
        ),
        Ok(Err(e)) if is_server_fault(&e) => internal_error(),
        Ok(Err(_)) => json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "invalid registration"}),
        ),
        Err(_) => internal_error(),
    }
}

async fn get_agent(
    State(state): State<Arc<AppState>>,
    agent_id: std::result::Result<UrlPath<String>, axum::extract::rejection::PathRejection>,
) -> Response {
    let not_found = || json_response(StatusCode::NOT_FOUND, json!({"error": "not found"}));
    let Ok(UrlPath(agent_id)) = agent_id else {
        return not_found();
    };
    if agent_name(&agent_id).is_err() {
        return not_found();
    }
    let store = state.store.clone();
    let id = agent_id.clone();
    let record = match tokio::task::spawn_blocking(move || store.get(&id)).await {
        Ok(Ok(record)) => record,
        Ok(Err(e)) if is_server_fault(&e) => return internal_error(),
        Ok(Err(_)) => return not_found(),
        Err(_) => return internal_error(),
    };
    match record {
        Some(record) if record.get("status").and_then(Value::as_str) == Some("active") => {
            match signed_record(&agent_id, &record, &state.signing_private_str, None) {
                Ok(document) => json_response(StatusCode::OK, document),
                Err(_) => not_found(),
            }
        }
        _ => not_found(),
    }
}

async fn healthz() -> Response {
    json_response(StatusCode::OK, json!({"status": "ok"}))
}

async fn fallback() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        Body::from("Not Found"),
    )
        .into_response()
}

/// The registry HTTP application: `POST /agents` (bearer write secret, compared in
/// constant time), `GET /agents/{agent_id}` (signed record, open read path) and
/// `/healthz`.
///
/// Both secrets are mandatory: an unauthenticated registry lets anyone who can reach
/// it become any agent, and a registry without a persistent signing key serves records
/// no proxy can pin.
pub fn create_registry_app(
    store_path: impl AsRef<Path>,
    write_token: Option<&str>,
    signing_private_str: Option<&str>,
) -> Result<Router> {
    let write_token = match write_token {
        Some(token) if !crate::validation::py_strip(token).is_empty() => token,
        _ => return Err(Error::value("a registry write token is required")),
    };
    let signing_private_str = match signing_private_str {
        Some(key) if !key.is_empty() => key,
        _ => {
            return Err(Error::value(
                "a persistent registry signing key is required",
            ));
        }
    };
    signing_key(signing_private_str)?;
    let state = Arc::new(AppState {
        store: Arc::new(Store::new(store_path.as_ref())),
        write_token: write_token.to_owned(),
        signing_private_str: signing_private_str.to_owned(),
    });
    Ok(Router::new()
        .route("/agents", post(register))
        .route("/agents/{agent_id}", get(get_agent))
        .route("/healthz", get(healthz))
        .fallback(fallback)
        .with_state(state))
}

/// Serve the registry until SIGINT/SIGTERM. `tls` is a validated (cert, key) pair;
/// renewing the certificate means restarting (no ACME).
pub async fn serve_registry(
    app: Router,
    host: &str,
    port: u16,
    tls: Option<(PathBuf, PathBuf)>,
) -> Result<()> {
    let addr = crate::net::socket_addr(host, port)?;
    let handle = axum_server::Handle::new();
    let shutdown = handle.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        shutdown.graceful_shutdown(Some(Duration::from_secs(10)));
    });
    let service = app.into_make_service();
    match tls {
        Some((cert, key)) => {
            let config = crate::net::rustls_config(&cert, &key).await?;
            axum_server::bind_rustls(addr, config)
                .handle(handle)
                .serve(service)
                .await?;
        }
        None => {
            axum_server::bind(addr)
                .handle(handle)
                .serve(service)
                .await?;
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    let interrupt = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut terminate =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(_) => {
                    let _ = interrupt.await;
                    return;
                }
            };
        tokio::select! {
            _ = interrupt => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = interrupt.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_names() {
        assert!(agent_name("agent-1").is_ok());
        assert!(agent_name("a.b_c").is_ok());
        assert_eq!(
            agent_name("../alice").unwrap_err().message,
            "invalid agent_id"
        );
        assert!(agent_name("-x").is_err());
        assert!(agent_name(&"a".repeat(129)).is_err());
    }

    #[test]
    fn cache_is_bounded_in_insertion_order() {
        let mut cache = Cache {
            capacity: 2,
            tick: 0,
            entries: HashMap::new(),
            order: BTreeMap::new(),
        };
        for id in ["a", "b", "a", "c"] {
            cache.insert(id, (id.into(), 0, 0));
        }
        let mut kept: Vec<&String> = cache.entries.keys().collect();
        kept.sort();
        assert_eq!(kept, ["a", "c"]);
    }
}
