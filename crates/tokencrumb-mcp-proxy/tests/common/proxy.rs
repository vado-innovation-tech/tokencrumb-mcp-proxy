//! HTTP harness for the proxy app: a recording fake upstream, a proxy built around a
//! real `Verifier` and a real `AuditLog`, and request helpers.
//!
//! Every assertion here is on the HTTP boundary, not on the verifier — a check that
//! only holds when called directly is not a check the gateway actually enforces.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use biscuit_auth::builder::Term as BiscuitTerm;
use biscuit_auth::{Biscuit, BiscuitBuilder, BlockBuilder};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures_util::future::BoxFuture;
use serde_json::{Value, json};
use tokencrumb_mcp_proxy::audit::{AuditLog, TrustedKeys};
use tokencrumb_mcp_proxy::biscuit_ops::{self, ForgeRequest};
use tokencrumb_mcp_proxy::keys::{Keypair, biscuit_public, generate_keypair};
use tokencrumb_mcp_proxy::policy::{Policy, parse_policy};
use tokencrumb_mcp_proxy::proxy::app::{ProxyConfig, create_app};
use tokencrumb_mcp_proxy::proxy::upstream::{
    ForwardHeaders, SharedUpstream, Upstream, UpstreamResponse,
};
use tokencrumb_mcp_proxy::verifier::{Decision, Headers, Verifier, VerifierOptions};
use tower::ServiceExt;

pub const TEST_AUDIENCE: &str = "test-gw";

/// Records what reached the upstream and replies with a canned response.
pub struct FakeUpstream {
    pub calls: Mutex<Vec<(String, Vec<u8>, ForwardHeaders)>>,
    pub payload: Mutex<Value>,
    /// Replaces the rendered payload verbatim when set (malformed bodies, split SSE).
    pub raw_body: Option<Vec<u8>>,
    pub content_type: String,
    pub status: u16,
    pub extra_headers: Vec<(String, String)>,
    pub requires_credentials: bool,
}

impl FakeUpstream {
    pub fn new(payload: Option<Value>, content_type: &str) -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            payload: Mutex::new(
                payload
                    .unwrap_or_else(|| json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": true}})),
            ),
            raw_body: None,
            content_type: content_type.to_owned(),
            status: 200,
            extra_headers: Vec::new(),
            requires_credentials: false,
        })
    }

    /// A default JSON upstream adjusted before it is shared.
    pub fn customized(adjust: impl FnOnce(&mut FakeUpstream)) -> Arc<Self> {
        let mut upstream = Arc::try_unwrap(Self::default_json())
            .unwrap_or_else(|_| unreachable!("fresh upstream"));
        adjust(&mut upstream);
        Arc::new(upstream)
    }

    pub fn default_json() -> Arc<Self> {
        Self::new(None, "application/json")
    }

    pub fn reached(&self) -> bool {
        !self.calls.lock().unwrap().is_empty()
    }

    pub fn clear(&self) {
        self.calls.lock().unwrap().clear();
    }

    pub fn bodies(&self) -> Vec<Value> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(_, b, _)| serde_json::from_slice(b).unwrap())
            .collect()
    }

    fn body(&self) -> Vec<u8> {
        if let Some(raw) = &self.raw_body {
            return raw.clone();
        }
        let payload = self.payload.lock().unwrap().clone();
        if self.content_type.contains("event-stream") {
            format!(
                "event: message\ndata: {}\n\n",
                tokencrumb_mcp_proxy::json::dumps(&payload)
            )
            .into_bytes()
        } else {
            tokencrumb_mcp_proxy::json::dumps(&payload).into_bytes()
        }
    }
}

impl Upstream for FakeUpstream {
    fn forward<'a>(
        &'a self,
        method: &'a str,
        body: Bytes,
        headers: &'a ForwardHeaders,
    ) -> BoxFuture<'a, tokencrumb_mcp_proxy::Result<UpstreamResponse>> {
        self.calls
            .lock()
            .unwrap()
            .push((method.to_owned(), body.to_vec(), headers.clone()));
        let mut response_headers = vec![("content-type".to_owned(), self.content_type.clone())];
        response_headers.extend(self.extra_headers.iter().cloned());
        let response = UpstreamResponse {
            status: self.status,
            headers: response_headers,
            body: Bytes::from(self.body()),
        };
        Box::pin(async move { Ok(response) })
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }

    fn requires_user_credentials(&self) -> bool {
        self.requires_credentials
    }
}

/// The conftest policy: a read tool scoped by prefix, a write tool requiring proofs.
pub fn test_policy() -> Policy {
    let mut policy = parse_policy(&json!({
        "deny_unknown_tools": true,
        "min_profile": "native",
        "tools": [
            {"name": "read_file", "operation": "read", "resource": {"from": "arguments.path"},
             "allow": {"resource_prefix": "/projects/acme/", "budget": 200}},
            {"name": "execute_sql", "operation": "write", "resource": {"from": "arguments.schema"},
             "allow": {"resource_prefix": "analytics", "budget": 20},
             "require": ["call_signature_valid", "nonce_fresh", "arguments_bound"]},
        ],
    }))
    .unwrap();
    policy.policy_digest = "test-policy-digest".into();
    policy
}

/// Keys and tokens shared by one test.
pub struct World {
    pub authority: Keypair,
    pub agent: Keypair,
    pub attacker: Keypair,
    pub audit_key: Keypair,
    pub dir: tempfile::TempDir,
}

impl World {
    pub fn new() -> Self {
        Self {
            authority: generate_keypair(),
            agent: generate_keypair(),
            attacker: generate_keypair(),
            audit_key: generate_keypair(),
            dir: tempfile::tempdir().unwrap(),
        }
    }

    pub fn audit_path(&self) -> PathBuf {
        self.dir.path().join("audit.log")
    }

    pub fn native_token(&self) -> String {
        biscuit_ops::forge(
            &self.authority.private_str,
            &ForgeRequest {
                agent_id: "agent-1".into(),
                tool: "read_file".into(),
                operation: "read".into(),
                ttl_seconds: 3600,
                budget: 200,
                resource_prefix: Some("/projects/acme/".into()),
                required_profile: "native".into(),
                audience: TEST_AUDIENCE.into(),
                ..Default::default()
            },
        )
        .unwrap()
    }

    pub fn hardened_token(&self) -> String {
        biscuit_ops::forge(
            &self.authority.private_str,
            &ForgeRequest {
                agent_id: "agent-rag-01".into(),
                tool: "execute_sql".into(),
                operation: "write".into(),
                ttl_seconds: 3600,
                budget: 20,
                resource_prefix: Some("analytics".into()),
                agent_pubkey: Some(self.agent.public_str.clone()),
                required_profile: "hardened_biscuit_anchored".into(),
                audience: TEST_AUDIENCE.into(),
                ..Default::default()
            },
        )
        .unwrap()
    }

    pub fn verifier(&self, policy: Policy, options: Option<VerifierOptions>) -> Arc<Verifier> {
        let options = options.unwrap_or_else(|| VerifierOptions::new(TEST_AUDIENCE));
        Arc::new(Verifier::new(&self.authority.public_str, policy, options).unwrap())
    }

    /// A proxy with one unnamed upstream, a real verifier and a real audit log.
    pub fn proxy(&self, upstream: Arc<FakeUpstream>, mode: Option<&str>) -> axum::Router {
        self.proxy_with(
            vec![(None, upstream as SharedUpstream)],
            mode,
            self.verifier(test_policy(), None),
            true,
        )
    }

    pub fn proxy_with(
        &self,
        upstreams: Vec<(Option<String>, SharedUpstream)>,
        mode: Option<&str>,
        verifier: Arc<Verifier>,
        audit: bool,
    ) -> axum::Router {
        let log = audit.then(|| {
            Arc::new(
                AuditLog::new(
                    self.audit_path(),
                    &self.audit_key.private_str,
                    "gw-test",
                    &verifier.policy().policy_digest,
                    TrustedKeys::new(),
                )
                .unwrap(),
            )
        });
        let mut config = ProxyConfig::new(verifier, upstreams, log);
        config.mode = mode.map(str::to_owned);
        config.allow_no_audit = !audit;
        create_app(config).unwrap()
    }

    pub fn audit_entries(&self) -> Vec<Value> {
        audit_entries(&self.audit_path())
    }
}

pub fn audit_entries(path: &std::path::Path) -> Vec<Value> {
    match std::fs::read_to_string(path) {
        Ok(text) => text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str::<Value>(l).unwrap()["entry"].clone())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// A buffered HTTP reply.
pub struct Reply {
    pub status: StatusCode,
    pub headers: axum::http::HeaderMap,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|_| panic!("not JSON: {}", self.text()))
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

pub async fn send(app: &axum::Router, request: Request<Body>) -> Reply {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    Reply {
        status,
        headers,
        body,
    }
}

/// POST a JSON-RPC body (a JSON value, or raw bytes) to `path`.
pub async fn post_to(
    app: &axum::Router,
    path: &str,
    payload: impl Into<Payload>,
    headers: &[(&str, &str)],
) -> Reply {
    let mut builder = Request::post(path).header("content-type", "application/json");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let body = match payload.into() {
        Payload::Json(v) => tokencrumb_mcp_proxy::json::dumps(&v).into_bytes(),
        Payload::Raw(b) => b,
    };
    send(app, builder.body(Body::from(body)).unwrap()).await
}

pub async fn post(
    app: &axum::Router,
    payload: impl Into<Payload>,
    headers: &[(&str, &str)],
) -> Reply {
    post_to(app, "/mcp", payload, headers).await
}

pub enum Payload {
    Json(Value),
    Raw(Vec<u8>),
}

impl From<Value> for Payload {
    fn from(v: Value) -> Self {
        Payload::Json(v)
    }
}

impl From<Vec<u8>> for Payload {
    fn from(b: Vec<u8>) -> Self {
        Payload::Raw(b)
    }
}

impl From<&[u8]> for Payload {
    fn from(b: &[u8]) -> Self {
        Payload::Raw(b.to_vec())
    }
}

pub fn bearer(token: &str) -> String {
    format!("Biscuit {token}")
}

// -- Verifier-level helpers ------------------------------------------------------------

/// `Authorization: Biscuit <token>`, plus `Agent-Attestation` when given.
pub fn biscuit_headers(token: &str, attestation: Option<&str>) -> Headers {
    let mut pairs = vec![("authorization".to_owned(), bearer(token))];
    if let Some(att) = attestation {
        pairs.push(("agent-attestation".to_owned(), att.to_owned()));
    }
    Headers::new(pairs)
}

/// Verifier options answering to the test audience.
pub fn options() -> VerifierOptions {
    VerifierOptions::new(TEST_AUDIENCE)
}

/// One `tools/call` through the verifier; an infrastructure error fails the test.
pub fn verify(verifier: &Verifier, tool: &str, arguments: Value, headers: &Headers) -> Decision {
    verifier
        .verify_call(tool, &arguments, headers, None, None)
        .unwrap_or_else(|e| panic!("verification could not complete: {}", e.message))
}

/// A forge request for the test audience; the other fields keep their defaults.
pub fn mandate(
    agent_id: &str,
    tool: &str,
    operation: &str,
    ttl_seconds: i128,
    budget: i128,
) -> ForgeRequest {
    ForgeRequest {
        agent_id: agent_id.into(),
        tool: tool.into(),
        operation: operation.into(),
        ttl_seconds,
        budget,
        audience: TEST_AUDIENCE.into(),
        ..Default::default()
    }
}

pub fn forge(authority_private: &str, request: ForgeRequest) -> String {
    biscuit_ops::forge(authority_private, &request).unwrap()
}

pub fn str_term(value: &str) -> BiscuitTerm {
    BiscuitTerm::Str(value.to_owned())
}

pub fn date_term(value: DateTime<Utc>) -> BiscuitTerm {
    BiscuitTerm::Date(u64::try_from(value.timestamp()).unwrap())
}

pub fn in_seconds(seconds: i64) -> DateTime<Utc> {
    Utc::now() + chrono::TimeDelta::seconds(seconds)
}

fn params(pairs: &[(&str, BiscuitTerm)]) -> HashMap<String, BiscuitTerm> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect()
}

/// A mandate built from raw Datalog — what a foreign issuer could mint.
pub fn build_token(authority_private: &str, code: &str, pairs: &[(&str, BiscuitTerm)]) -> String {
    BiscuitBuilder::new()
        .code_with_params(code, params(pairs), HashMap::new())
        .unwrap()
        .build(&tokencrumb_mcp_proxy::keys::biscuit_keypair(authority_private).unwrap())
        .unwrap()
        .to_base64()
        .unwrap()
}

/// Append a block to a verified token, as any holder can offline.
pub fn append_block(
    token: &str,
    authority_public: &str,
    code: &str,
    pairs: &[(&str, BiscuitTerm)],
) -> String {
    let block = BlockBuilder::new()
        .code_with_params(code, params(pairs), HashMap::new())
        .unwrap();
    Biscuit::from_base64(token, biscuit_public(authority_public).unwrap())
        .unwrap()
        .append(block)
        .unwrap()
        .to_base64()
        .unwrap()
}

// -- A real HTTP upstream on 127.0.0.1 ---------------------------------------------------

/// One request as the recording server received it.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    /// Lowercase names, in arrival order (repeated headers kept).
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Recorded {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn header_all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

/// A canned reply.
pub struct Canned {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Canned {
    pub fn json(status: u16, value: Value) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: serde_json::to_vec(&value).unwrap(),
        }
    }

    pub fn raw(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Self {
        Self {
            status,
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            body: body.to_vec(),
        }
    }
}

type Responder = Arc<dyn Fn(&Recorded) -> Canned + Send + Sync>;

/// An HTTP server on an ephemeral local port that records every request (the
/// counterpart of `httpx.MockTransport`, over a real socket).
pub struct RecordingServer {
    pub base: String,
    requests: Arc<Mutex<Vec<Recorded>>>,
    task: tokio::task::JoinHandle<()>,
}

impl RecordingServer {
    pub async fn start(respond: impl Fn(&Recorded) -> Canned + Send + Sync + 'static) -> Self {
        let requests: Arc<Mutex<Vec<Recorded>>> = Arc::default();
        let respond: Responder = Arc::new(respond);
        let seen = requests.clone();
        let handler = move |request: Request<Body>| {
            let seen = seen.clone();
            let respond = respond.clone();
            async move {
                let (parts, body) = request.into_parts();
                let body = axum::body::to_bytes(body, usize::MAX)
                    .await
                    .unwrap()
                    .to_vec();
                let recorded = Recorded {
                    method: parts.method.to_string(),
                    path: parts.uri.path().to_owned(),
                    headers: parts
                        .headers
                        .iter()
                        .map(|(k, v)| {
                            (
                                k.as_str().to_owned(),
                                String::from_utf8_lossy(v.as_bytes()).into_owned(),
                            )
                        })
                        .collect(),
                    body,
                };
                let canned = respond(&recorded);
                seen.lock().unwrap().push(recorded);
                let mut response = axum::response::Response::new(Body::from(canned.body));
                *response.status_mut() = StatusCode::from_u16(canned.status).unwrap();
                for (k, v) in canned.headers {
                    response.headers_mut().append(
                        axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                        axum::http::HeaderValue::from_str(&v).unwrap(),
                    );
                }
                response
            }
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = axum::Router::new().fallback(handler);
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            base: format!("http://{address}"),
            requests,
            task,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for RecordingServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
