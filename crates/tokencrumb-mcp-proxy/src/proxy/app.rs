//! The TokenCrumb - MCP Proxy proxy application (Streamable HTTP).
//!
//! One process, one endpoint per upstream (architecture decision 3): `/mcp` for a single unnamed
//! upstream, `/mcp/<name>` for each entry of `upstreams:` in `policy.yaml`. The client
//! keeps one entry per server in its own config, exactly as it would without the proxy
//! (architecture decision 3), and sessions, `initialize` capabilities and catalogs stay 1:1 — nothing is
//! multiplexed. What IS shared is the budget counters and the single signed audit chain,
//! which is the whole point of running one process.
//!
//! Default deny, by direction:
//!
//! ```text
//! client -> server, `tools/call`   enforced by the ordered verification pipeline
//! client -> server, `tools/list`   relayed, then filtered against the local catalog
//! client -> server, allow-listed   relayed as-is (initialize, ping, notifications)
//! client -> server, anything else  refused with a JSON-RPC error
//! server -> client (GET/SSE)       channel not opened — a server can never initiate
//! ```
//!
//! Pinned to an MCP revision that has no JSON-RPC batching (policy `mcp.spec_version`),
//! so a batch body is refused outright rather than unpacked: accepting batches while only
//! inspecting the first object is how a `tools/call` slips past a gateway unverified.
//!
//! Refusals return an opaque correlation id. The reason, the resource and the policy
//! digest go to the audit log only — a denial must never become an enumeration oracle.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures_util::StreamExt;
use rand::RngCore;
use serde_json::{Map, Value, json};

use crate::audit::{AuditLog, Record};
use crate::error::{Error, ErrorKind, Result, py_repr};
use crate::json::{dumps, strict_json};
use crate::policy::Policy;
use crate::proxy::messages::{
    INTERNAL_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, PARSE_ERROR, deny_result, error_response,
    response_messages,
};
use crate::proxy::upstream::{ForwardHeaders, SharedUpstream, UpstreamResponse};
use crate::validation::choice;
use crate::verifier::{Decision, Headers, Verifier};

/// Session headers relayed back to the client.
const RELAY_HEADERS: &[&str] = &["mcp-session-id", "mcp-protocol-version"];
const MAX_CLIENTS: usize = 4096;
const MAX_SESSIONS: usize = 4096;
const SESSION_TTL: Duration = Duration::from_secs(3600);

pub struct ProxyConfig {
    pub verifier: Arc<Verifier>,
    /// One entry per endpoint (architecture decision 3), in declaration order. `None` is the single
    /// unnamed upstream served at `/mcp`; a name is served at `/mcp/<name>`.
    pub upstreams: Vec<(Option<String>, SharedUpstream)>,
    pub audit: Option<Arc<AuditLog>>,
    /// `None` follows the per-request policy snapshot.
    pub mode: Option<String>,
    pub allow_no_audit: bool,
    pub max_request_bytes: usize,
    pub requests_per_minute: u32,
    pub allowed_origins: Vec<String>,
}

impl ProxyConfig {
    pub fn new(
        verifier: Arc<Verifier>,
        upstreams: Vec<(Option<String>, SharedUpstream)>,
        audit: Option<Arc<AuditLog>>,
    ) -> Self {
        Self {
            verifier,
            upstreams,
            audit,
            mode: None,
            allow_no_audit: false,
            max_request_bytes: 1024 * 1024,
            requests_per_minute: 600,
            allowed_origins: Vec::new(),
        }
    }

    fn validate(&self) -> Result<()> {
        if let Some(mode) = &self.mode {
            choice(mode, &["enforce", "warn-only"], "mode")?;
        }
        if self.audit.is_none() && !self.allow_no_audit {
            return Err(Error::value(
                "an audit log is required; allow_no_audit is an explicit unguaranteed mode",
            ));
        }
        if self.upstreams.is_empty() {
            return Err(Error::value(
                "a proxy with no upstream has nothing to protect",
            ));
        }
        Ok(())
    }
}

/// Opaque, unpredictable, unique, carrying no internal meaning.
fn correlation_id() -> String {
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// The name the former runtime gave an error's type, for the infrastructure trace.
fn error_type(error: &Error) -> &'static str {
    match error.kind {
        ErrorKind::Io if error.message == "TimeoutError" => "TimeoutError",
        ErrorKind::Io if error.message.starts_with("ConnectError") => "ConnectError",
        ErrorKind::Io => "OSError",
        ErrorKind::NotFound => "FileNotFoundError",
        ErrorKind::Runtime => "RuntimeError",
        ErrorKind::Revocation => "RevocationError",
        _ => "ValueError",
    }
}

struct RateWindow {
    started: Instant,
    count: u32,
}

#[derive(Default)]
struct Rates {
    order: VecDeque<String>,
    clients: HashMap<String, RateWindow>,
}

#[derive(Default)]
struct Sessions {
    /// Insertion order, oldest first (a refresh moves an entry to the back).
    order: VecDeque<(Option<String>, String)>,
    owners: HashMap<(Option<String>, String), (String, Instant)>,
}

impl Sessions {
    fn purge(&mut self, now: Instant) {
        while let Some(key) = self.order.front() {
            match self.owners.get(key) {
                Some((_, expiry)) if *expiry <= now => {
                    let key = self.order.pop_front().expect("front");
                    self.owners.remove(&key);
                }
                None => {
                    self.order.pop_front();
                }
                _ => break,
            }
        }
    }
}

struct AppState {
    config: ProxyConfig,
    upstreams: HashMap<Option<String>, SharedUpstream>,
    rates: Mutex<Rates>,
    sessions: Mutex<Sessions>,
}

fn json_response(status: StatusCode, value: &Value) -> Response {
    let mut response = Response::new(Body::from(serde_json::to_vec(value).expect("json")));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

fn empty(status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

/// Relay an upstream reply: its status, its media type and the session headers only.
fn relay(upstream: &UpstreamResponse, body: Option<Vec<u8>>) -> Response {
    let body = body
        .map(Bytes::from)
        .unwrap_or_else(|| upstream.body.clone());
    let mut response = Response::new(Body::from(body));
    *response.status_mut() =
        StatusCode::from_u16(upstream.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut media = upstream
        .header("content-type")
        .unwrap_or("application/json")
        .to_owned();
    if media.starts_with("text/") && !media.contains("charset=") {
        media.push_str("; charset=utf-8");
    }
    if let Ok(value) = HeaderValue::from_str(&media) {
        response.headers_mut().insert(header::CONTENT_TYPE, value);
    }
    copy_session_headers(upstream, response.headers_mut());
    response
}

fn copy_session_headers(upstream: &UpstreamResponse, headers: &mut HeaderMap) {
    for name in RELAY_HEADERS {
        if let Some(value) = upstream
            .header(name)
            .and_then(|v| HeaderValue::from_str(v).ok())
        {
            headers.insert(*name, value);
        }
    }
}

/// Filter `result.tools` in place against the local catalog; returns how many tools
/// were masked (model A: filter by the locally mapped catalog).
fn filter_tools(payload: &mut Value, allowed: &[&str]) -> usize {
    let Some(tools) = payload
        .get_mut("result")
        .and_then(|r| r.get_mut("tools"))
        .and_then(Value::as_array_mut)
    else {
        return 0;
    };
    let before = tools.len();
    tools.retain(|t| {
        t.get("name")
            .and_then(Value::as_str)
            .is_some_and(|n| allowed.contains(&n))
            && t.is_object()
    });
    before - tools.len()
}

/// Remove a top-level `"$schema"` naming JSON Schema draft-07 from a tool's input and
/// output schemas. The TypeScript SDK stamps it on every tool, and clients that only
/// accept 2020-12 (Claude Desktop) then reject the whole catalog. Only the declaration
/// goes: the keywords zod emits read the same in both dialects.
fn drop_draft_07_declaration(tool: &mut Value) {
    for key in ["inputSchema", "outputSchema"] {
        let Some(schema) = tool.get_mut(key).and_then(Value::as_object_mut) else {
            continue;
        };
        let is_draft_07 = schema
            .get("$schema")
            .and_then(Value::as_str)
            .is_some_and(|uri| {
                let uri = uri.trim_end_matches('#');
                uri == "http://json-schema.org/draft-07/schema"
                    || uri == "https://json-schema.org/draft-07/schema"
            });
        if is_draft_07 {
            schema.remove("$schema");
        }
    }
}

fn rewrite_tools_list(
    upstream: &UpstreamResponse,
    allowed: &[&str],
    aliases: &HashMap<String, String>,
) -> Result<(Vec<u8>, usize)> {
    let (mut messages, is_sse) = response_messages(
        upstream.status,
        upstream.header("content-type"),
        &upstream.body,
    )?;
    let mut masked = 0;
    for payload in &mut messages {
        let well_formed = payload
            .get("result")
            .and_then(|r| r.get("tools"))
            .is_some_and(Value::is_array);
        if payload.get("error").is_none() && !well_formed {
            return Err(Error::value("malformed tools/list response"));
        }
        if let Some(tools) = payload
            .get_mut("result")
            .and_then(|r| r.get_mut("tools"))
            .and_then(Value::as_array_mut)
        {
            for tool in tools.iter_mut() {
                let public = tool
                    .get("name")
                    .and_then(Value::as_str)
                    .and_then(|n| aliases.get(n))
                    .cloned();
                if let (Some(public), Some(map)) = (public, tool.as_object_mut()) {
                    map.insert("name".into(), Value::String(public));
                }
                drop_draft_07_declaration(tool);
            }
        }
        masked += filter_tools(payload, allowed);
    }
    let body = if is_sse {
        messages
            .iter()
            .flat_map(|m| format!("event: message\ndata: {}\n\n", dumps(m)).into_bytes())
            .collect()
    } else {
        dumps(&messages[0]).into_bytes()
    };
    Ok((body, masked))
}

/// Re-serialize a `tools/call` with the upstream's own name for the tool. Only the body
/// sent onward changes: the attestation and the argument binding were already checked
/// against the PUBLIC name, which is what the mandate grants and the agent signed.
fn rename_tool(message: &Map<String, Value>, upstream_tool: &str) -> Vec<u8> {
    let mut rewritten = message.clone();
    let mut params = rewritten
        .get("params")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    params.insert("name".into(), Value::String(upstream_tool.to_owned()));
    rewritten.insert("params".into(), Value::Object(params));
    dumps(&Value::Object(rewritten)).into_bytes()
}

fn is_jsonrpc_id(value: &Value) -> bool {
    value.is_string() || crate::validation::is_int(value)
}

/// Everything one request needs to write its audit entries.
struct Ctx<'a> {
    state: &'a AppState,
    policy: Arc<Policy>,
    endpoint: Option<String>,
}

impl Ctx<'_> {
    /// Where the entry came from: with one chain across N upstreams, an entry that does
    /// not say which endpoint it came from is unattributable.
    fn detail(&self) -> Option<Map<String, Value>> {
        self.endpoint.as_ref().map(|e| {
            let mut map = Map::new();
            map.insert("upstream".into(), json!(e));
            map
        })
    }

    async fn audit(&self, mut record: Record) -> Result<()> {
        let Some(audit) = self.state.config.audit.clone() else {
            return Ok(());
        };
        if record.policy_digest.is_none() {
            record.policy_digest = Some(self.policy.policy_digest.clone());
        }
        tokio::task::spawn_blocking(move || audit.record(record))
            .await
            .map_err(|e| Error::runtime(e.to_string()))??;
        Ok(())
    }

    async fn deny(
        &self,
        method: &str,
        reason: &str,
        correlation: Option<&str>,
        detail: Option<Map<String, Value>>,
    ) -> Result<()> {
        self.audit(Record {
            decision: "DENY".into(),
            method: Some(method.into()),
            reason: Some(reason.into()),
            correlation_id: correlation.map(str::to_owned),
            detail,
            ..Default::default()
        })
        .await
    }
}

async fn read_body(body: Body, limit: usize) -> std::result::Result<Vec<u8>, bool> {
    let mut stream = body.into_data_stream();
    let mut raw = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| false)?;
        if raw.len() + chunk.len() > limit {
            return Err(true);
        }
        raw.extend_from_slice(&chunk);
    }
    Ok(raw)
}

async fn session_owner(verifier: &Arc<Verifier>, headers: &Headers) -> Result<String> {
    let verifier = verifier.clone();
    let headers = headers.clone();
    tokio::task::spawn_blocking(move || verifier.session_owner(&headers))
        .await
        .map_err(|e| Error::runtime(e.to_string()))?
}

async fn handle(
    state: Arc<AppState>,
    endpoint: Option<String>,
    client: String,
    request: Request,
) -> Response {
    let policy = state.config.verifier.policy();
    match handle_inner(&state, endpoint.clone(), client, request, policy.clone()).await {
        Ok(response) => response,
        // Infrastructure errors must not dispatch again: record, then an opaque 503.
        Err(error) => {
            let cid = correlation_id();
            let ctx = Ctx {
                state: &state,
                policy,
                endpoint: None,
            };
            let _ = ctx
                .deny(
                    "<infrastructure>",
                    &format!("{}: request could not be completed", error_type(&error)),
                    Some(&cid),
                    None,
                )
                .await;
            json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &error_response(Value::Null, INTERNAL_ERROR, "request unavailable", &cid),
            )
        }
    }
}

async fn handle_inner(
    state: &AppState,
    endpoint: Option<String>,
    client: String,
    request: Request,
    policy: Arc<Policy>,
) -> Result<Response> {
    // The policy is read per request: with hot reload on, a value captured at startup
    // would keep enforcing rules the file no longer holds.
    let mode = state
        .config
        .mode
        .clone()
        .unwrap_or_else(|| policy.mode.clone());
    let ctx = Ctx {
        state,
        policy: policy.clone(),
        endpoint: endpoint.clone(),
    };
    let now = Instant::now();

    // -- per-client rate limit ---------------------------------------------------------
    let exceeded = {
        let mut rates = state.rates.lock().expect("rates lock");
        while let Some(first) = rates.order.front().cloned() {
            if rates
                .clients
                .get(&first)
                .is_some_and(|w| w.started + Duration::from_secs(60) <= now)
            {
                rates.order.pop_front();
                rates.clients.remove(&first);
            } else {
                break;
            }
        }
        if !rates.clients.contains_key(&client) {
            if rates.clients.len() >= MAX_CLIENTS {
                return Ok(empty(StatusCode::TOO_MANY_REQUESTS));
            }
            rates.order.push_back(client.clone());
            rates.clients.insert(
                client.clone(),
                RateWindow {
                    started: now,
                    count: 0,
                },
            );
        }
        let window = rates.clients.get_mut(&client).expect("window");
        window.count += 1;
        (window.count > state.config.requests_per_minute).then_some(window.count)
    };
    if let Some(count) = exceeded {
        if count == state.config.requests_per_minute + 1 {
            ctx.deny("<rate-limit>", "request rate exceeded", None, None)
                .await?;
        }
        let mut response = empty(StatusCode::TOO_MANY_REQUESTS);
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        return Ok(response);
    }

    let headers = Headers::from_http(request.headers());
    if let Some(origin) = headers.get("origin")
        && !state.config.allowed_origins.iter().any(|o| o == origin)
    {
        ctx.deny("<origin>", "untrusted browser origin", None, None)
            .await?;
        return Ok(empty(StatusCode::FORBIDDEN));
    }
    if let Some(version) = headers.get("mcp-protocol-version")
        && !version.is_empty()
        && version != policy.mcp.spec_version
    {
        return Ok(empty(StatusCode::BAD_REQUEST));
    }

    let upstream = state
        .upstreams
        .get(&endpoint)
        .cloned()
        .ok_or_else(|| Error::value("unknown endpoint"))?;
    let mut forward_headers = ForwardHeaders {
        incoming: headers.clone(),
        principal: None,
    };
    {
        let mut sessions = state.sessions.lock().expect("sessions lock");
        sessions.purge(now);
    }
    if let Some(session_id) = headers.get("mcp-session-id").filter(|s| !s.is_empty()) {
        if session_id.chars().count() > 256 {
            return Err(Error::value("invalid session id"));
        }
        let owner = session_owner(&state.config.verifier, &headers).await?;
        let known = {
            let sessions = state.sessions.lock().expect("sessions lock");
            sessions
                .owners
                .get(&(endpoint.clone(), session_id.to_owned()))
                .map(|(o, _)| o.clone())
        };
        if known.as_deref() != Some(owner.as_str()) {
            ctx.deny("<session>", "unknown or foreign session", None, None)
                .await?;
            return Ok(empty(StatusCode::NOT_FOUND));
        }
    }

    let path = match &endpoint {
        None => "/mcp".to_owned(),
        Some(name) => format!("/mcp/{name}"),
    };

    // -- server -> client channel: not opened ---------------------------------------
    if request.method() == Method::GET {
        let cid = correlation_id();
        ctx.deny(
            &format!("GET {path}"),
            "server-initiated channel (SSE) is not enabled in this build",
            Some(&cid),
            ctx.detail(),
        )
        .await?;
        return Ok(json_response(
            StatusCode::METHOD_NOT_ALLOWED,
            &error_response(
                Value::Null,
                METHOD_NOT_FOUND,
                "server-initiated channel not enabled",
                &cid,
            ),
        ));
    }
    if request.method() == Method::DELETE {
        ctx.deny(
            "DELETE",
            "session teardown requires an authenticated session; stateless gateway",
            None,
            ctx.detail(),
        )
        .await?;
        return Ok(empty(StatusCode::METHOD_NOT_ALLOWED));
    }

    let raw = match read_body(request.into_body(), state.config.max_request_bytes).await {
        Ok(raw) => raw,
        Err(true) => {
            ctx.deny("<oversize>", "request size limit", None, ctx.detail())
                .await?;
            return Ok(empty(StatusCode::PAYLOAD_TOO_LARGE));
        }
        Err(false) => return Err(Error::io("request body could not be read")),
    };
    let message = match strict_json(&raw) {
        Ok(message) => message,
        Err(_) => {
            let cid = correlation_id();
            ctx.deny("<parse>", "invalid strict JSON", Some(&cid), ctx.detail())
                .await?;
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"jsonrpc": "2.0", "id": null, "error": {"code": PARSE_ERROR, "message": "Parse error"}}),
            ));
        }
    };

    // -- batch: refused, never unpacked ------------------------------------------------
    if let Value::Array(batch) = &message {
        let cid = correlation_id();
        let mut detail = Map::new();
        detail.insert("messages".into(), json!(batch.len()));
        detail.extend(ctx.detail().unwrap_or_default());
        ctx.deny(
            "<batch>",
            &format!(
                "JSON-RPC batching is not part of MCP {}",
                policy.mcp.spec_version
            ),
            Some(&cid),
            Some(detail),
        )
        .await?;
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &error_response(
                Value::Null,
                INVALID_REQUEST,
                "batch requests are not supported",
                &cid,
            ),
        ));
    }
    let Value::Object(message) = message else {
        let cid = correlation_id();
        ctx.deny(
            "<malformed>",
            "request body is not a JSON-RPC object",
            Some(&cid),
            ctx.detail(),
        )
        .await?;
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &error_response(Value::Null, INVALID_REQUEST, "invalid request", &cid),
        ));
    };
    let envelope_ok = message.get("jsonrpc") == Some(&json!("2.0"))
        && message.get("method").is_some_and(Value::is_string)
        && message.get("id").is_none_or(is_jsonrpc_id);
    if !envelope_ok {
        let cid = correlation_id();
        ctx.deny(
            "<malformed>",
            "invalid JSON-RPC envelope",
            Some(&cid),
            ctx.detail(),
        )
        .await?;
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &error_response(Value::Null, INVALID_REQUEST, "invalid request", &cid),
        ));
    }
    let method = message["method"].as_str().expect("checked").to_owned();
    if message.get("params").is_some_and(|p| !p.is_object()) {
        let cid = correlation_id();
        ctx.deny(
            &method,
            "params must be an object",
            Some(&cid),
            ctx.detail(),
        )
        .await?;
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &error_response(
                message.get("id").cloned().unwrap_or(Value::Null),
                INVALID_REQUEST,
                "invalid params",
                &cid,
            ),
        ));
    }
    let request_id = message.get("id").cloned();

    let refuse = |reason: String, code: i64| {
        let ctx = &ctx;
        let method = method.clone();
        let request_id = request_id.clone();
        async move {
            let cid = correlation_id();
            ctx.deny(&method, &reason, Some(&cid), ctx.detail()).await?;
            // A notification has no response by protocol; the audit entry is the trace.
            // This is a refusal on record, not a silent drop.
            Ok::<Response, Error>(match request_id {
                None => empty(StatusCode::ACCEPTED),
                Some(id) => json_response(
                    StatusCode::OK,
                    &error_response(id, code, "method not allowed", &cid),
                ),
            })
        }
    };

    if method != "tools/call" && upstream.requires_user_credentials() {
        let verifier = state.config.verifier.clone();
        let incoming = headers.clone();
        let principal = tokio::task::spawn_blocking(move || verifier.session_principal(&incoming))
            .await
            .map_err(|e| Error::runtime(e.to_string()))?;
        match principal {
            Ok(principal) => forward_headers.principal = Some(principal),
            Err(_) => {
                return refuse(
                    "upstream session requires an authenticated mandate".into(),
                    METHOD_NOT_FOUND,
                )
                .await;
            }
        }
    }

    let mut outgoing: Vec<u8> = raw.clone();
    let empty_params = Value::Object(Map::new());
    if method == "tools/call" {
        // -- tools/call: the enforced path -------------------------------------------
        let params = message.get("params").unwrap_or(&empty_params);
        let tool = params.get("name").cloned().unwrap_or(json!(""));
        let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
        let tool = match (&tool, arguments.is_object()) {
            (Value::String(t), true) if !t.is_empty() => t.clone(),
            _ => return refuse("invalid tool name or arguments".into(), INVALID_REQUEST).await,
        };
        let verifier = state.config.verifier.clone();
        let (call_tool, call_args, call_headers, call_endpoint, call_policy) = (
            tool.clone(),
            arguments.clone(),
            headers.clone(),
            endpoint.clone(),
            policy.clone(),
        );
        let outcome = tokio::task::spawn_blocking(move || {
            verifier.verify_call(
                &call_tool,
                &call_args,
                &call_headers,
                call_endpoint.as_deref(),
                Some(call_policy),
            )
        })
        .await
        .map_err(|e| Error::runtime(e.to_string()))?;
        // The verifier must never fail open: an incomplete verification is a denial.
        let (decision, reason): (Option<Decision>, String) = match outcome {
            Ok(decision) => {
                let reason = decision.reason.clone();
                (Some(decision), reason)
            }
            Err(e) => (None, format!("internal verifier error: {}", e.message)),
        };
        let allowed = decision.as_ref().is_some_and(|d| d.allow);
        let cid = (!allowed).then(correlation_id);
        // warn-only forwards a denied call; `enforced` records that so the log never
        // reads as if the call had been blocked.
        let enforced = allowed || mode != "warn-only";
        let mut detail = ctx.detail().unwrap_or_default();
        if let Some(warning) = state
            .config
            .verifier
            .revocation
            .as_ref()
            .and_then(|r| r.last_error())
        {
            detail.insert("revocation_warning".into(), json!(warning));
        }
        let identity = decision
            .as_ref()
            .map(Decision::identity)
            .unwrap_or_else(|| {
                let mut map = Map::new();
                for key in ["mandate_id", "subject", "issuer", "agent_key"] {
                    map.insert(key.into(), Value::Null);
                }
                map
            });
        ctx.audit(Record {
            decision: if allowed { "ALLOW" } else { "DENY" }.into(),
            method: Some(method.clone()),
            tool: Some(tool.clone()),
            agent_id: decision.as_ref().and_then(|d| d.agent_id.clone()),
            resource: decision.as_ref().and_then(|d| d.resource.clone()),
            reason: (!allowed).then(|| reason.clone()),
            correlation_id: cid.clone(),
            enforced: Some(enforced),
            arguments_hash: decision.as_ref().and_then(|d| d.arguments_hash.clone()),
            profile: Some(
                decision
                    .as_ref()
                    .map_or_else(|| "native".to_owned(), |d| d.profile.clone()),
            ),
            detail: Some(detail),
            remaining_budget: decision.as_ref().and_then(|d| d.remaining_budget),
            identity: Some(identity),
            ..Default::default()
        })
        .await?;
        if !allowed && mode != "warn-only" {
            return Ok(match &request_id {
                None => empty(StatusCode::ACCEPTED),
                Some(id) => json_response(
                    StatusCode::OK,
                    &deny_result(id.clone(), cid.as_deref().unwrap_or_default()),
                ),
            });
        }
        if let Some(decision) = decision.as_ref().filter(|d| d.allow) {
            forward_headers.principal = Some((decision.issuer.clone(), decision.subject.clone()));
        }
        outgoing = match policy.tool(&tool).and_then(|t| t.upstream_tool.clone()) {
            Some(alias) => rename_tool(&message, &alias),
            None => dumps(&Value::Object(message.clone())).into_bytes(),
        };
    } else if method == "tools/list" {
        // -- tools/list: relayed, then filtered ---------------------------------------
        ctx.audit(Record {
            decision: "RELAY".into(),
            method: Some(method.clone()),
            detail: ctx.detail(),
            ..Default::default()
        })
        .await?;
        let response = upstream
            .forward("POST", Bytes::from(raw), &forward_headers)
            .await?;
        let (messages, _) = response_messages(
            response.status,
            response.header("content-type"),
            &response.body,
        )?;
        if let Some(id) = &request_id
            && (messages.len() != 1 || messages[0].get("id") != Some(id))
        {
            return Err(Error::value("unpaired upstream catalog response"));
        }
        let allowed = policy.tools_for(endpoint.as_deref());
        let aliases: HashMap<String, String> = policy
            .tools
            .iter()
            .filter(|t| allowed.contains(&t.name.as_str()))
            .filter_map(|t| t.upstream_tool.clone().map(|u| (u, t.name.clone())))
            .collect();
        let (body, masked) = rewrite_tools_list(&response, &allowed, &aliases)?;
        let mut detail = ctx.detail().unwrap_or_default();
        if masked > 0 {
            detail.insert("tools_masked".into(), json!(masked));
        }
        ctx.audit(Record {
            decision: "ALLOW".into(),
            method: Some(method.clone()),
            detail: Some(detail).filter(|d| !d.is_empty()),
            ..Default::default()
        })
        .await?;
        return Ok(relay(&response, Some(body)));
    } else if policy.method_allowed(&method) {
        // -- allow-listed session methods ---------------------------------------------
        if method == "initialize" {
            let mut rewritten = message.clone();
            let mut params = rewritten
                .get("params")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            params.insert("protocolVersion".into(), json!(policy.mcp.spec_version));
            params.insert("capabilities".into(), json!({}));
            rewritten.insert("params".into(), Value::Object(params));
            outgoing = dumps(&Value::Object(rewritten)).into_bytes();
        }
        ctx.audit(Record {
            decision: "ALLOW".into(),
            method: Some(method.clone()),
            detail: ctx.detail(),
            ..Default::default()
        })
        .await?;
    } else {
        // -- everything else: default deny ---------------------------------------------
        return refuse(
            format!("method {} is not in the MCP allowlist", py_repr(&method)),
            METHOD_NOT_FOUND,
        )
        .await;
    }

    let response = upstream
        .forward("POST", Bytes::from(outgoing), &forward_headers)
        .await?;
    let (mut messages, _) = response_messages(
        response.status,
        response.header("content-type"),
        &response.body,
    )?;
    if let Some(id) = &request_id
        && (messages.len() != 1 || messages[0].get("id") != Some(id))
    {
        return Err(Error::value("unpaired upstream response"));
    }
    remember_session(state, &endpoint, &headers, &response, now).await?;
    if method == "initialize"
        && let Some(result) = messages
            .first_mut()
            .and_then(|m| m.get_mut("result"))
            .and_then(Value::as_object_mut)
    {
        let negotiated = result
            .get("protocolVersion")
            .cloned()
            .unwrap_or_else(|| json!(policy.mcp.spec_version));
        if negotiated != json!(policy.mcp.spec_version) {
            return Err(Error::value(
                "upstream did not negotiate the supported MCP version",
            ));
        }
        if let Some(capabilities) = result.get("capabilities") {
            let has_tools = match capabilities {
                Value::Object(map) => map.contains_key("tools"),
                Value::Array(items) => items.contains(&json!("tools")),
                Value::String(s) => s.contains("tools"),
                _ => false,
            };
            result.insert(
                "capabilities".into(),
                if has_tools {
                    json!({"tools": {}})
                } else {
                    json!({})
                },
            );
        }
        let mut reply = json_response(
            StatusCode::from_u16(response.status).unwrap_or(StatusCode::OK),
            &messages[0],
        );
        copy_session_headers(&response, reply.headers_mut());
        return Ok(reply);
    }
    Ok(relay(&response, None))
}

async fn remember_session(
    state: &AppState,
    endpoint: &Option<String>,
    headers: &Headers,
    response: &UpstreamResponse,
    now: Instant,
) -> Result<()> {
    let Some(session_id) = response.header("mcp-session-id").filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    {
        let sessions = state.sessions.lock().expect("sessions lock");
        if session_id.chars().count() > 256 || sessions.owners.len() >= MAX_SESSIONS {
            return Err(Error::value("session capacity/size exceeded"));
        }
    }
    let owner = session_owner(&state.config.verifier, headers).await?;
    let mut sessions = state.sessions.lock().expect("sessions lock");
    let key = (endpoint.clone(), session_id.to_owned());
    if let Some((previous, _)) = sessions.owners.get(&key)
        && *previous != owner
    {
        return Err(Error::value("upstream reused another mandate's session"));
    }
    sessions.order.retain(|k| *k != key);
    sessions.order.push_back(key.clone());
    sessions.owners.insert(key, (owner, now + SESSION_TTL));
    Ok(())
}

async fn healthz() -> Response {
    json_response(StatusCode::OK, &json!({"status": "ok"}))
}

fn client_host(request: &Request) -> String {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_string())
        .unwrap_or_else(|| "unknown".into())
}

/// Build the proxy router. Serve it with `into_make_service_with_connect_info::<SocketAddr>()`
/// so the per-client rate limit sees real peer addresses.
pub fn create_app(config: ProxyConfig) -> Result<Router> {
    config.validate()?;
    let upstreams: HashMap<Option<String>, SharedUpstream> = config
        .upstreams
        .iter()
        .map(|(name, up)| (name.clone(), up.clone()))
        .collect();
    let names: Vec<Option<String>> = config
        .upstreams
        .iter()
        .map(|(name, _)| name.clone())
        .collect();
    let state = Arc::new(AppState {
        config,
        upstreams,
        rates: Mutex::new(Rates::default()),
        sessions: Mutex::new(Sessions::default()),
    });
    let mut router = Router::new();
    for name in names {
        let path = match &name {
            None => "/mcp".to_owned(),
            Some(n) => format!("/mcp/{n}"),
        };
        let handler = move |State(state): State<Arc<AppState>>, request: Request| {
            let name = name.clone();
            async move {
                let client = client_host(&request);
                handle(state, name, client, request).await
            }
        };
        router = router.route(
            &path,
            get(handler.clone()).post(handler.clone()).delete(handler),
        );
    }
    Ok(router.route("/healthz", get(healthz)).with_state(state))
}

/// Close every upstream (stdio children are killed).
pub async fn close_upstreams(upstreams: &[(Option<String>, SharedUpstream)]) {
    for (_, upstream) in upstreams {
        upstream.close().await;
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        empty(StatusCode::INTERNAL_SERVER_ERROR)
    }
}
