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
//! client -> server, server/discover relayed, capabilities reduced to tools
//! client -> server, anything else  refused with a JSON-RPC error
//! server -> client (GET/SSE)       channel not opened — a server can never initiate
//! ```
//!
//! Two MCP eras are served (see [`super::era`]): `initialize`-based revisions with
//! sessions, and 2026-07-28 requests carrying their revision in `_meta`, whose mirrored
//! headers are checked against the body before any decision.
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

use crate::approval::{Approved, hold_result};
use crate::audit::{AuditLog, Record};
use crate::error::{Error, ErrorKind, Result, py_repr};
use crate::json::{dumps, strict_json};
use crate::policy::{MODERN_SPEC_VERSIONS, Policy};
use crate::proxy::era::{self, Era, ParamHeader};
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
/// How often a running gateway looks for approved calls whose lease ran out.
const RECEIPT_SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// A `server/discover` probe left unanswered this long identifies a legacy server.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// The gateway's own refusal of a feature it does not open (multi round-trip
/// requests, tasks): outside the JSON-RPC reserved range, as MCP 2026-07-28 asks.
pub const NOT_ENABLED: i64 = -31001;

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

/// `(endpoint, public tool name)`.
type ToolKey = (Option<String>, String);

struct AppState {
    config: ProxyConfig,
    upstreams: HashMap<Option<String>, SharedUpstream>,
    rates: Mutex<Rates>,
    sessions: Mutex<Sessions>,
    last_sweep: Mutex<Instant>,
    /// Each upstream's era, once detected.
    eras: Mutex<HashMap<Option<String>, Era>>,
    /// `x-mcp-header` annotations learned from each endpoint's catalog, by public tool name.
    param_headers: Mutex<HashMap<ToolKey, Vec<ParamHeader>>>,
    /// When the client-capacity refusal was last written to the audit log.
    capacity_logged: Mutex<Option<Instant>>,
}

/// Settle approved calls left `reserved` past their lease (a crash, a restart): their
/// upstream effect is unknown. Each becomes an `OUTCOME` entry with state `unknown`.
fn sweep_receipts(verifier: &Verifier, audit: Option<&AuditLog>) -> Result<()> {
    let Some(store) = &verifier.receipts else {
        return Ok(());
    };
    for row in store.sweep(crate::isotime::timestamp(&verifier.now()))? {
        if let Some(audit) = audit {
            let mut detail = Map::new();
            detail.insert("receipt_id".into(), json!(row.receipt_id));
            detail.insert("state".into(), json!("unknown"));
            detail.insert("instance_id".into(), json!(row.instance_id));
            detail.insert("lease_expired".into(), json!(true));
            audit.record(Record {
                decision: "OUTCOME".into(),
                method: Some("tools/call".into()),
                detail: Some(detail),
                ..Default::default()
            })?;
        }
    }
    Ok(())
}

/// What became of an approved call once forwarded: `ok` when the tool answered (an
/// `isError` tool result included), `upstream_error` for a JSON-RPC or HTTP error
/// before any result, `unknown` when no usable answer came back.
fn outcome_state(forwarded: &Result<UpstreamResponse>) -> &'static str {
    match forwarded {
        Err(e) if e.kind == ErrorKind::Io && e.message.starts_with("ConnectError") => {
            "upstream_error"
        }
        Err(_) => "unknown",
        Ok(response) if response.status >= 400 => "upstream_error",
        Ok(response) => match response_messages(
            response.status,
            response.header("content-type"),
            &response.body,
        ) {
            Ok((messages, _)) if messages.len() == 1 => {
                if messages[0].get("result").is_some() {
                    "ok"
                } else {
                    "upstream_error"
                }
            }
            _ => "unknown",
        },
    }
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

/// Serialize messages back in the shape they arrived in (one JSON object, or SSE).
fn serialize(messages: &[Value], is_sse: bool) -> Vec<u8> {
    if is_sse {
        messages
            .iter()
            .flat_map(|m| format!("event: message\ndata: {}\n\n", dumps(m)).into_bytes())
            .collect()
    } else {
        messages
            .first()
            .map(|m| dumps(m).into_bytes())
            .unwrap_or_default()
    }
}

/// How a catalog reply is rewritten for a 2026-07-28 exchange.
struct ModernList<'a> {
    /// The agent is modern: the filtered list is per-mandate (`cacheScope: "private"`).
    private: bool,
    /// The upstream is modern: its `x-mcp-header` annotations, by public tool name.
    /// A tool whose annotations are invalid is dropped, as the revision requires.
    annotations: &'a mut Vec<(String, Vec<ParamHeader>)>,
}

fn rewrite_tools_list(
    upstream: &UpstreamResponse,
    allowed: &[&str],
    aliases: &HashMap<String, String>,
    mut modern: Option<ModernList<'_>>,
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
        let (Some(modern), Some(result)) = (
            modern.as_mut(),
            payload.get_mut("result").and_then(Value::as_object_mut),
        ) else {
            continue;
        };
        if let Some(tools) = result.get_mut("tools").and_then(Value::as_array_mut) {
            let before = tools.len();
            tools.retain(|tool| match era::param_headers(tool) {
                Ok(found) => {
                    let name = tool.get("name").and_then(Value::as_str).unwrap_or("");
                    modern.annotations.push((name.to_owned(), found));
                    true
                }
                Err(_) => false,
            });
            masked += before - tools.len();
        }
        if modern.private {
            era::mark_private(result);
            result
                .entry("resultType")
                .or_insert_with(|| json!("complete"));
        }
    }
    Ok((serialize(&messages, is_sse), masked))
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

    /// Settle the receipt of an approved call and record its `OUTCOME`.
    async fn outcome(&self, tool: &str, approved: &Approved, state: &str) -> Result<()> {
        let verifier = self.state.config.verifier.clone();
        let receipt_id = approved.receipt_id.clone();
        let settled = state.to_owned();
        let updated = tokio::task::spawn_blocking(move || match &verifier.receipts {
            Some(store) => store.finish(
                &receipt_id,
                &verifier.instance_id,
                &settled,
                crate::isotime::timestamp(&verifier.now()),
            ),
            None => Ok(false),
        })
        .await
        .map_err(|e| Error::runtime(e.to_string()))??;
        let mut detail = self.detail().unwrap_or_default();
        detail.insert("receipt_id".into(), json!(approved.receipt_id));
        detail.insert("request_id".into(), json!(approved.request_id));
        detail.insert("state".into(), json!(state));
        if !updated {
            // A sweep already declared it unknown: the lease was shorter than the call.
            detail.insert("late".into(), json!(true));
        }
        self.audit(Record {
            decision: "OUTCOME".into(),
            method: Some("tools/call".into()),
            tool: Some(tool.to_owned()),
            detail: Some(detail),
            ..Default::default()
        })
        .await
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
        if !rates.clients.contains_key(&client) && rates.clients.len() >= MAX_CLIENTS {
            None
        } else {
            if !rates.clients.contains_key(&client) {
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
            Some((window.count > state.config.requests_per_minute).then_some(window.count))
        }
    };
    let Some(exceeded) = exceeded else {
        // Logged once a minute at most: a flood of new clients must not flood the log.
        let log = {
            let mut last = state.capacity_logged.lock().expect("capacity lock");
            let due = last.is_none_or(|t| t + Duration::from_secs(60) <= now);
            if due {
                *last = Some(now);
            }
            due
        };
        if log {
            ctx.deny(
                "<client-cap>",
                "tracked client capacity reached",
                None,
                None,
            )
            .await?;
        }
        return Ok(empty(StatusCode::TOO_MANY_REQUESTS));
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
    let header_version = headers
        .get("mcp-protocol-version")
        .filter(|v| !v.is_empty())
        .map(str::to_owned);
    if let Some(version) = &header_version
        && !policy.mcp.accepts(version)
    {
        let cid = correlation_id();
        let mut detail = ctx.detail().unwrap_or_default();
        detail.insert(
            "requested".into(),
            json!(version.chars().take(64).collect::<String>()),
        );
        ctx.deny(
            "<protocol-version>",
            "unsupported MCP-Protocol-Version",
            Some(&cid),
            Some(detail),
        )
        .await?;
        let supported: Vec<&str> = policy
            .mcp
            .spec_versions
            .iter()
            .map(String::as_str)
            .collect();
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &unsupported_version(Value::Null, &supported, version, &cid),
        ));
    }
    // A 2026-07-28 request has no session: its `Mcp-Session-Id` is ignored.
    let header_modern = header_version
        .as_deref()
        .is_some_and(|v| MODERN_SPEC_VERSIONS.contains(&v));

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
    if let Some(session_id) = headers
        .get("mcp-session-id")
        .filter(|s| !s.is_empty() && !header_modern)
    {
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

    // -- MCP 2026-07-28: headers checked against the body, before any decision --------
    let modern = header_modern || era::body_version(&message).is_some();
    let called_tool = message
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .filter(|_| method == "tools/call")
        .map(str::to_owned);
    let known_params = called_tool.as_ref().and_then(|tool| {
        state
            .param_headers
            .lock()
            .expect("param headers lock")
            .get(&(endpoint.clone(), tool.clone()))
            .cloned()
    });
    if modern {
        let mismatch = era::check_headers(&message, &headers, known_params.as_deref())
            .err()
            .map(|reason| (reason, era::HEADER_MISMATCH, "Header mismatch"))
            .or_else(|| {
                (!era::has_client_capabilities(&message)).then(|| {
                    (
                        "_meta clientCapabilities missing".to_owned(),
                        era::INVALID_PARAMS,
                        "invalid params",
                    )
                })
            });
        if let Some((reason, code, text)) = mismatch {
            let cid = correlation_id();
            let mut detail = ctx.detail().unwrap_or_default();
            detail.insert("method".into(), json!(method));
            ctx.deny("<header-mismatch>", &reason, Some(&cid), Some(detail))
                .await?;
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &error_response(request_id.clone().unwrap_or(Value::Null), code, text, &cid),
            ));
        }
    }

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

    // Multi round-trip replies and tasks reach no upstream until policy can govern them.
    let params_map = message.get("params").and_then(Value::as_object);
    if let Some(key) = ["task", "inputResponses", "requestState"]
        .into_iter()
        .find(|k| params_map.is_some_and(|p| p.contains_key(*k)))
    {
        return refuse(
            format!("params.{key}: tasks and multi round-trip requests are not enabled"),
            NOT_ENABLED,
        )
        .await;
    }
    if modern && era::LEGACY_ONLY_METHODS.contains(&method.as_str()) {
        return refuse(
            format!(
                "method {} does not exist in MCP 2026-07-28",
                py_repr(&method)
            ),
            METHOD_NOT_FOUND,
        )
        .await;
    }

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

    // -- upstream era -------------------------------------------------------------------
    // `upstream_version`: the revision declared to a modern upstream; `None` relays in
    // the `initialize` era exactly as before.
    let cached_era = state
        .eras
        .lock()
        .expect("eras lock")
        .get(&endpoint)
        .cloned();
    let upstream_era = match cached_era {
        Some(found) => Some(found),
        None if modern => {
            let mut principal = forward_headers.principal.clone();
            if principal.is_none() && upstream.requires_user_credentials() {
                let verifier = state.config.verifier.clone();
                let incoming = headers.clone();
                principal =
                    tokio::task::spawn_blocking(move || verifier.session_principal(&incoming))
                        .await
                        .map_err(|e| Error::runtime(e.to_string()))?
                        .ok();
            }
            Some(ensure_era(state, &endpoint, &upstream, &policy, principal).await?)
        }
        None => None,
    };
    let upstream_version: Option<String> = match (&upstream_era, modern) {
        (Some(Era::Legacy), true) => {
            // A dual-era agent falls back to `initialize` on this error.
            let cid = correlation_id();
            ctx.deny(
                &method,
                "upstream speaks an initialize-era MCP revision",
                Some(&cid),
                ctx.detail(),
            )
            .await?;
            let requested = era::body_version(&message)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &unsupported_version(
                    request_id.clone().unwrap_or(Value::Null),
                    &policy.mcp.legacy_versions(),
                    &requested,
                    &cid,
                ),
            ));
        }
        (_, true) => era::body_version(&message)
            .and_then(Value::as_str)
            .map(str::to_owned),
        (Some(Era::Modern { versions, .. }), false) => match common_version(&policy, versions) {
            Some(version) => Some(version),
            None => {
                return refuse(
                    "no MCP revision shared with the upstream".into(),
                    NOT_ENABLED,
                )
                .await;
            }
        },
        _ => None,
    };
    let translated = upstream_version.is_some() && !modern;

    let mut outgoing: Vec<u8> = raw.clone();
    let mut approved: Option<(String, Approved)> = None;
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
        let due = {
            let mut last = state.last_sweep.lock().expect("sweep lock");
            let due = last.elapsed() >= RECEIPT_SWEEP_INTERVAL;
            if due {
                *last = Instant::now();
            }
            due
        };
        if due && state.config.verifier.receipts.is_some() {
            let verifier = state.config.verifier.clone();
            let audit = state.config.audit.clone();
            tokio::task::spawn_blocking(move || sweep_receipts(&verifier, audit.as_deref()))
                .await
                .map_err(|e| Error::runtime(e.to_string()))??;
        }
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
        let hold = decision.as_ref().and_then(|d| d.hold.clone());
        let cid = (!allowed).then(correlation_id);
        // A tool under approval is never forwarded without a consumed receipt, not even
        // in warn-only: otherwise any refused receipt would skip the approval.
        let gated = policy.tool(&tool).is_some_and(|t| t.approval.is_some());
        // warn-only forwards a denied call; `enforced` records that so the log never
        // reads as if the call had been blocked.
        let enforced = allowed || mode != "warn-only" || gated;
        let mut detail = ctx.detail().unwrap_or_default();
        if let Some(endorsements) = decision.as_ref().and_then(Decision::endorsements_json) {
            detail.insert("third_party".into(), endorsements);
        }
        if let Some(Value::Object(held)) = hold.as_ref().map(|h| h.audit_detail()) {
            detail.extend(held);
        }
        if let Some(consumed) = decision.as_ref().and_then(|d| d.approval.as_ref()) {
            detail.insert("approval".into(), consumed.audit_detail());
        }
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
            decision: if hold.is_some() {
                "HOLD"
            } else if allowed {
                "ALLOW"
            } else {
                "DENY"
            }
            .into(),
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
        if let Some(hold) = &hold {
            return Ok(match &request_id {
                None => empty(StatusCode::ACCEPTED),
                Some(id) => json_response(
                    StatusCode::OK,
                    &hold_result(id.clone(), cid.as_deref().unwrap_or_default(), hold),
                ),
            });
        }
        if !allowed && (mode != "warn-only" || gated) {
            return Ok(match &request_id {
                None => empty(StatusCode::ACCEPTED),
                Some(id) => {
                    let mut denial = deny_result(id.clone(), cid.as_deref().unwrap_or_default());
                    if modern {
                        denial["result"]["resultType"] = json!("complete");
                    }
                    json_response(StatusCode::OK, &denial)
                }
            });
        }
        if let Some(decision) = decision.as_ref().filter(|d| d.allow) {
            forward_headers.principal = Some((decision.issuer.clone(), decision.subject.clone()));
            approved = decision.approval.clone().map(|a| (tool.clone(), a));
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
        let (body, sent) = prepare(&raw, upstream_version.as_deref(), &headers, None)?;
        forward_headers.incoming = sent;
        let response = upstream.forward("POST", body, &forward_headers).await?;
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
        let mut annotations = Vec::new();
        let list_mode = upstream_version.as_ref().map(|_| ModernList {
            private: modern,
            annotations: &mut annotations,
        });
        let (body, masked) = rewrite_tools_list(&response, &allowed, &aliases, list_mode)?;
        if upstream_version.is_some() {
            let mut known = state.param_headers.lock().expect("param headers lock");
            known.retain(|(e, _), _| *e != endpoint);
            for (tool, found) in annotations {
                known.insert((endpoint.clone(), tool), found);
            }
        }
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
        let mut reply = relay(&response, Some(body));
        if modern {
            reply.headers_mut().remove("mcp-session-id");
        }
        return Ok(reply);
    } else if method == "server/discover" && modern {
        // -- server/discover: relayed, reduced to tools ------------------------------
        ctx.audit(Record {
            decision: "ALLOW".into(),
            method: Some(method.clone()),
            detail: ctx.detail(),
            ..Default::default()
        })
        .await?;
    } else if policy.method_allowed(&method) {
        // -- allow-listed session methods ---------------------------------------------
        ctx.audit(Record {
            decision: "ALLOW".into(),
            method: Some(method.clone()),
            detail: ctx.detail(),
            ..Default::default()
        })
        .await?;
        if translated {
            // A modern upstream has no handshake: the gateway answers it itself.
            if let Some(local) = local_answer(&method, &message, &policy, upstream_era.as_ref())? {
                return Ok(local);
            }
        } else if method == "initialize" {
            let legacy = policy.mcp.legacy_versions();
            let requested = message
                .get("params")
                .and_then(|p| p.get("protocolVersion"))
                .and_then(Value::as_str)
                .filter(|v| legacy.contains(v));
            let Some(version) = requested.or_else(|| legacy.first().copied()) else {
                return Err(Error::value("no initialize-era MCP revision is accepted"));
            };
            let mut rewritten = message.clone();
            let mut params = rewritten
                .get("params")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            params.insert("protocolVersion".into(), json!(version));
            params.insert("capabilities".into(), json!({}));
            rewritten.insert("params".into(), Value::Object(params));
            outgoing = dumps(&Value::Object(rewritten)).into_bytes();
        }
    } else {
        // -- everything else: default deny ---------------------------------------------
        return refuse(
            format!("method {} is not in the MCP allowlist", py_repr(&method)),
            METHOD_NOT_FOUND,
        )
        .await;
    }

    let (body, sent) = prepare(
        &outgoing,
        upstream_version.as_deref(),
        &headers,
        known_params.as_deref(),
    )?;
    forward_headers.incoming = sent;
    let forwarded = upstream.forward("POST", body, &forward_headers).await;
    if let Some((tool, receipt)) = &approved {
        ctx.outcome(tool, receipt, outcome_state(&forwarded))
            .await?;
    }
    let response = forwarded?;

    // A legacy agent's `initialize` refused by an upstream of unknown era: a modern-only
    // server answers no handshake. Probe it; if modern, answer in its place.
    if method == "initialize"
        && upstream_era.is_none()
        && !policy.mcp.modern_versions().is_empty()
        && !initialize_succeeded(&response)
    {
        let found = ensure_era(
            state,
            &endpoint,
            &upstream,
            &policy,
            forward_headers.principal.clone(),
        )
        .await?;
        if matches!(found, Era::Modern { .. })
            && let Some(local) = local_answer(&method, &message, &policy, Some(&found))?
        {
            return Ok(local);
        }
    }

    let (mut messages, is_sse) = response_messages(
        response.status,
        response.header("content-type"),
        &response.body,
    )?;
    if let Some(id) = &request_id
        && (messages.len() != 1 || messages[0].get("id") != Some(id))
    {
        return Err(Error::value("unpaired upstream response"));
    }
    if upstream_version.is_some() {
        // -- a modern upstream's reply ------------------------------------------------
        for message in &messages {
            let kind = message
                .get("result")
                .and_then(|r| r.get("resultType"))
                .and_then(Value::as_str)
                .unwrap_or("complete");
            if kind != "complete" {
                return refuse(
                    format!(
                        "upstream returned resultType {}; tasks and multi round-trip requests are not enabled",
                        py_repr(kind)
                    ),
                    NOT_ENABLED,
                )
                .await;
            }
        }
        if modern {
            for message in &mut messages {
                if let Some(result) = message.get_mut("result").and_then(Value::as_object_mut) {
                    result
                        .entry("resultType")
                        .or_insert_with(|| json!("complete"));
                    if method == "server/discover" {
                        reduce_discover(result, &policy);
                    }
                }
            }
        }
        let mut reply = relay(&response, Some(serialize(&messages, is_sse)));
        reply.headers_mut().remove("mcp-session-id");
        return Ok(reply);
    }
    remember_session(state, &endpoint, &headers, &response, now).await?;
    if method == "initialize"
        && let Some(result) = messages
            .first_mut()
            .and_then(|m| m.get_mut("result"))
            .and_then(Value::as_object_mut)
    {
        let sent: Value = strict_json(&outgoing)?;
        let requested = sent
            .pointer("/params/protocolVersion")
            .cloned()
            .unwrap_or(Value::Null);
        let negotiated = result.get("protocolVersion").cloned().unwrap_or(requested);
        let accepted = negotiated
            .as_str()
            .is_some_and(|v| policy.mcp.legacy_versions().contains(&v));
        if !accepted {
            return Err(Error::value(
                "upstream did not negotiate a supported MCP version",
            ));
        }
        if let Some(capabilities) = result.get("capabilities") {
            let reduced = era::tools_only(Some(capabilities));
            result.insert("capabilities".into(), reduced);
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

/// The body and headers sent upstream. In the `initialize` era the body is unchanged and
/// no 2026-07-28 mirror header is passed on. To a modern upstream, `_meta` declares
/// `version` with the client capabilities the gateway allows (none), and every mirror
/// header is recomputed from that body — after any `rename_tool`.
fn prepare(
    outgoing: &[u8],
    version: Option<&str>,
    incoming: &Headers,
    params: Option<&[ParamHeader]>,
) -> Result<(Bytes, Headers)> {
    let Some(version) = version else {
        return Ok((
            Bytes::from(outgoing.to_vec()),
            era::legacy_forward(incoming),
        ));
    };
    let Value::Object(mut message) = strict_json(outgoing)? else {
        return Err(Error::value("request body is not a JSON-RPC object"));
    };
    // Mirrors an `initialize`-era agent sent were never checked: none is passed on.
    let base = if era::body_version(&message).is_some() {
        incoming.clone()
    } else {
        era::legacy_forward(incoming)
    };
    era::set_meta(&mut message, version);
    let headers = era::modern_forward(&base, &message, params);
    Ok((
        Bytes::from(dumps(&Value::Object(message)).into_bytes()),
        headers,
    ))
}

/// The first revision of the policy's modern list the upstream also supports.
fn common_version(policy: &Policy, upstream_versions: &[String]) -> Option<String> {
    policy
        .mcp
        .modern_versions()
        .into_iter()
        .find(|v| upstream_versions.iter().any(|u| u == v))
        .map(str::to_owned)
}

fn unsupported_version(id: Value, supported: &[&str], requested: &str, cid: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": era::UNSUPPORTED_PROTOCOL_VERSION,
            "message": "Unsupported protocol version",
            "data": {
                "supported": supported,
                "requested": requested.chars().take(64).collect::<String>(),
                "correlation_id": cid,
            },
        },
    })
}

/// A `DiscoverResult` as the gateway presents it: tools only, the revisions both the
/// policy and the upstream accept (plus the `initialize` ones the gateway translates),
/// and private, briefly cached.
fn reduce_discover(result: &mut Map<String, Value>, policy: &Policy) {
    let capabilities = era::tools_only(result.get("capabilities"));
    result.insert("capabilities".into(), capabilities);
    let upstream: Vec<String> = result
        .get("supportedVersions")
        .and_then(Value::as_array)
        .map(|v| {
            v.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let mut versions: Vec<&str> = policy
        .mcp
        .modern_versions()
        .into_iter()
        .filter(|v| upstream.iter().any(|u| u == v))
        .collect();
    versions.extend(policy.mcp.legacy_versions());
    result.insert("supportedVersions".into(), json!(versions));
    era::mark_private(result);
}

/// True when an `initialize` reply is a successful JSON-RPC result.
fn initialize_succeeded(response: &UpstreamResponse) -> bool {
    response.status < 400
        && response_messages(
            response.status,
            response.header("content-type"),
            &response.body,
        )
        .is_ok_and(|(m, _)| m.first().is_some_and(|m| m.get("result").is_some()))
}

/// The gateway's own answer to a legacy agent's handshake methods when the upstream is
/// modern; `None` for methods that are relayed.
fn local_answer(
    method: &str,
    message: &Map<String, Value>,
    policy: &Policy,
    upstream_era: Option<&Era>,
) -> Result<Option<Response>> {
    let id = message.get("id").cloned().unwrap_or(Value::Null);
    match method {
        "initialize" => {
            let legacy = policy.mcp.legacy_versions();
            let requested = message
                .get("params")
                .and_then(|p| p.get("protocolVersion"))
                .and_then(Value::as_str)
                .filter(|v| legacy.contains(v));
            let Some(version) = requested.or_else(|| legacy.first().copied()) else {
                return Err(Error::value("no initialize-era MCP revision is accepted"));
            };
            let discover = match upstream_era {
                Some(Era::Modern {
                    discover: Some(d), ..
                }) => d.clone(),
                _ => Map::new(),
            };
            let mut result = Map::new();
            result.insert("protocolVersion".into(), json!(version));
            result.insert(
                "capabilities".into(),
                era::tools_only(discover.get("capabilities")),
            );
            result.insert(
                "serverInfo".into(),
                discover
                    .get("_meta")
                    .and_then(|m| m.get("io.modelcontextprotocol/serverInfo"))
                    .cloned()
                    .unwrap_or_else(
                        || json!({"name": "tokencrumb", "version": env!("CARGO_PKG_VERSION")}),
                    ),
            );
            if let Some(instructions) = discover.get("instructions") {
                result.insert("instructions".into(), instructions.clone());
            }
            Ok(Some(json_response(
                StatusCode::OK,
                &json!({"jsonrpc": "2.0", "id": id, "result": result}),
            )))
        }
        "notifications/initialized" => Ok(Some(empty(StatusCode::ACCEPTED))),
        "ping" => Ok(Some(json_response(
            StatusCode::OK,
            &json!({"jsonrpc": "2.0", "id": id, "result": {}}),
        ))),
        _ => Ok(None),
    }
}

/// The upstream's era: remembered, or detected once with a `server/discover` probe.
async fn ensure_era(
    state: &AppState,
    endpoint: &Option<String>,
    upstream: &SharedUpstream,
    policy: &Policy,
    principal: Option<crate::proxy::upstream::Principal>,
) -> Result<Era> {
    if let Some(found) = state.eras.lock().expect("eras lock").get(endpoint) {
        return Ok(found.clone());
    }
    let found = probe_era(upstream, policy, principal).await?;
    state
        .eras
        .lock()
        .expect("eras lock")
        .insert(endpoint.clone(), found.clone());
    Ok(found)
}

/// Probe with `server/discover`. A `DiscoverResult` or a recognized modern error means
/// modern; any other reply, or none in time, means legacy (and a stdio child is
/// restarted, so the `initialize` that follows meets a fresh process). A transport
/// failure is not an answer: it is returned, and nothing is remembered.
async fn probe_era(
    upstream: &SharedUpstream,
    policy: &Policy,
    principal: Option<crate::proxy::upstream::Principal>,
) -> Result<Era> {
    let Some(first) = policy
        .mcp
        .modern_versions()
        .first()
        .map(|v| (*v).to_owned())
    else {
        return Ok(Era::Legacy);
    };
    let mut version = first;
    for _ in 0..2 {
        let request = era::discover_request(&version);
        let headers = ForwardHeaders {
            incoming: era::modern_forward(
                &Headers::default(),
                request.as_object().expect("object"),
                None,
            ),
            principal: principal.clone(),
        };
        let outcome = tokio::time::timeout(
            PROBE_TIMEOUT,
            upstream.forward("POST", Bytes::from(dumps(&request).into_bytes()), &headers),
        )
        .await;
        let response = match outcome {
            Ok(Ok(response)) => response,
            Ok(Err(e)) if e.kind == ErrorKind::Io && e.message.starts_with("ConnectError") => {
                return Err(e);
            }
            _ => {
                upstream.close().await;
                return Ok(Era::Legacy);
            }
        };
        let first_message = response_messages(
            response.status,
            response.header("content-type"),
            &response.body,
        )
        .ok()
        .and_then(|(m, _)| m.into_iter().next());
        match era::classify_discover(first_message.as_ref()) {
            Some(Era::Modern {
                versions,
                discover: None,
            }) => match common_version(policy, &versions) {
                // Unsupported version: retry once with one both sides accept.
                Some(retry) if retry != version => version = retry,
                _ => {
                    return Ok(Era::Modern {
                        versions,
                        discover: None,
                    });
                }
            },
            Some(found) => return Ok(found),
            None => {
                upstream.close().await;
                return Ok(Era::Legacy);
            }
        }
    }
    Ok(Era::Modern {
        versions: Vec::new(),
        discover: None,
    })
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
    // Approved calls a previous process left in flight past their lease: settle them
    // before serving anything.
    sweep_receipts(&config.verifier, config.audit.as_deref())?;
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
        last_sweep: Mutex::new(Instant::now()),
        eras: Mutex::new(HashMap::new()),
        param_headers: Mutex::new(HashMap::new()),
        capacity_logged: Mutex::new(None),
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
