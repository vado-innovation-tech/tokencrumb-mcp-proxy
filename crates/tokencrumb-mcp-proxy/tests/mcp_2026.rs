//! MCP 2026-07-28 through the gateway: both agent eras against both upstream eras,
//! mirrored headers checked against the body, no sessions, private catalogs and
//! `resultType` on every gateway result.

mod common;

use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use bytes::Bytes;
use common::proxy::*;
use futures_util::future::BoxFuture;
use serde_json::{Value, json};
use tokencrumb_mcp_proxy::json::dumps;
use tokencrumb_mcp_proxy::policy::parse_policy;
use tokencrumb_mcp_proxy::proxy::upstream::{
    ForwardHeaders, SharedUpstream, Upstream, UpstreamResponse,
};

const MODERN: &str = "2026-07-28";

/// An upstream of either era, answering by method and recording what it received.
struct EraUpstream {
    modern: bool,
    /// Replaces the `tools/call` result (multi round-trip, task).
    call_result: Option<Value>,
    calls: Mutex<Vec<(Value, ForwardHeaders)>>,
}

impl EraUpstream {
    fn new(modern: bool) -> Arc<Self> {
        Self::with_call_result(modern, None)
    }

    fn with_call_result(modern: bool, call_result: Option<Value>) -> Arc<Self> {
        Arc::new(Self {
            modern,
            call_result,
            calls: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<(Value, ForwardHeaders)> {
        self.calls.lock().unwrap().clone()
    }

    /// Requests other than the era probe.
    fn requests(&self) -> Vec<(Value, ForwardHeaders)> {
        self.calls()
            .into_iter()
            .filter(|(b, _)| b["id"] != json!("tokencrumb-discover"))
            .collect()
    }

    fn reply(&self, message: &Value) -> (u16, Value) {
        let id = message["id"].clone();
        let method = message["method"].as_str().unwrap_or("");
        let declared = message.pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion");
        if self.modern && declared.is_none() {
            return (
                400,
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32020, "message": "Header mismatch"}}),
            );
        }
        if !self.modern && method == "server/discover" {
            return (
                400,
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32600, "message": "no session"}}),
            );
        }
        let tools = json!([
            {"name": "read_file", "inputSchema": {"type": "object", "properties": {
                "path": {"type": "string", "x-mcp-header": "Path"}}}},
            {"name": "fs_read", "inputSchema": {"type": "object", "properties": {
                "path": {"type": "string", "x-mcp-header": "Path"}}}},
            {"name": "secret_tool", "inputSchema": {"type": "object"}},
        ]);
        let mut result = match method {
            "server/discover" => json!({
                "supportedVersions": [MODERN],
                "capabilities": {"tools": {"listChanged": true}, "resources": {}, "prompts": {}},
                "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "modern-up", "version": "1"}},
                "ttlMs": 3_600_000, "cacheScope": "public",
            }),
            "initialize" => json!({
                "protocolVersion": message["params"]["protocolVersion"],
                "capabilities": {"tools": {}, "sampling": {}},
                "serverInfo": {"name": "legacy-up", "version": "1"},
            }),
            "tools/list" if self.modern => {
                json!({"tools": tools, "ttlMs": 3_600_000, "cacheScope": "public"})
            }
            "tools/list" => json!({"tools": tools}),
            "tools/call" => self
                .call_result
                .clone()
                .unwrap_or_else(|| json!({"content": [{"type": "text", "text": "ok"}]})),
            _ => json!({}),
        };
        if self.modern
            && let Some(map) = result.as_object_mut()
        {
            map.entry("resultType").or_insert(json!("complete"));
        }
        (200, json!({"jsonrpc": "2.0", "id": id, "result": result}))
    }
}

impl Upstream for EraUpstream {
    fn forward<'a>(
        &'a self,
        _method: &'a str,
        body: Bytes,
        headers: &'a ForwardHeaders,
    ) -> BoxFuture<'a, tokencrumb_mcp_proxy::Result<UpstreamResponse>> {
        let message: Value = serde_json::from_slice(&body).unwrap();
        self.calls
            .lock()
            .unwrap()
            .push((message.clone(), headers.clone()));
        let (status, reply) = if message.get("id").is_none() {
            (202, Value::Null)
        } else {
            self.reply(&message)
        };
        let body = if reply.is_null() {
            Bytes::new()
        } else {
            Bytes::from(dumps(&reply).into_bytes())
        };
        Box::pin(async move {
            Ok(UpstreamResponse {
                status,
                headers: vec![("content-type".into(), "application/json".into())],
                body,
            })
        })
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

fn app_for(w: &World, upstream: Arc<EraUpstream>) -> axum::Router {
    let mut policy = parse_policy(&json!({
        "deny_unknown_tools": true,
        "min_profile": "native",
        "tools": [
            {"name": "read_file", "operation": "read", "resource": {"from": "arguments.path"},
             "allow": {"resource_prefix": "/projects/acme/", "budget": 200}},
        ],
    }))
    .unwrap();
    policy.policy_digest = "test-policy-digest".into();
    w.proxy_with(
        vec![(None, upstream as SharedUpstream)],
        None,
        w.verifier(policy, None),
        true,
    )
}

/// The same policy, the granted tool served upstream as `fs_read`.
fn renaming_app(w: &World, upstream: Arc<EraUpstream>) -> axum::Router {
    let mut policy = parse_policy(&json!({
        "deny_unknown_tools": true,
        "min_profile": "native",
        "tools": [
            {"name": "read_file", "operation": "read", "upstream_tool": "fs_read",
             "resource": {"from": "arguments.path"},
             "allow": {"resource_prefix": "/projects/acme/", "budget": 200}},
        ],
    }))
    .unwrap();
    policy.policy_digest = "test-policy-digest".into();
    w.proxy_with(
        vec![(None, upstream as SharedUpstream)],
        None,
        w.verifier(policy, None),
        true,
    )
}

fn modern_body(id: i64, method: &str, params: Value) -> Value {
    let mut params = params.as_object().cloned().unwrap_or_default();
    params.insert(
        "_meta".into(),
        json!({
            "io.modelcontextprotocol/protocolVersion": MODERN,
            "io.modelcontextprotocol/clientCapabilities": {"sampling": {}, "elicitation": {}},
            "io.modelcontextprotocol/clientInfo": {"name": "agent", "version": "1"},
        }),
    );
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

fn call_params(path: &str) -> Value {
    json!({"name": "read_file", "arguments": {"path": path}})
}

async fn modern_call(app: &axum::Router, token: &str, path: &str, extra: &[(&str, &str)]) -> Reply {
    let auth = bearer(token);
    let mut headers = vec![
        ("mcp-protocol-version", MODERN),
        ("mcp-method", "tools/call"),
        ("mcp-name", "read_file"),
        ("authorization", auth.as_str()),
    ];
    headers.extend_from_slice(extra);
    post(
        app,
        modern_body(1, "tools/call", call_params(path)),
        &headers,
    )
    .await
}

async fn modern_list(app: &axum::Router) -> Reply {
    post(
        app,
        modern_body(2, "tools/list", json!({})),
        &[
            ("mcp-protocol-version", MODERN),
            ("mcp-method", "tools/list"),
        ],
    )
    .await
}

fn last_method(entries: &[Value]) -> Value {
    entries.last().unwrap()["method"].clone()
}

// -- the four combinations ------------------------------------------------------------

#[tokio::test]
async fn modern_agent_to_modern_upstream() {
    let w = World::new();
    let upstream = EraUpstream::new(true);
    let app = app_for(&w, upstream.clone());
    let reply = modern_call(
        &app,
        &w.native_token(),
        "/projects/acme/a.txt",
        &[("mcp-param-path", "/projects/acme/a.txt")],
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(reply.json()["result"]["resultType"], json!("complete"));
    let (sent, headers) = upstream.requests().pop().unwrap();
    // Client capabilities are controlled per request, as `initialize` is rewritten.
    assert_eq!(
        sent["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"],
        json!({})
    );
    assert_eq!(
        sent["params"]["_meta"]["io.modelcontextprotocol/clientInfo"]["name"],
        json!("agent")
    );
    assert_eq!(headers.incoming.get("mcp-protocol-version"), Some(MODERN));
    assert_eq!(headers.incoming.get("mcp-method"), Some("tools/call"));
    assert_eq!(headers.incoming.get("mcp-name"), Some("read_file"));
    // The probe ran once and is remembered.
    let probes = upstream.calls().len() - upstream.requests().len();
    assert_eq!(probes, 1);
    modern_call(&app, &w.native_token(), "/projects/acme/b.txt", &[]).await;
    assert_eq!(upstream.calls().len() - upstream.requests().len(), 1);
}

#[tokio::test]
async fn legacy_agent_to_modern_upstream_is_translated() {
    let w = World::new();
    let upstream = EraUpstream::new(true);
    let app = app_for(&w, upstream.clone());
    let init = post(
        &app,
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2025-06-18", "capabilities": {"sampling": {}},
                          "clientInfo": {"name": "wrap", "version": "1"}}}),
        &[],
    )
    .await;
    assert_eq!(init.status, StatusCode::OK, "{}", init.text());
    let result = &init.json()["result"];
    assert_eq!(result["protocolVersion"], json!("2025-06-18"));
    assert_eq!(result["capabilities"], json!({"tools": {}}));
    assert_eq!(result["serverInfo"]["name"], json!("modern-up"));
    assert!(init.headers.get("mcp-session-id").is_none());
    let notified = post(
        &app,
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        &[("mcp-protocol-version", "2025-06-18")],
    )
    .await;
    assert_eq!(notified.status, StatusCode::ACCEPTED);
    let call = post(
        &app,
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": call_params("/projects/acme/a.txt")}),
        &[
            ("mcp-protocol-version", "2025-06-18"),
            ("mcp-param-path", "/elsewhere"),
            ("authorization", &bearer(&w.native_token())),
        ],
    )
    .await;
    assert_eq!(call.status, StatusCode::OK, "{}", call.text());
    assert_eq!(call.json()["result"]["content"][0]["text"], json!("ok"));
    let (sent, headers) = upstream.requests().pop().unwrap();
    assert_eq!(
        sent["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
        json!(MODERN)
    );
    assert_eq!(headers.incoming.get("mcp-protocol-version"), Some(MODERN));
    assert_eq!(headers.incoming.get("mcp-name"), Some("read_file"));
    assert!(
        headers.incoming.get("mcp-param-path").is_none(),
        "an unchecked legacy mirror is not passed on"
    );
}

#[tokio::test]
async fn modern_agent_to_legacy_upstream_is_told_to_use_initialize() {
    let w = World::new();
    let upstream = EraUpstream::new(false);
    let app = app_for(&w, upstream.clone());
    let reply = modern_call(&app, &w.native_token(), "/projects/acme/a.txt", &[]).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    let error = &reply.json()["error"];
    assert_eq!(error["code"], json!(-32022));
    assert_eq!(
        error["data"]["supported"],
        json!(["2025-06-18", "2025-11-25"])
    );
    assert!(
        upstream.requests().is_empty(),
        "nothing but the probe reached it"
    );
    // The dual-era agent falls back to `initialize`, and the legacy path works.
    let init = post(
        &app,
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2025-11-25", "capabilities": {}}}),
        &[],
    )
    .await;
    assert_eq!(
        init.json()["result"]["protocolVersion"],
        json!("2025-11-25")
    );
}

#[tokio::test]
async fn legacy_agent_to_legacy_upstream_is_unchanged() {
    let w = World::new();
    let upstream = EraUpstream::new(false);
    let app = app_for(&w, upstream.clone());
    let call = post(
        &app,
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": call_params("/projects/acme/a.txt")}),
        &[
            ("mcp-protocol-version", "2025-06-18"),
            ("mcp-session-id", "s-1"),
            ("authorization", &bearer(&w.native_token())),
        ],
    )
    .await;
    // An unknown session is refused as before; no probe is ever sent for a legacy agent.
    assert_eq!(call.status, StatusCode::NOT_FOUND);
    let call = post(
        &app,
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": call_params("/projects/acme/a.txt")}),
        &[
            ("mcp-protocol-version", "2025-06-18"),
            ("mcp-name", "spoofed"),
            ("authorization", &bearer(&w.native_token())),
        ],
    )
    .await;
    assert_eq!(call.status, StatusCode::OK);
    let calls = upstream.calls();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].0["params"].get("_meta").is_none());
    assert!(
        calls[0].1.incoming.get("mcp-name").is_none(),
        "no 2026 mirror to a legacy upstream"
    );
}

// -- headers and body ----------------------------------------------------------------

#[tokio::test]
async fn modern_request_without_protocol_version_header_is_refused() {
    let w = World::new();
    let upstream = EraUpstream::new(true);
    let app = app_for(&w, upstream.clone());
    let reply = post(
        &app,
        modern_body(1, "tools/call", call_params("/projects/acme/a.txt")),
        &[
            ("mcp-method", "tools/call"),
            ("mcp-name", "read_file"),
            ("authorization", &bearer(&w.native_token())),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.json()["error"]["code"], json!(-32020));
    assert!(upstream.calls().is_empty());
    assert_eq!(last_method(&w.audit_entries()), json!("<header-mismatch>"));
}

#[tokio::test]
async fn header_contradicting_body_is_refused_before_the_decision() {
    let w = World::new();
    let upstream = EraUpstream::new(true);
    let app = app_for(&w, upstream.clone());
    for extra in [
        vec![("mcp-name", "other_tool")],
        vec![("mcp-method", "tools/list")],
        vec![("mcp-protocol-version", "2025-06-18")],
    ] {
        let auth = bearer(&w.native_token());
        let mut headers = vec![
            ("mcp-protocol-version", MODERN),
            ("mcp-method", "tools/call"),
            ("mcp-name", "read_file"),
            ("authorization", auth.as_str()),
        ];
        // Later duplicates lose (first occurrence wins): put the contradiction first.
        headers.retain(|(k, _)| !extra.iter().any(|(e, _)| e == k));
        headers.splice(0..0, extra.clone());
        let reply = post(
            &app,
            modern_body(1, "tools/call", call_params("/projects/acme/a.txt")),
            &headers,
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{extra:?}");
    }
    assert!(upstream.calls().is_empty());
    let entries = w.audit_entries();
    assert_eq!(entries.len(), 3);
    assert!(
        entries
            .iter()
            .all(|e| e["method"] == json!("<header-mismatch>") && e["decision"] == json!("DENY"))
    );
    assert!(
        entries.iter().all(|e| e["tool"].is_null()),
        "no authorization decision ran"
    );
}

#[tokio::test]
async fn param_headers_are_checked_against_the_learned_schema() {
    let w = World::new();
    let upstream = EraUpstream::new(true);
    let app = app_for(&w, upstream.clone());
    assert_eq!(modern_list(&app).await.status, StatusCode::OK);
    // A value in the body with no header, or a header naming another value: refused.
    let missing = modern_call(&app, &w.native_token(), "/projects/acme/a.txt", &[]).await;
    assert_eq!(missing.status, StatusCode::BAD_REQUEST);
    let other = modern_call(
        &app,
        &w.native_token(),
        "/projects/acme/a.txt",
        &[("mcp-param-path", "/projects/acme/other.txt")],
    )
    .await;
    assert_eq!(other.status, StatusCode::BAD_REQUEST);
    // Base64-encoded values are decoded before the comparison.
    let path = "/projects/acme/é.txt";
    let encoded = format!(
        "=?base64?{}?=",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, path)
    );
    let ok = modern_call(
        &app,
        &w.native_token(),
        path,
        &[("mcp-param-path", encoded.as_str())],
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text());
    let (_, headers) = upstream.requests().pop().unwrap();
    assert_eq!(
        headers.incoming.get("mcp-param-path"),
        Some(encoded.as_str())
    );
}

#[tokio::test]
async fn renamed_tool_is_forwarded_with_a_recomputed_mcp_name() {
    let w = World::new();
    let upstream = EraUpstream::new(true);
    let app = renaming_app(&w, upstream.clone());
    let reply = modern_call(&app, &w.native_token(), "/projects/acme/a.txt", &[]).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let (sent, headers) = upstream.requests().pop().unwrap();
    assert_eq!(sent["params"]["name"], json!("fs_read"));
    assert_eq!(headers.incoming.get("mcp-name"), Some("fs_read"));
    assert_eq!(headers.incoming.get("mcp-method"), Some("tools/call"));
}

#[tokio::test]
async fn session_id_is_ignored_in_modern_mode() {
    let w = World::new();
    let upstream = EraUpstream::new(true);
    let app = app_for(&w, upstream.clone());
    let reply = modern_call(
        &app,
        &w.native_token(),
        "/projects/acme/a.txt",
        &[("mcp-session-id", "never-issued"), ("last-event-id", "7")],
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let (_, headers) = upstream.requests().pop().unwrap();
    assert!(headers.incoming.get("mcp-session-id").is_none());
    assert!(headers.incoming.get("last-event-id").is_none());
    assert!(reply.headers.get("mcp-session-id").is_none());
}

#[tokio::test]
async fn unsupported_protocol_version_is_refused_and_audited() {
    let w = World::new();
    let upstream = EraUpstream::new(true);
    let app = app_for(&w, upstream.clone());
    let reply = post(
        &app,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        &[("mcp-protocol-version", "2099-01-01")],
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.json()["error"]["code"], json!(-32022));
    assert_eq!(
        reply.json()["error"]["data"]["supported"],
        json!(["2025-06-18", "2025-11-25", MODERN])
    );
    assert_eq!(last_method(&w.audit_entries()), json!("<protocol-version>"));
}

// -- results ---------------------------------------------------------------------------

#[tokio::test]
async fn gateway_refusal_carries_result_type() {
    let w = World::new();
    let upstream = EraUpstream::new(true);
    let app = app_for(&w, upstream.clone());
    let reply = modern_call(&app, &w.native_token(), "/etc/passwd", &[]).await;
    assert_eq!(reply.status, StatusCode::OK);
    let result = &reply.json()["result"];
    assert_eq!(result["isError"], json!(true));
    assert_eq!(result["resultType"], json!("complete"));
    assert!(upstream.requests().is_empty());
}

#[tokio::test]
async fn filtered_tools_list_is_private_and_short_lived() {
    let w = World::new();
    let upstream = EraUpstream::new(true);
    let app = app_for(&w, upstream.clone());
    let reply = modern_list(&app).await;
    let result = &reply.json()["result"];
    let names: Vec<&str> = result["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["read_file"]);
    assert_eq!(result["cacheScope"], json!("private"));
    assert!(result["ttlMs"].as_u64().unwrap() <= 30_000);
    assert_eq!(result["resultType"], json!("complete"));
}

#[tokio::test]
async fn server_discover_is_reduced_to_tools() {
    let w = World::new();
    let upstream = EraUpstream::new(true);
    let app = app_for(&w, upstream.clone());
    let reply = post(
        &app,
        modern_body(5, "server/discover", json!({})),
        &[
            ("mcp-protocol-version", MODERN),
            ("mcp-method", "server/discover"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let result = &reply.json()["result"];
    assert_eq!(result["capabilities"], json!({"tools": {}}));
    assert_eq!(
        result["supportedVersions"],
        json!([MODERN, "2025-06-18", "2025-11-25"])
    );
    assert_eq!(result["cacheScope"], json!("private"));
    assert_eq!(result["resultType"], json!("complete"));
}

#[tokio::test]
async fn input_required_and_tasks_are_refused_by_default() {
    let w = World::new();
    let upstream = EraUpstream::with_call_result(
        true,
        Some(json!({"resultType": "input_required", "inputRequests": {},
                    "requestState": "opaque"})),
    );
    let app = app_for(&w, upstream.clone());
    let reply = modern_call(&app, &w.native_token(), "/projects/acme/a.txt", &[]).await;
    assert_eq!(reply.json()["error"]["code"], json!(-31001));
    assert!(reply.json().get("result").is_none());
    // A retry carrying input responses, or a task-augmented call, never leaves.
    upstream.calls.lock().unwrap().clear();
    let auth = bearer(&w.native_token());
    for extra in [
        json!({"inputResponses": {}, "requestState": "x"}),
        json!({"task": {"ttl": 1}}),
    ] {
        let mut params = call_params("/projects/acme/a.txt");
        params
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let reply = post(
            &app,
            modern_body(1, "tools/call", params),
            &[
                ("mcp-protocol-version", MODERN),
                ("mcp-method", "tools/call"),
                ("mcp-name", "read_file"),
                ("authorization", &auth),
            ],
        )
        .await;
        assert_eq!(reply.json()["error"]["code"], json!(-31001));
    }
    assert!(upstream.calls().is_empty());
}

#[tokio::test]
async fn legacy_methods_are_refused_in_modern_mode() {
    let w = World::new();
    let upstream = EraUpstream::new(true);
    let app = app_for(&w, upstream.clone());
    let reply = post(
        &app,
        modern_body(1, "ping", json!({})),
        &[("mcp-protocol-version", MODERN), ("mcp-method", "ping")],
    )
    .await;
    assert_eq!(reply.json()["error"]["code"], json!(-32601));
    assert!(upstream.calls().is_empty());
}

#[tokio::test]
async fn policy_accepts_a_list_or_a_single_revision() {
    let single = parse_policy(&json!({"mcp": {"spec_version": "2025-06-18"}})).unwrap();
    assert_eq!(single.mcp.spec_versions, ["2025-06-18"]);
    let listed = parse_policy(&json!({"mcp": {"spec_version": [MODERN, "2025-06-18"]}})).unwrap();
    assert_eq!(listed.mcp.spec_version, MODERN);
    assert_eq!(listed.mcp.modern_versions(), [MODERN]);
    for bad in [json!([]), json!(["2024-11-05"]), json!([MODERN, MODERN])] {
        assert!(parse_policy(&json!({"mcp": {"spec_version": bad}})).is_err());
    }
    // Pinned to the legacy revision, a modern request is refused outright.
    let w = World::new();
    let upstream = EraUpstream::new(true);
    let mut policy = parse_policy(&json!({"mcp": {"spec_version": "2025-06-18"}})).unwrap();
    policy.policy_digest = "d".into();
    let app = w.proxy_with(
        vec![(None, upstream.clone() as SharedUpstream)],
        None,
        w.verifier(policy, None),
        true,
    );
    assert_eq!(modern_list(&app).await.status, StatusCode::BAD_REQUEST);
    assert!(upstream.calls().is_empty());
}

#[test]
fn reserved_mirror_headers_cannot_be_configured_credentials() {
    use tokencrumb_mcp_proxy::proxy::upstream::HttpUpstream;
    for name in ["Mcp-Method", "mcp-name", "Mcp-Param-Region"] {
        assert!(
            HttpUpstream::new("http://127.0.0.1:1/mcp", vec![(name.into(), "x".into())]).is_err(),
            "{name}"
        );
    }
}

// -- stdio: the era probe is `server/discover` -------------------------------------------

fn stdio_server(modern: bool) -> SharedUpstream {
    let discover = if modern {
        r#"{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{}}}}"#
    } else {
        r#"{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"Method not found"}}"#
    };
    let script = format!(
        r#"while read line; do
id=$(printf '%s' "$line" | sed -E 's/.*"id": *("[^"]*"|[0-9]+).*/\1/')
method=$(printf '%s' "$line" | sed -E 's/.*"method": *"([^"]*)".*/\1/')
case "$method" in
  server/discover) printf '{discover}\n' "$id" ;;
  tools/list) printf '{{"jsonrpc":"2.0","id":%s,"result":{{"tools":[{{"name":"read_file"}}]}}}}\n' "$id" ;;
  *) printf '{{"jsonrpc":"2.0","id":%s,"result":{{}}}}\n' "$id" ;;
esac
done"#
    );
    Arc::new(
        tokencrumb_mcp_proxy::proxy::upstream::StdioUpstream::new(vec![
            "/bin/sh".into(),
            "-c".into(),
            script,
        ])
        .unwrap(),
    )
}

fn stdio_app(w: &World, upstream: SharedUpstream) -> axum::Router {
    let mut policy = parse_policy(&json!({
        "min_profile": "native",
        "tools": [{"name": "read_file", "operation": "read",
                   "resource": {"from": "arguments.path"},
                   "allow": {"resource_prefix": "/projects/acme/"}}],
    }))
    .unwrap();
    policy.policy_digest = "d".into();
    w.proxy_with(vec![(None, upstream)], None, w.verifier(policy, None), true)
}

#[tokio::test]
async fn stdio_upstream_era_is_probed_with_server_discover() {
    let w = World::new();
    let app = stdio_app(&w, stdio_server(true));
    let reply = modern_list(&app).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(reply.json()["result"]["cacheScope"], json!("private"));

    let w = World::new();
    let app = stdio_app(&w, stdio_server(false));
    let reply = modern_list(&app).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.json()["error"]["code"], json!(-32022));
    // The legacy child is restarted and serves `initialize` as before.
    let init = post(
        &app,
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2025-06-18", "capabilities": {}}}),
        &[],
    )
    .await;
    assert_eq!(init.status, StatusCode::OK, "{}", init.text());
}
