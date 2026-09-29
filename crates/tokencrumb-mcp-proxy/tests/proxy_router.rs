//! Router-level tests: what reaches the upstream, and what the client learns.
//!
//! These are the tests that were missing in 0.1.0. Every one of them asserts on the
//! HTTP boundary, not on the verifier.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tokencrumb_mcp_proxy::proxy::messages::{INVALID_REQUEST, METHOD_NOT_FOUND};
use common::proxy::{FakeUpstream, World, bearer, post, send};
use serde_json::{Value, json};

fn call() -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "execute_sql", "arguments": {"schema": "analytics"}}})
}

// -- The bypass: a tools/call wrapped in a JSON-RPC batch ----------------------------

/// A batch body must not be unpacked, relayed, or silently accepted. In 0.1.0 the
/// guard was an object check, so a one-element array skipped verification entirely.
#[tokio::test]
async fn batch_never_reaches_upstream() {
    let w = World::new();
    let upstream = FakeUpstream::default_json();
    let app = w.proxy(upstream.clone(), None);
    let reply = post(&app, json!([call()]), &[]).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.json()["error"]["code"], json!(INVALID_REQUEST));
    assert!(
        !upstream.reached(),
        "batch was forwarded upstream without verification"
    );
    let entries = w.audit_entries();
    assert_eq!(
        entries
            .iter()
            .map(|e| e["decision"].clone())
            .collect::<Vec<_>>(),
        vec![json!("DENY")]
    );
    assert_eq!(entries[0]["method"], json!("<batch>"));
}

#[tokio::test]
async fn batch_refusal_is_audited_with_a_correlation_id() {
    let w = World::new();
    let app = w.proxy(FakeUpstream::default_json(), None);
    let reply = post(&app, json!([call(), call()]), &[]).await;
    let cid = reply.json()["error"]["data"]["correlation_id"].clone();
    assert_eq!(w.audit_entries()[0]["correlation_id"], cid);
    assert_eq!(w.audit_entries()[0]["detail"], json!({"messages": 2}));
}

#[tokio::test]
async fn unauthenticated_call_is_denied_and_not_forwarded() {
    let w = World::new();
    let upstream = FakeUpstream::default_json();
    let app = w.proxy(upstream.clone(), None);
    let reply = post(&app, call(), &[]).await;
    assert_eq!(reply.json()["result"]["isError"], json!(true));
    assert!(!upstream.reached());
}

// -- Method allowlist ----------------------------------------------------------------

#[tokio::test]
async fn allowlisted_methods_are_relayed() {
    let w = World::new();
    let upstream = FakeUpstream::default_json();
    let app = w.proxy(upstream.clone(), None);
    for method in ["initialize", "ping", "notifications/initialized"] {
        upstream.clear();
        let reply = post(
            &app,
            json!({"jsonrpc": "2.0", "id": 1, "method": method}),
            &[],
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{method}");
        assert!(upstream.reached(), "{method} should be relayed");
    }
}

/// resources/*, prompts/*, sampling and friends were relayed with no token at all.
#[tokio::test]
async fn ungated_families_are_denied() {
    let w = World::new();
    let upstream = FakeUpstream::default_json();
    let app = w.proxy(upstream.clone(), None);
    let denied = [
        "resources/read",
        "resources/list",
        "prompts/get",
        "sampling/createMessage",
        "elicitation/create",
        "completion/complete",
        "logging/setLevel",
        "totally/unknown",
    ];
    for method in denied {
        let reply = post(
            &app,
            json!({"jsonrpc": "2.0", "id": 7, "method": method}),
            &[],
        )
        .await;
        assert_eq!(
            reply.json()["error"]["code"],
            json!(METHOD_NOT_FOUND),
            "{method}"
        );
    }
    assert!(!upstream.reached());
    let entries = w.audit_entries();
    let methods: std::collections::HashSet<String> = entries
        .iter()
        .map(|e| e["method"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(methods, denied.iter().map(|m| m.to_string()).collect());
    assert!(entries.iter().all(|e| e["decision"] == json!("DENY")));
    assert_eq!(
        entries[0]["reason"],
        json!("method 'resources/read' is not in the MCP allowlist")
    );
}

/// A notification has no protocol response — the audit entry is the trace.
#[tokio::test]
async fn denied_notification_gets_no_body_but_is_audited() {
    let w = World::new();
    let upstream = FakeUpstream::default_json();
    let app = w.proxy(upstream.clone(), None);
    let reply = post(
        &app,
        json!({"jsonrpc": "2.0", "method": "notifications/message"}),
        &[],
    )
    .await;
    assert_eq!(reply.status, StatusCode::ACCEPTED);
    assert!(reply.body.is_empty());
    assert!(!upstream.reached());
    assert_eq!(w.audit_entries()[0]["decision"], json!("DENY"));
}

/// The server->client channel is closed, so a reply to it cannot be legitimate.
#[tokio::test]
async fn response_without_method_is_refused() {
    let w = World::new();
    let upstream = FakeUpstream::default_json();
    let app = w.proxy(upstream.clone(), None);
    let reply = post(
        &app,
        json!({"jsonrpc": "2.0", "id": 3, "result": {"anything": true}}),
        &[],
    )
    .await;
    assert_eq!(reply.json()["error"]["code"], json!(INVALID_REQUEST));
    assert!(!upstream.reached());
}

#[tokio::test]
async fn server_to_client_channel_is_closed() {
    let w = World::new();
    let upstream = FakeUpstream::default_json();
    let app = w.proxy(upstream.clone(), None);
    let reply = send(&app, Request::get("/mcp").body(Body::empty()).unwrap()).await;
    assert_eq!(reply.status, StatusCode::METHOD_NOT_ALLOWED);
    assert!(!upstream.reached());
    assert_eq!(w.audit_entries()[0]["method"], json!("GET /mcp"));
}

// -- tools/list filtering (model A — by local catalog) -------------------------------

fn tools_response(names: &[&str]) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": names.iter().map(|n| json!({"name": n})).collect::<Vec<_>>()}})
}

#[tokio::test]
async fn tools_list_is_filtered_by_local_catalog() {
    let w = World::new();
    let upstream = FakeUpstream::new(
        Some(tools_response(&[
            "read_file",
            "execute_sql",
            "leaky_search",
        ])),
        "application/json",
    );
    let app = w.proxy(upstream, None);
    let reply = post(
        &app,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        &[],
    )
    .await;
    let names: Vec<Value> = reply.json()["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].clone())
        .collect();
    assert_eq!(names, vec![json!("read_file"), json!("execute_sql")]);
    assert!(!reply.text().contains("leaky_search"));
}

#[tokio::test]
async fn tools_list_filtered_over_sse() {
    let w = World::new();
    let upstream = FakeUpstream::new(
        Some(tools_response(&["read_file", "leaky_search"])),
        "text/event-stream",
    );
    let app = w.proxy(upstream, None);
    let reply = post(
        &app,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        &[],
    )
    .await;
    assert!(!reply.text().contains("leaky_search"));
    assert_eq!(
        reply.headers["content-type"],
        "text/event-stream; charset=utf-8"
    );
    let text = reply.text();
    let data = text.lines().find(|l| l.starts_with("data:")).unwrap();
    let payload: Value = serde_json::from_str(data["data:".len()..].trim()).unwrap();
    assert_eq!(payload["result"]["tools"], json!([{"name": "read_file"}]));
}

#[tokio::test]
async fn tools_list_masking_is_audited() {
    let w = World::new();
    let upstream = FakeUpstream::new(
        Some(tools_response(&["read_file", "leaky_search"])),
        "application/json",
    );
    let app = w.proxy(upstream, None);
    post(
        &app,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        &[],
    )
    .await;
    let entries = w.audit_entries();
    let entry = entries.last().unwrap();
    assert_eq!(entry["method"], json!("tools/list"));
    assert_eq!(entry["detail"], json!({"tools_masked": 1}));
    assert_eq!(entries[0]["decision"], json!("RELAY"));
}

// -- Generic denial — a refusal must not become an oracle ----------------------------

/// The client gets an opaque id; the reason stays in the audit log.
#[tokio::test]
async fn denial_leaks_nothing_to_the_client() {
    let w = World::new();
    let app = w.proxy(FakeUpstream::default_json(), None);
    let payload = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": "execute_sql", "arguments": {"schema": "secret-schema"}}});
    let token = bearer(&w.native_token());
    let reply = post(&app, payload, &[("authorization", &token)]).await;
    let body = reply.text();
    for leak in [
        "secret-schema",
        "profile",
        "policy",
        "hardened",
        "budget",
        "Traceback",
        "resource",
        "downgrade",
        "agent-1",
    ] {
        assert!(!body.contains(leak), "denial leaked {leak:?} to the client");
    }
    let entry = &w.audit_entries()[0];
    assert!(body.contains(entry["correlation_id"].as_str().unwrap()));
    assert!(
        !entry["reason"].as_str().unwrap().is_empty(),
        "the real reason IS recorded"
    );
}

/// warn-only used to log DENY and forward anyway, with nothing to tell them apart.
#[tokio::test]
async fn warn_only_marks_the_entry_as_not_enforced() {
    let w = World::new();
    let upstream = FakeUpstream::default_json();
    let app = w.proxy(upstream.clone(), Some("warn-only"));
    post(&app, call(), &[]).await;
    let entry = &w.audit_entries()[0];
    assert_eq!(entry["decision"], json!("DENY"));
    assert_eq!(entry["enforced"], json!(false));
    assert!(upstream.reached(), "warn-only forwards the call");
}

#[tokio::test]
async fn enforced_is_true_when_blocking() {
    let w = World::new();
    let upstream = FakeUpstream::default_json();
    let app = w.proxy(upstream.clone(), Some("enforce"));
    post(&app, call(), &[]).await;
    assert_eq!(w.audit_entries()[0]["enforced"], json!(true));
    assert!(!upstream.reached());
}

// -- Audit metadata ------------------------------------------------------------------

#[tokio::test]
async fn entries_carry_gateway_policy_digest_and_sequence() {
    let w = World::new();
    let app = w.proxy(FakeUpstream::default_json(), None);
    post(
        &app,
        json!({"jsonrpc": "2.0", "id": 1, "method": "resources/read"}),
        &[],
    )
    .await;
    post(
        &app,
        json!({"jsonrpc": "2.0", "id": 2, "method": "prompts/get"}),
        &[],
    )
    .await;
    let entries = w.audit_entries();
    assert_eq!(
        entries.iter().map(|e| e["seq"].clone()).collect::<Vec<_>>(),
        vec![json!(0), json!(1)]
    );
    assert!(entries.iter().all(|e| e["gateway_id"] == json!("gw-test")));
    assert!(
        entries
            .iter()
            .all(|e| e["policy_digest"] == json!("test-policy-digest"))
    );
    assert_ne!(
        entries[0]["correlation_id"], entries[1]["correlation_id"],
        "unique per refusal"
    );
}

// -- The enforced path end to end ----------------------------------------------------

#[tokio::test]
async fn allowed_call_is_forwarded_with_its_audit_identity() {
    let w = World::new();
    let upstream = FakeUpstream::default_json();
    let app = w.proxy(upstream.clone(), None);
    let token = w.native_token();
    let payload = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": "read_file", "arguments": {"path": "/projets/acme/q3.md"}}});
    let reply = post(&app, payload, &[("authorization", &bearer(&token))]).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["result"], json!({"ok": true}));
    assert!(upstream.reached());
    let entry = &w.audit_entries()[0];
    assert_eq!(entry["decision"], json!("ALLOW"));
    assert_eq!(entry["reason"], Value::Null);
    assert_eq!(entry["resource"], json!("/projets/acme/q3.md"));
    assert_eq!(entry["remaining_budget"], json!(199));
    assert_eq!(
        entry["identity"]["mandate_id"],
        json!(tokencrumb_mcp_proxy::biscuit_ops::capability_key(&token).unwrap())
    );
    assert!(
        entry.get("detail").is_none(),
        "an unnamed endpoint records no detail"
    );
}

#[tokio::test]
async fn protocol_version_and_origin_are_checked_before_anything() {
    let w = World::new();
    let upstream = FakeUpstream::default_json();
    let app = w.proxy(upstream.clone(), None);
    let ping = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
    let reply = post(
        &app,
        ping.clone(),
        &[("mcp-protocol-version", "2024-11-05")],
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    let reply = post(&app, ping, &[("origin", "https://evil.example")]).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert!(!upstream.reached());
    assert_eq!(w.audit_entries()[0]["method"], json!("<origin>"));
}

#[tokio::test]
async fn malformed_bodies_are_refused_and_audited() {
    let w = World::new();
    let upstream = FakeUpstream::default_json();
    let app = w.proxy(upstream.clone(), None);
    let reply = post(&app, b"{not json".to_vec(), &[]).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        reply.json(),
        json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "Parse error"}})
    );
    let reply = post(
        &app,
        br#"{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}"#.to_vec(),
        &[],
    )
    .await;
    assert_eq!(
        reply.status,
        StatusCode::BAD_REQUEST,
        "duplicate keys are a parse error"
    );
    let reply = post(
        &app,
        json!({"jsonrpc": "2.0", "id": null, "method": "ping"}),
        &[],
    )
    .await;
    assert_eq!(
        reply.status,
        StatusCode::BAD_REQUEST,
        "a null id is not a JSON-RPC id"
    );
    let reply = post(
        &app,
        json!({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": []}),
        &[],
    )
    .await;
    assert_eq!(reply.json()["error"]["message"], json!("invalid params"));
    let reply = post(&app, vec![b' '; 1024 * 1024 + 1], &[]).await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(!upstream.reached());
    let methods: Vec<Value> = w
        .audit_entries()
        .iter()
        .map(|e| e["method"].clone())
        .collect();
    assert_eq!(
        methods,
        vec![
            json!("<parse>"),
            json!("<parse>"),
            json!("<malformed>"),
            json!("ping"),
            json!("<oversize>")
        ]
    );
}

#[tokio::test]
async fn initialize_is_pinned_and_capabilities_reduced() {
    let w = World::new();
    let upstream = FakeUpstream::new(
        Some(json!({"jsonrpc": "2.0", "id": 1, "result": {
        "protocolVersion": "2025-06-18",
        "capabilities": {"tools": {"listChanged": true}, "resources": {}, "prompts": {}},
        "serverInfo": {"name": "x", "version": "1"}}})),
        "application/json",
    );
    let app = w.proxy(upstream.clone(), None);
    let reply = post(&app, json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                  "params": {"protocolVersion": "2024-01-01", "capabilities": {"sampling": {}}}}), &[]).await;
    assert_eq!(reply.json()["result"]["capabilities"], json!({"tools": {}}));
    let sent = &upstream.bodies()[0];
    assert_eq!(sent["params"]["protocolVersion"], json!("2025-06-18"));
    assert_eq!(sent["params"]["capabilities"], json!({}));
}

#[tokio::test]
async fn unpaired_upstream_reply_is_an_infrastructure_refusal() {
    let w = World::new();
    let upstream = FakeUpstream::new(
        Some(json!({"jsonrpc": "2.0", "id": 99, "result": {}})),
        "application/json",
    );
    let app = w.proxy(upstream, None);
    let reply = post(
        &app,
        json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
        &[],
    )
    .await;
    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        reply.json()["error"]["message"],
        json!("request unavailable")
    );
    let entries = w.audit_entries();
    let last = entries.last().unwrap();
    assert_eq!(last["method"], json!("<infrastructure>"));
    assert_eq!(
        last["reason"],
        json!("ValueError: request could not be completed")
    );
}
