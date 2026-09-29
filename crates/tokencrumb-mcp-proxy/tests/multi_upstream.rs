//! One process, one endpoint per upstream (ADR-0006).
//!
//! What the shape has to buy, and what it must not cost:
//!   - a client config that still lists one entry per server (ADR-0005);
//!   - a budget and an audit chain shared across upstreams — the reason for one process;
//!   - sessions, catalogs and namespaces that stay 1:1 per endpoint.
//!
//! Ported from `tests/test_multi_upstream.py`.

mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use tokencrumb_mcp_proxy::ErrorKind;
use tokencrumb_mcp_proxy::policy::{Policy, parse_policy};
use tokencrumb_mcp_proxy::proxy::upstream::SharedUpstream;
use common::proxy::{
    FakeUpstream, Reply, TEST_AUDIENCE, World, bearer, build_token, date_term, in_seconds, options,
    post_to, str_term,
};
use serde_json::{Value, json};

const TOOLS: [(&str, &str); 2] = [("catalog", "search_objects"), ("inventory", "get_stock")];

fn policy(budget_total: Option<i64>) -> Policy {
    let mut raw = json!({
        "deny_unknown_tools": true,
        "upstreams": {
            "catalog": "http://catalog:8080/mcp",
            "inventory": "http://inventory:8080/mcp",
        },
        "tools": [
            {"name": "search_objects", "operation": "read", "upstream": "catalog",
             "allow": {"budget": 50}},
            {"name": "get_stock", "operation": "read", "upstream": "inventory",
             "allow": {"budget": 50}},
        ],
    });
    if let Some(total) = budget_total {
        raw["budget_total"] = json!(total);
    }
    let mut p = parse_policy(&raw).unwrap();
    p.policy_digest = "test-policy-digest".into();
    p
}

/// One mandate, both tools — the point of a shared control plane.
fn mandate(w: &World) -> String {
    build_token(
        &w.authority.private_str,
        r#"agent_id("agent-1"); required_profile("native"); audience({aud});
           right("search_objects", "read"); right("get_stock", "read");
           budget_cap(1000); expires_at({exp}); check if time($t), $t < {exp};"#,
        &[
            ("aud", str_term(TEST_AUDIENCE)),
            ("exp", date_term(in_seconds(3600))),
        ],
    )
}

/// A two-endpoint proxy sharing one audit chain, and its upstreams by name.
struct Stack {
    app: axum::Router,
    ups: Vec<(String, Arc<FakeUpstream>)>,
}

impl Stack {
    fn up(&self, name: &str) -> &Arc<FakeUpstream> {
        &self.ups.iter().find(|(n, _)| n == name).unwrap().1
    }
}

fn stack_with(w: &World, policy: Policy, payload: Option<Value>, audit: bool) -> Stack {
    let ups: Vec<(String, Arc<FakeUpstream>)> = policy
        .upstreams
        .iter()
        .map(|(name, _)| {
            (
                name.clone(),
                FakeUpstream::new(payload.clone(), "application/json"),
            )
        })
        .collect();
    let verifier = w.verifier(policy, Some(options()));
    let upstreams = ups
        .iter()
        .map(|(n, u)| (Some(n.clone()), u.clone() as SharedUpstream))
        .collect();
    Stack {
        app: w.proxy_with(upstreams, None, verifier, audit),
        ups,
    }
}

fn stack(w: &World, policy: Policy) -> Stack {
    stack_with(w, policy, None, true)
}

async fn call(app: &axum::Router, path: &str, tool: &str, token: &str) -> Reply {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": tool, "arguments": {}}});
    post_to(app, path, body, &[("authorization", &bearer(token))]).await
}

fn denied(reply: &Reply) -> bool {
    reply.json()["result"]["isError"] == json!(true)
}

// -- routing ----------------------------------------------------------------------------

#[tokio::test]
async fn each_endpoint_forwards_to_its_own_upstream() {
    let w = World::new();
    let s = stack(&w, policy(None));
    let token = mandate(&w);
    assert!(!denied(
        &call(&s.app, "/mcp/catalog", "search_objects", &token).await
    ));
    assert!(!denied(
        &call(&s.app, "/mcp/inventory", "get_stock", &token).await
    ));
    assert!(s.up("catalog").reached() && s.up("inventory").reached());
    assert_eq!(s.up("catalog").calls.lock().unwrap().len(), 1);
    assert_eq!(s.up("inventory").calls.lock().unwrap().len(), 1);
}

/// Without this the namespace would be decorative: every endpoint would serve the
/// whole catalog.
#[tokio::test]
async fn an_endpoint_refuses_another_upstream_s_tool() {
    let w = World::new();
    let s = stack(&w, policy(None));
    let reply = call(&s.app, "/mcp/inventory", "search_objects", &mandate(&w)).await;
    assert!(denied(&reply));
    assert!(!s.up("inventory").reached());
}

#[tokio::test]
async fn the_single_endpoint_path_is_gone_when_upstreams_are_named() {
    let w = World::new();
    let s = stack(&w, policy(None));
    let reply = post_to(
        &s.app,
        "/mcp",
        json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
        &[],
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn tools_list_shows_only_the_endpoint_s_own_catalog() {
    let w = World::new();
    let catalog = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
        {"name": "search_objects"}, {"name": "get_stock"}, {"name": "leaky_export"},
    ]}});
    let s = stack_with(&w, policy(None), Some(catalog), false);
    for (endpoint, expected) in TOOLS {
        let reply = post_to(
            &s.app,
            &format!("/mcp/{endpoint}"),
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
        assert_eq!(names, vec![json!(expected)], "{endpoint}");
    }
}

// -- what the single process buys -------------------------------------------------------

/// "Three calls, every system included" — inexpressible with one proxy per upstream,
/// and the reason ADR-0006 keeps a single process.
#[tokio::test]
async fn the_budget_is_shared_across_upstreams() {
    let w = World::new();
    let s = stack(&w, policy(Some(3)));
    let token = mandate(&w);
    assert!(!denied(
        &call(&s.app, "/mcp/catalog", "search_objects", &token).await
    ));
    assert!(!denied(
        &call(&s.app, "/mcp/inventory", "get_stock", &token).await
    ));
    assert!(!denied(
        &call(&s.app, "/mcp/catalog", "search_objects", &token).await
    ));
    // Per-tool budgets are nowhere near exhausted; the global one is.
    assert!(denied(
        &call(&s.app, "/mcp/inventory", "get_stock", &token).await
    ));
}

#[tokio::test]
async fn one_audit_chain_carries_both_endpoints() {
    let w = World::new();
    let s = stack(&w, policy(None));
    let token = mandate(&w);
    call(&s.app, "/mcp/catalog", "search_objects", &token).await;
    call(&s.app, "/mcp/inventory", "get_stock", &token).await;

    let entries: Vec<Value> = w
        .audit_entries()
        .into_iter()
        .filter(|e| !e["tool"].is_null())
        .collect();
    let upstreams: Vec<Value> = entries
        .iter()
        .map(|e| e["detail"]["upstream"].clone())
        .collect();
    assert_eq!(upstreams, vec![json!("catalog"), json!("inventory")]);
    // A single chain: sequence numbers are contiguous across upstreams.
    let seqs: Vec<i64> = entries.iter().map(|e| e["seq"].as_i64().unwrap()).collect();
    let mut sorted = seqs.clone();
    sorted.sort_unstable();
    assert_eq!(seqs, sorted);
}

// -- aliasing ---------------------------------------------------------------------------

#[tokio::test]
async fn an_alias_is_rewritten_on_the_way_out_only() {
    let w = World::new();
    let mut p = policy(None);
    p.tools
        .iter_mut()
        .find(|t| t.name == "get_stock")
        .unwrap()
        .upstream_tool = Some("stock".into());
    let s = stack(&w, p);
    assert!(!denied(
        &call(&s.app, "/mcp/inventory", "get_stock", &mandate(&w)).await
    ));
    let forwarded = &s.up("inventory").bodies()[0];
    assert_eq!(forwarded["params"]["name"], json!("stock"));
}

// -- startup validation -----------------------------------------------------------------

fn policy_error(raw: Value) -> tokencrumb_mcp_proxy::Error {
    let err = parse_policy(&raw).expect_err("policy loaded");
    assert_eq!(err.kind, ErrorKind::Value);
    err
}

#[test]
fn a_tool_without_an_upstream_is_a_startup_failure() {
    let err = policy_error(json!({
        "upstreams": {"a": "http://a/mcp", "b": "http://b/mcp"},
        "tools": [{"name": "t", "operation": "read"}],
    }));
    assert!(err.message.contains("no `upstream:`"), "{}", err.message);
}

#[test]
fn an_unknown_upstream_is_a_startup_failure() {
    let err = policy_error(json!({
        "upstreams": {"a": "http://a/mcp"},
        "tools": [{"name": "t", "operation": "read", "upstream": "b"}],
    }));
    assert!(err.message.contains("not declared"), "{}", err.message);
}

#[test]
fn a_single_upstream_is_inferred() {
    let p = parse_policy(&json!({
        "upstreams": {"only": "http://only/mcp"},
        "tools": [{"name": "t", "operation": "read"}],
    }))
    .unwrap();
    assert_eq!(p.tool("t").unwrap().upstream.as_deref(), Some("only"));
}

#[test]
fn a_tool_mapped_twice_is_a_startup_failure() {
    let err = policy_error(json!({
        "tools": [{"name": "t", "operation": "read"}, {"name": "t", "operation": "write"}],
    }));
    assert!(err.message.contains("mapped twice"), "{}", err.message);
}
