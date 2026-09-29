//! Adversarial suite — Datalog runtime bounds are real (ROADMAP v0.2.0).
//!
//! In the former implementation the `limits:` block of policy.yaml was once inert (a
//! failed library call swallowed by a bare `except`), so biscuit-auth's own defaults
//! applied. These cases fail if the block goes inert again: each configures a bound
//! TIGHTER than the library default, so passing them proves the policy is what took
//! effect.
//!
//! Ported from `tests/adversarial/test_datalog_limits.py`.

mod common;

use tokencrumb_mcp_proxy::policy::{Policy, parse_policy};
use tokencrumb_mcp_proxy::verifier::Decision;
use common::proxy::{World, append_block, biscuit_headers, forge, mandate, options, verify};
use serde_json::{Value, json};

/// 21 facts joined with themselves -> 441 derived facts: under biscuit-auth's default
/// ceiling of 1000, over the 100 configured below.
const FACT_COUNT: usize = 21;

fn policy(limits: Value) -> Policy {
    let mut p = parse_policy(&json!({
        "deny_unknown_tools": true,
        "limits": limits,
        "tools": [{"name": "read_file", "operation": "read"}],
    }))
    .unwrap();
    p.policy_digest = "test-policy-digest".into();
    p
}

/// A mandate carrying a rule whose join blows up the fact base.
fn exploding_token(w: &World) -> String {
    let token = forge(
        &w.authority.private_str,
        mandate("agent-1", "read_file", "read", 3600, 200),
    );
    let mut source: String = (0..FACT_COUNT).map(|i| format!("num({i}); ")).collect();
    source.push_str("pair($x, $y) <- num($x), num($y);");
    append_block(&token, &w.authority.public_str, &source, &[])
}

fn call(w: &World, limits: Value) -> Decision {
    verify(
        &w.verifier(policy(limits), Some(options())),
        "read_file",
        json!({}),
        &biscuit_headers(&exploding_token(w), None),
    )
}

#[test]
fn combinatorial_explosion_is_refused() {
    let w = World::new();
    let d = call(&w, json!({"max_facts": 100}));
    assert!(!d.allow);
    assert!(
        d.reason.contains("Datalog execution limits"),
        "{}",
        d.reason
    );
}

/// Control: the token is only refused because of the configured bound, not because
/// it is malformed.
#[test]
fn the_same_token_passes_under_a_generous_ceiling() {
    let w = World::new();
    let d = call(&w, json!({"max_facts": 5000}));
    assert!(d.allow, "{}", d.reason);
}

#[test]
fn iteration_ceiling_is_applied() {
    let w = World::new();
    let d = call(&w, json!({"max_iterations": 1}));
    assert!(!d.allow);
    assert!(
        d.reason.contains("Datalog execution limits"),
        "{}",
        d.reason
    );
}
