//! Signed expiry and maximum remaining lifetime (architecture decision 6).
//!
//! Ported from `tests/test_max_ttl.py`.

mod common;

use std::sync::Arc;

use common::proxy::{
    TEST_AUDIENCE, World, biscuit_headers, build_token, date_term, forge, in_seconds, mandate,
    options, str_term, verify,
};
use serde_json::{Value, json};
use tokencrumb_mcp_proxy::biscuit_ops::{Attenuation, ForgeRequest, attenuate, capability_key};
use tokencrumb_mcp_proxy::budget::BudgetStore;
use tokencrumb_mcp_proxy::policy::{Policy, parse_policy};
use tokencrumb_mcp_proxy::verifier::{Decision, Verifier};

fn args() -> Value {
    json!({"path": "/projects/acme/rapport.md"})
}

fn policy(max_ttl: Option<Value>, budget: i64) -> Policy {
    let mut raw = json!({
        "deny_unknown_tools": true,
        "tools": [{
            "name": "read_file",
            "operation": "read",
            "resource": {"from": "arguments.path"},
            "allow": {"resource_prefix": "/projects/acme/", "budget": budget},
        }],
    });
    if let Some(ttl) = max_ttl {
        raw["max_ttl"] = ttl;
    }
    let mut p = parse_policy(&raw).unwrap();
    p.policy_digest = "test-policy-digest".into();
    p
}

fn verifier(w: &World, policy: Policy, store: Option<Arc<BudgetStore>>) -> Arc<Verifier> {
    let mut opts = options();
    opts.budget_store = store;
    w.verifier(policy, Some(opts))
}

fn token(w: &World, ttl_seconds: i128) -> String {
    forge(
        &w.authority.private_str,
        ForgeRequest {
            resource_prefix: Some("/projects/acme/".into()),
            ..mandate("agent-1", "read_file", "read", ttl_seconds, 200)
        },
    )
}

/// A mandate from an issuer that never bounds anything in time.
fn timeless_token(w: &World) -> String {
    build_token(
        &w.authority.private_str,
        r#"agent_id("agent-1"); required_profile("native"); audience({aud});
           right("read_file", "read"); budget_cap(200);
           check if resource($r), $r.starts_with("/projects/acme/");"#,
        &[("aud", str_term(TEST_AUDIENCE))],
    )
}

fn read(v: &Verifier, token: &str) -> Decision {
    verify(v, "read_file", args(), &biscuit_headers(token, None))
}

#[test]
fn a_mandate_inside_the_cap_is_allowed() {
    let w = World::new();
    let v = verifier(&w, policy(Some(json!("8h")), 200), None);
    let d = read(&v, &token(&w, 3600));
    assert!(d.allow, "{}", d.reason);
}

#[test]
fn a_mandate_outliving_the_cap_is_refused() {
    let w = World::new();
    let v = verifier(&w, policy(Some(json!("1h")), 200), None);
    let d = read(&v, &token(&w, 30 * 3600));
    assert!(!d.allow);
    assert!(
        d.reason.contains("not bounded within max_ttl"),
        "{}",
        d.reason
    );
}

/// The case that motivates the mechanism: an issuer the proxy does not control.
#[test]
fn a_mandate_with_no_expiry_at_all_is_refused() {
    let w = World::new();
    let v = verifier(&w, policy(Some(json!("8h")), 200), None);
    let d = read(&v, &timeless_token(&w));
    assert!(!d.allow);
    assert!(
        d.reason.contains("not bounded within max_ttl"),
        "{}",
        d.reason
    );
}

/// Control: the refusal above comes from the cap, not from the token being odd.
#[test]
fn an_unbounded_mandate_is_refused_even_without_an_explicit_cap() {
    let w = World::new();
    let v = verifier(&w, policy(None, 200), None);
    assert!(!read(&v, &timeless_token(&w)).allow);
}

/// Inspect the refused root counter, not a different freshly forged token.
#[test]
fn a_refusal_for_excessive_signed_expiry_consumes_no_budget() {
    let w = World::new();
    let store = Arc::new(BudgetStore::in_memory());
    let policy = policy(Some(json!("1h")), 5);
    let long_token = token(&w, 30 * 3600);
    let short_token = token(&w, 600);

    assert!(
        !read(
            &verifier(&w, policy.clone(), Some(store.clone())),
            &long_token
        )
        .allow
    );

    let key = capability_key(&long_token).unwrap();
    assert_eq!(store.remaining(&key, 200).unwrap(), 200);
    assert_eq!(store.remaining(&format!("{key}|read_file"), 5).unwrap(), 5);

    let d = read(&verifier(&w, policy, Some(store)), &short_token);
    assert!(d.allow, "{}", d.reason);
    assert_eq!(
        d.remaining_budget,
        Some(4),
        "first of five, nothing was spent by the refusal"
    );
}

/// A holder can bring an over-long mandate back under the cap offline.
#[test]
fn signed_expiry_uses_the_earliest_attenuated_ttl() {
    let w = World::new();
    let policy = policy(Some(json!("1h")), 200);
    let long_token = token(&w, 30 * 3600);
    let narrowed = attenuate(
        &long_token,
        &w.authority.public_str,
        &Attenuation {
            ttl_seconds: Some(600),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!read(&verifier(&w, policy.clone(), None), &long_token).allow);
    assert!(read(&verifier(&w, policy, None), &narrowed).allow);
}

#[test]
fn max_ttl_accepts_human_durations() {
    let ttl = |v: Value| {
        parse_policy(&json!({"max_ttl": v, "tools": []}))
            .unwrap()
            .max_ttl_seconds
    };
    assert_eq!(ttl(json!("8h")), 28800);
    assert_eq!(ttl(json!(900)), 900);
}

/// The horizon pass must not accidentally rescue an already-expired mandate.
#[test]
fn an_expired_mandate_is_still_refused_on_its_own() {
    let w = World::new();
    let expired = build_token(
        &w.authority.private_str,
        r#"agent_id("agent-1"); required_profile("native"); audience({aud});
           right("read_file", "read"); budget_cap(200);
           expires_at({exp}); check if time($t), $t < {exp};"#,
        &[
            ("aud", str_term(TEST_AUDIENCE)),
            ("exp", date_term(in_seconds(-2 * 3600))),
        ],
    );
    let d = read(
        &verifier(&w, policy(Some(json!("8h")), 200), None),
        &expired,
    );
    assert!(!d.allow);
    assert!(d.reason.contains("policy denied"), "{}", d.reason);
}
