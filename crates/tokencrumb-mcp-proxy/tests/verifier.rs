//! Nominal verifier behavior across profiles 1 / 3a / 3b.
//!
//! Ported from `tests/test_verifier.py`.

mod common;

use tokencrumb_mcp_proxy::attestation::build_attestation;
use tokencrumb_mcp_proxy::biscuit_ops::ForgeRequest;
use common::proxy::{World, biscuit_headers, forge, mandate, options, test_policy, verify};
use serde_json::json;

#[test]
fn profile1_allow_in_scope() {
    let w = World::new();
    let d = verify(
        &w.verifier(test_policy(), None),
        "read_file",
        json!({"path": "/projets/acme/q3.md"}),
        &biscuit_headers(&w.native_token(), None),
    );
    assert!(d.allow);
    assert_eq!(d.profile, "native");
}

#[test]
fn profile1_deny_out_of_scope() {
    let w = World::new();
    let d = verify(
        &w.verifier(test_policy(), None),
        "read_file",
        json!({"path": "/etc/passwd"}),
        &biscuit_headers(&w.native_token(), None),
    );
    assert!(!d.allow);
}

#[test]
fn unknown_tool_denied() {
    let w = World::new();
    let d = verify(
        &w.verifier(test_policy(), None),
        "leaky_search",
        json!({"query": "x"}),
        &biscuit_headers(&w.native_token(), None),
    );
    assert!(!d.allow);
    assert!(d.reason.contains("unknown tool"), "{}", d.reason);
}

#[test]
fn missing_token_denied() {
    let w = World::new();
    let d = verify(
        &w.verifier(test_policy(), None),
        "read_file",
        json!({"path": "/x"}),
        &tokencrumb_mcp_proxy::verifier::Headers::default(),
    );
    assert!(!d.allow);
}

#[test]
fn budget_exhaustion() {
    let w = World::new();
    let token = forge(
        &w.authority.private_str,
        ForgeRequest {
            resource_prefix: Some("/projets/acme/".into()),
            ..mandate("a", "read_file", "read", 3600, 3)
        },
    );
    let v = w.verifier(test_policy(), Some(options()));
    let headers = biscuit_headers(&token, None);
    let allows = (0..6)
        .filter(|_| {
            verify(
                &v,
                "read_file",
                json!({"path": "/projets/acme/q3.md"}),
                &headers,
            )
            .allow
        })
        .count();
    assert_eq!(allows, 3, "ceiling is the token's budget_cap");
}

/// A native token cannot satisfy execute_sql's `require:` proofs (closed world).
#[test]
fn write_tool_requires_hardened() {
    let w = World::new();
    let token = forge(
        &w.authority.private_str,
        ForgeRequest {
            resource_prefix: Some("analytics".into()),
            ..mandate("a", "execute_sql", "write", 3600, 20)
        },
    );
    let d = verify(
        &w.verifier(test_policy(), None),
        "execute_sql",
        json!({"schema": "analytics", "query": "x"}),
        &biscuit_headers(&token, None),
    );
    assert!(!d.allow);
}

#[test]
fn profile3b_hardened_allow() {
    let w = World::new();
    let token = w.hardened_token();
    let args = json!({"schema": "analytics", "query": "select 1"});
    let att = build_attestation(
        "agent-rag-01",
        "execute_sql",
        &args,
        &token,
        &w.agent.private_str,
        None,
    )
    .unwrap();
    let d = verify(
        &w.verifier(test_policy(), None),
        "execute_sql",
        args,
        &biscuit_headers(&token, Some(&att)),
    );
    assert!(d.allow, "{}", d.reason);
    assert_eq!(d.profile, "hardened_biscuit_anchored");
}

#[test]
fn profile3a_registry_allow() {
    let w = World::new();
    let token = forge(
        &w.authority.private_str,
        ForgeRequest {
            resource_prefix: Some("analytics".into()),
            required_profile: "registry_backed".into(),
            ..mandate("agent-rag-01", "execute_sql", "write", 3600, 20)
        },
    );
    let args = json!({"schema": "analytics", "query": "x"});
    let att = build_attestation(
        "agent-rag-01",
        "execute_sql",
        &args,
        &token,
        &w.agent.private_str,
        None,
    )
    .unwrap();
    let agent_public = w.agent.public_str.clone();
    let mut opts = options();
    opts.resolve_agent_pubkey = Some(Box::new(move |aid: &str| {
        (aid == "agent-rag-01").then(|| agent_public.clone())
    }));
    let d = verify(
        &w.verifier(test_policy(), Some(opts)),
        "execute_sql",
        args,
        &biscuit_headers(&token, Some(&att)),
    );
    assert!(d.allow, "{}", d.reason);
    assert_eq!(d.profile, "registry_backed");
}
