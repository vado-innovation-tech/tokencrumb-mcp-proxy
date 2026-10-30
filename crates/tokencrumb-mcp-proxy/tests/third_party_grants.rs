//! Third-party grants: the one authority that owns a tool may grant it in place of the
//! root authority's right, within its declared tools only.

mod common;

use common::proxy::{TEST_AUDIENCE, World, append_block, biscuit_headers, forge, mandate, verify};
use serde_json::{Value, json};
use tokencrumb_mcp_proxy::biscuit_ops::{
    Attenuation, Endorse, append_third_party, attenuate, sign_third_party, sign_third_party_at,
    third_party_request,
};
use tokencrumb_mcp_proxy::keys::{Keypair, generate_keypair};
use tokencrumb_mcp_proxy::policy::{Policy, parse_policy};
use tokencrumb_mcp_proxy::verifier::{Decision, Verifier, VerifierOptions};

const SHARED: &str = "/partner/shared/report.md";

fn policy_for(partner: &str, approver: &str) -> Policy {
    parse_policy(&json!({
        "third_party": {
            "partner": {"keys": [partner], "predicates": ["grant"]},
            "approver": {"keys": [approver], "predicates": ["approval"]},
        },
        "tools": [
            {"name": "read_file", "operation": "read", "resource": {"from": "arguments.path"}},
            {"name": "share_file", "operation": "write", "resource": {"from": "arguments.path"},
             "grant_third_party": {"authority": "partner", "predicate": "grant"}},
            {"name": "purge_share", "operation": "write",
             "grant_third_party": {"authority": "partner"},
             "require_third_party": [{"authority": "approver"}]},
        ],
    }))
    .unwrap()
}

struct Setup {
    world: World,
    partner: Keypair,
    approver: Keypair,
    verifier: std::sync::Arc<Verifier>,
}

fn setup() -> Setup {
    let world = World::new();
    let partner = generate_keypair();
    let approver = generate_keypair();
    let verifier = world.verifier(
        policy_for(&partner.public_str, &approver.public_str),
        Some(VerifierOptions::new(TEST_AUDIENCE)),
    );
    Setup {
        world,
        partner,
        approver,
        verifier,
    }
}

/// A mandate whose root authority granted `read_file` only.
fn reader(s: &Setup) -> String {
    forge(
        &s.world.authority.private_str,
        mandate("agent-1", "read_file", "read", 600, 10),
    )
}

fn statement(predicate: &str, tool: &str, prefix: &str) -> Endorse {
    Endorse {
        predicate: predicate.into(),
        tools: vec![tool.into()],
        resource_prefix: prefix.into(),
        ttl_seconds: 300,
    }
}

fn signed(s: &Setup, token: &str, signer: &Keypair, what: &Endorse) -> String {
    let request = third_party_request(token, &s.world.authority.public_str).unwrap();
    let block = sign_third_party(&request, &signer.private_str, what).unwrap();
    append_third_party(token, &s.world.authority.public_str, &block, None).unwrap()
}

fn call(v: &Verifier, token: &str, tool: &str, arguments: Value) -> Decision {
    verify(v, tool, arguments, &biscuit_headers(token, None))
}

fn share(v: &Verifier, token: &str, path: &str) -> Decision {
    call(v, token, "share_file", json!({"path": path}))
}

fn denied(decision: &Decision, needle: &str) {
    assert!(!decision.allow, "unexpected ALLOW");
    assert!(
        decision.reason.contains(needle),
        "reason {:?} lacks {needle:?}",
        decision.reason
    );
}

#[test]
fn a_tool_outside_the_root_grant_names_its_missing_grant() {
    let s = setup();
    denied(
        &share(&s.verifier, &reader(&s), SHARED),
        "third-party grant missing: partner.grant",
    );
}

#[test]
fn the_owner_grants_a_tool_the_root_authority_did_not() {
    let s = setup();
    let t = signed(
        &s,
        &reader(&s),
        &s.partner,
        &statement("grant", "share_file", "/partner/"),
    );
    let decision = share(&s.verifier, &t, SHARED);
    assert!(decision.allow, "{}", decision.reason);
    assert_eq!(decision.endorsements.len(), 1);
    assert_eq!(decision.endorsements[0].authority, "partner");
    // The root right still works on its own.
    assert!(call(&s.verifier, &t, "read_file", json!({"path": SHARED})).allow);
}

#[test]
fn the_root_right_still_suffices_for_a_grantable_tool() {
    let s = setup();
    let t = forge(
        &s.world.authority.private_str,
        mandate("agent-1", "share_file", "write", 600, 10),
    );
    let decision = share(&s.verifier, &t, SHARED);
    assert!(decision.allow, "{}", decision.reason);
}

#[test]
fn a_grant_is_bound_to_its_tool_resource_and_expiry() {
    let s = setup();
    let base = reader(&s);
    let other_tool = signed(
        &s,
        &base,
        &s.partner,
        &statement("grant", "purge_share", ""),
    );
    denied(&share(&s.verifier, &other_tool, SHARED), "grant missing");
    let other_dir = signed(
        &s,
        &base,
        &s.partner,
        &statement("grant", "share_file", "/elsewhere/"),
    );
    denied(&share(&s.verifier, &other_dir, SHARED), "grant missing");

    let request = third_party_request(&base, &s.world.authority.public_str).unwrap();
    let block = sign_third_party_at(
        &request,
        &s.partner.private_str,
        &Endorse {
            ttl_seconds: 60,
            ..statement("grant", "share_file", "/partner/")
        },
        chrono::Utc::now() - chrono::TimeDelta::seconds(120),
    )
    .unwrap();
    let expired = append_third_party(&base, &s.world.authority.public_str, &block, None).unwrap();
    denied(&share(&s.verifier, &expired, SHARED), "grant missing");
}

#[test]
fn only_the_owner_can_grant() {
    let s = setup();
    // The approver may only state approvals: a grant from it refuses the whole mandate.
    let t = signed(
        &s,
        &reader(&s),
        &s.approver,
        &statement("grant", "share_file", "/partner/"),
    );
    denied(&share(&s.verifier, &t, SHARED), "not delegated");
    // An approval is not a grant, even from a declared authority.
    let t = signed(
        &s,
        &reader(&s),
        &s.approver,
        &statement("approval", "share_file", "/partner/"),
    );
    denied(&share(&s.verifier, &t, SHARED), "grant missing");
}

#[test]
fn a_holder_cannot_grant_itself() {
    let s = setup();
    for code in [
        r#"grant("share_file", "/partner/", 2100-01-01T00:00:00Z)"#,
        r#"right("share_file", "write")"#,
    ] {
        let t = append_block(&reader(&s), &s.world.authority.public_str, code, &[]);
        denied(&share(&s.verifier, &t, SHARED), "grant missing");
    }
}

#[test]
fn a_grant_reaches_no_tool_it_does_not_own() {
    let s = setup();
    // read_file has no owner: a partner grant for it changes nothing.
    let t = forge(
        &s.world.authority.private_str,
        mandate("agent-1", "share_file", "write", 600, 10),
    );
    let t = signed(&s, &t, &s.partner, &statement("grant", "read_file", ""));
    denied(
        &call(&s.verifier, &t, "read_file", json!({"path": SHARED})),
        "right",
    );
}

#[test]
fn a_granted_tool_still_needs_its_endorsements() {
    let s = setup();
    let granted = signed(
        &s,
        &reader(&s),
        &s.partner,
        &statement("grant", "purge_share", ""),
    );
    denied(
        &call(&s.verifier, &granted, "purge_share", json!({})),
        "third-party endorsement missing: approver.approval",
    );
    let both = signed(
        &s,
        &granted,
        &s.approver,
        &statement("approval", "purge_share", ""),
    );
    let decision = call(&s.verifier, &both, "purge_share", json!({}));
    assert!(decision.allow, "{}", decision.reason);
    assert_eq!(decision.endorsements.len(), 2);
}

#[test]
fn a_holder_can_narrow_a_granted_tool() {
    let s = setup();
    let granted = signed(
        &s,
        &reader(&s),
        &s.partner,
        &statement("grant", "share_file", "/partner/"),
    );
    let narrowed = attenuate(
        &granted,
        &s.world.authority.public_str,
        &Attenuation {
            resource: Some("/partner/drafts/".into()),
            ..Default::default()
        },
    )
    .unwrap();
    denied(&share(&s.verifier, &narrowed, SHARED), "policy denied");
    assert!(share(&s.verifier, &narrowed, "/partner/drafts/a.md").allow);
    let other_tools = attenuate(
        &granted,
        &s.world.authority.public_str,
        &Attenuation {
            tools: vec!["read_file".into()],
            ..Default::default()
        },
    )
    .unwrap();
    denied(&share(&s.verifier, &other_tools, SHARED), "policy denied");
}

#[test]
fn the_policy_keeps_grants_apart() {
    let key = generate_keypair().public_str;
    let other = generate_keypair().public_str;
    for (doc, needle) in [
        (
            json!({"third_party": {"a": {"keys": [key], "predicates": ["grant"]}},
                   "tools": [{"name": "t", "operation": "x",
                              "grant_third_party": {"authority": "b", "predicate": "grant"}}]}),
            "is not declared",
        ),
        (
            json!({"third_party": {"a": {"keys": [key], "predicates": ["grant"]}},
                   "tools": [{"name": "t", "operation": "x",
                              "grant_third_party": {"authority": "a", "predicate": "approval"}}]}),
            "is not delegated",
        ),
        (
            json!({"third_party": {"a": {"keys": [key], "predicates": ["grant"]}},
                   "tools": [{"name": "t", "operation": "x",
                              "grant_third_party": [{"authority": "a"}, {"authority": "a"}]}]}),
            "expected",
        ),
        (
            json!({"third_party": {"a": {"keys": [key], "predicates": ["ok"]},
                                   "b": {"keys": [other], "predicates": ["ok"]}},
                   "tools": [{"name": "t", "operation": "x",
                              "grant_third_party": {"authority": "a"}},
                             {"name": "u", "operation": "x",
                              "require_third_party": [{"authority": "a"}]}]}),
            "both grants and endorses",
        ),
    ] {
        let message = parse_policy(&doc).unwrap_err().message;
        assert!(message.contains(needle), "{message:?} lacks {needle:?}");
    }
}
