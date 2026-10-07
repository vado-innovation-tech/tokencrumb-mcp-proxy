//! Adversarial suite — audience and upstream targeting (architecture decision 4).
//!
//! Before this, `forge --audience` wrote a fact nothing ever read: a mandate minted for
//! one deployment was replayable on every other one that mapped the same tool name.
//! These cases pin the fix and its provenance rule.
//!
//! Ported from `tests/adversarial/test_audience_upstream.py`.

mod common;

use std::sync::Arc;

use common::proxy::{
    TEST_AUDIENCE, World, append_block, biscuit_headers, build_token, date_term, forge, in_seconds,
    mandate, options, str_term, test_policy, verify,
};
use serde_json::{Value, json};
use tokencrumb_mcp_proxy::attestation::build_attestation;
use tokencrumb_mcp_proxy::biscuit_ops::{self, Attenuation, ForgeRequest, attenuate};
use tokencrumb_mcp_proxy::policy::parse_policy;
use tokencrumb_mcp_proxy::verifier::{Decision, Verifier, VerifierOptions};

const OTHER: &str = "prod-gw";

fn args() -> Value {
    json!({"path": "/projects/acme/rapport.md"})
}

fn read_token(w: &World, audience: &str, upstream: Option<&str>) -> String {
    forge(
        &w.authority.private_str,
        ForgeRequest {
            resource_prefix: Some("/projects/acme/".into()),
            audience: audience.into(),
            upstream: upstream.map(str::to_owned),
            ..mandate("agent-1", "read_file", "read", 3600, 200)
        },
    )
}

fn verifier(w: &World, upstream_name: Option<&str>) -> Arc<Verifier> {
    let mut opts = options();
    opts.upstream_name = upstream_name.map(str::to_owned);
    w.verifier(test_policy(), Some(opts))
}

fn read(v: &Verifier, token: &str) -> Decision {
    verify(v, "read_file", args(), &biscuit_headers(token, None))
}

// -- audience ---------------------------------------------------------------------------

/// An unnamed gateway cannot reject anything — so it must not exist. (Python also
/// tried `None`; a Rust audience is a `String`, so that case cannot be expressed.)
#[test]
fn gateway_without_an_audience_refuses_to_start() {
    let w = World::new();
    for bad in ["", "   "] {
        let err = Verifier::new(
            &w.authority.public_str,
            test_policy(),
            VerifierOptions::new(bad),
        )
        .err()
        .expect("an unnamed gateway started");
        assert!(err.message.contains("audience"), "{}", err.message);
    }
}

/// A mandate with no audience is denied everywhere; fail at issuance instead.
#[test]
fn forging_without_an_audience_is_refused() {
    let w = World::new();
    let err = biscuit_ops::forge(
        &w.authority.private_str,
        &ForgeRequest {
            audience: String::new(),
            ..mandate("agent-1", "read_file", "read", 3600, 200)
        },
    )
    .unwrap_err();
    assert!(err.message.contains("audience"), "{}", err.message);
}

/// A foreign issuer that omits the fact does not get a wildcard.
#[test]
fn mandate_without_audience_is_denied() {
    let w = World::new();
    let token = build_token(
        &w.authority.private_str,
        r#"agent_id({a}); required_profile("native"); right({t}, {o}); budget_cap(200);"#,
        &[
            ("a", str_term("agent-1")),
            ("t", str_term("read_file")),
            ("o", str_term("read")),
        ],
    );
    let d = read(&verifier(&w, None), &token);
    assert!(!d.allow);
    assert!(d.reason.contains("no audience"), "{}", d.reason);
}

#[test]
fn mandate_for_another_deployment_is_denied() {
    let w = World::new();
    let d = read(&verifier(&w, None), &read_token(&w, OTHER, None));
    assert!(!d.allow);
    assert!(d.reason.contains("audience mismatch"), "{}", d.reason);
}

/// The holder appends the gateway's own audience. Provenance reads block 0.
#[test]
fn audience_cannot_be_widened_by_attenuation() {
    let w = World::new();
    let evil = append_block(
        &read_token(&w, OTHER, None),
        &w.authority.public_str,
        "audience({a});",
        &[("a", str_term(TEST_AUDIENCE))],
    );
    let d = read(&verifier(&w, None), &evil);
    assert!(!d.allow);
    assert!(
        d.reason.contains("must originate in authority block"),
        "{}",
        d.reason
    );
}

#[test]
fn matching_audience_is_allowed() {
    let w = World::new();
    let d = read(&verifier(&w, None), &read_token(&w, TEST_AUDIENCE, None));
    assert!(d.allow, "{}", d.reason);
}

// -- upstream ---------------------------------------------------------------------------

#[test]
fn upstream_bound_mandate_reaches_only_its_upstream() {
    let w = World::new();
    let token = read_token(&w, TEST_AUDIENCE, Some("catalog"));
    assert!(read(&verifier(&w, Some("catalog")), &token).allow);
    assert!(!read(&verifier(&w, Some("inventory")), &token).allow);
}

/// No fact injected -> the token's check fails by closed-world semantics.
#[test]
fn upstream_bound_mandate_is_denied_by_an_unnamed_gateway() {
    let w = World::new();
    let token = read_token(&w, TEST_AUDIENCE, Some("catalog"));
    assert!(!read(&verifier(&w, None), &token).allow);
}

/// `upstream` is a check, not a fact: appending one can only remove reach.
#[test]
fn attenuation_narrows_the_upstream_and_cannot_widen_it() {
    let w = World::new();
    let narrowed = attenuate(
        &read_token(&w, TEST_AUDIENCE, Some("catalog")),
        &w.authority.public_str,
        &Attenuation {
            upstream: Some("inventory".into()),
            ..Default::default()
        },
    )
    .unwrap();
    // Both checks now have to hold at once, so neither endpoint accepts it.
    assert!(!read(&verifier(&w, Some("catalog")), &narrowed).allow);
    assert!(!read(&verifier(&w, Some("inventory")), &narrowed).allow);
}

/// Absent `upstream` is deliberately not a denial — the mandate is worth its rights
/// wherever they are routed (architecture decision 4).
#[test]
fn unrestricted_mandate_reaches_every_upstream() {
    let w = World::new();
    let token = read_token(&w, TEST_AUDIENCE, None);
    assert!(read(&verifier(&w, Some("catalog")), &token).allow);
    assert!(read(&verifier(&w, Some("inventory")), &token).allow);
}

// -- agent_id binding (3b mandates from an issuer that emits none) ----------------------

fn keycloak_like(w: &World, extra: &str) -> (String, Arc<Verifier>) {
    let token = build_token(
        &w.authority.private_str,
        &format!(
            r#"audience({{aud}}); required_profile("hardened_biscuit_anchored");
               {extra} agent_pubkey({{k}}); right("read_file", "read");
               expires_at({{exp}}); check if time($t), $t < {{exp}};"#
        ),
        &[
            ("aud", str_term(TEST_AUDIENCE)),
            ("k", str_term(&w.agent.public_str)),
            ("exp", date_term(in_seconds(3600))),
        ],
    );
    let mut p =
        parse_policy(&json!({"tools": [{"name": "read_file", "operation": "read"}]})).unwrap();
    p.policy_digest = "d".into();
    (token, w.verifier(p, Some(options())))
}

fn attested(w: &World, v: &Verifier, token: &str, claimed_agent: &str) -> Decision {
    let att = build_attestation(
        claimed_agent,
        "read_file",
        &json!({}),
        token,
        &w.agent.private_str,
        None,
    )
    .unwrap();
    verify(
        v,
        "read_file",
        json!({}),
        &biscuit_headers(token, Some(&att)),
    )
}

/// In 3b the anchored KEY is the identity. A mandate that binds no name — what
/// Keycloak mints — has nothing for the attestation to contradict.
#[test]
fn a_3b_mandate_without_agent_id_is_accepted() {
    let w = World::new();
    let (token, v) = keycloak_like(&w, "");
    let d = attested(&w, &v, &token, "whatever");
    assert!(d.allow, "{}", d.reason);
}

/// The check is not dropped — only skipped when the mandate binds no name.
#[test]
fn a_declared_agent_id_must_still_match() {
    let w = World::new();
    let (token, v) = keycloak_like(&w, r#"agent_id("agent-1");"#);
    let d = attested(&w, &v, &token, "someone-else");
    assert!(!d.allow);
    assert!(d.reason.contains("agent_id mismatch"), "{}", d.reason);
}
