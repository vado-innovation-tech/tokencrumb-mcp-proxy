//! Adversarial suite — the TokenCrumb - MCP Proxy threat model. Every case must DENY.
//!
//! Ported from `tests/adversarial/test_adversarial.py`.

mod common;

use std::sync::Arc;

use tokencrumb_mcp_proxy::attestation::build_attestation;
use tokencrumb_mcp_proxy::biscuit_ops::{ForgeRequest, capability_key};
use tokencrumb_mcp_proxy::keys::{Keypair, generate_keypair};
use tokencrumb_mcp_proxy::nonce_cache::{NonceCache, NonceStore};
use tokencrumb_mcp_proxy::revocation::{RevocationList, sign_revocation_list};
use tokencrumb_mcp_proxy::verifier::{Verifier, VerifierOptions};
use chrono::{DateTime, TimeDelta, Utc};
use common::proxy::{
    World, append_block, biscuit_headers, forge, mandate, options, str_term, test_policy, verify,
};
use serde_json::{Value, json};

fn args() -> Value {
    json!({"schema": "analytics", "query": "select 1"})
}

fn att_for(agent: &Keypair, token: &str, tool: &str, arguments: &Value) -> String {
    build_attestation(
        "agent-rag-01",
        tool,
        arguments,
        token,
        &agent.private_str,
        None,
    )
    .unwrap()
}

fn att(agent: &Keypair, token: &str) -> String {
    att_for(agent, token, "execute_sql", &args())
}

fn verifier(w: &World) -> Arc<Verifier> {
    w.verifier(test_policy(), None)
}

fn with_clock(
    w: &World,
    clock: impl Fn() -> DateTime<Utc> + Send + Sync + 'static,
) -> Arc<Verifier> {
    let mut opts = options();
    opts.now_fn = Some(Box::new(clock));
    w.verifier(test_policy(), Some(opts))
}

/// A native read mandate over `/projets/acme/`.
fn read_scope(ttl_seconds: i128) -> ForgeRequest {
    ForgeRequest {
        resource_prefix: Some("/projets/acme/".into()),
        ..mandate("a", "read_file", "read", ttl_seconds, 10)
    }
}

#[test]
fn replay_denied() {
    let w = World::new();
    let v = verifier(&w);
    let token = w.hardened_token();
    let h = biscuit_headers(&token, Some(&att(&w.agent, &token)));
    assert!(verify(&v, "execute_sql", args(), &h).allow);
    assert!(!verify(&v, "execute_sql", args(), &h).allow, "replay");
}

#[test]
fn arguments_tampering_denied() {
    let w = World::new();
    let token = w.hardened_token();
    let signed = att_for(
        &w.agent,
        &token,
        "execute_sql",
        &json!({"schema": "analytics", "query": "A"}),
    );
    let d = verify(
        &verifier(&w),
        "execute_sql",
        json!({"schema": "analytics", "query": "B"}),
        &biscuit_headers(&token, Some(&signed)),
    );
    assert!(!d.allow);
    assert!(d.reason.contains("arguments_hash"), "{}", d.reason);
}

/// Attacker anchors their own agent_pubkey in an attenuation block and signs with
/// their key. Provenance reads block 0 only, so verification uses the REAL agent key
/// and the attacker's signature fails. Central 3b criterion.
#[test]
fn stolen_attenuator_denied() {
    let w = World::new();
    let evil = append_block(
        &w.hardened_token(),
        &w.authority.public_str,
        "agent_pubkey({k});",
        &[("k", str_term(&w.attacker.public_str))],
    );
    let signed = att(&w.attacker, &evil); // signed by attacker
    let d = verify(
        &verifier(&w),
        "execute_sql",
        args(),
        &biscuit_headers(&evil, Some(&signed)),
    );
    assert!(!d.allow);
    assert!(
        d.reason.contains("must originate in authority block"),
        "{}",
        d.reason
    );
}

/// A hardened-required token presented WITHOUT attestation -> native -> downgrade.
#[test]
fn downgrade_denied() {
    let w = World::new();
    let d = verify(
        &verifier(&w),
        "execute_sql",
        args(),
        &biscuit_headers(&w.hardened_token(), None),
    );
    assert!(!d.allow);
    assert!(d.reason.contains("downgrade"), "{}", d.reason);
}

#[test]
fn attestation_tool_mismatch_denied() {
    let w = World::new();
    let token = w.hardened_token();
    // signed for a different tool
    let signed = att_for(&w.agent, &token, "read_file", &args());
    let d = verify(
        &verifier(&w),
        "execute_sql",
        args(),
        &biscuit_headers(&token, Some(&signed)),
    );
    assert!(
        !d.allow && d.reason.contains("tool mismatch"),
        "{}",
        d.reason
    );
    let control = verify(
        &verifier(&w),
        "execute_sql",
        args(),
        &biscuit_headers(&token, Some(&att(&w.agent, &token))),
    );
    assert!(control.allow, "{}", control.reason);
}

/// An attestation bound to a DIFFERENT token than the one presented.
#[test]
fn token_substitution_denied() {
    let w = World::new();
    let other = forge(
        &w.authority.private_str,
        ForgeRequest {
            resource_prefix: Some("analytics".into()),
            agent_pubkey: Some(w.agent.public_str.clone()),
            required_profile: "hardened_biscuit_anchored".into(),
            ..mandate("agent-rag-01", "execute_sql", "write", 3600, 20)
        },
    );
    let signed = att(&w.agent, &other); // bound to `other`
    let d = verify(
        &verifier(&w),
        "execute_sql",
        args(),
        &biscuit_headers(&w.hardened_token(), Some(&signed)),
    );
    assert!(!d.allow);
    assert!(d.reason.contains("biscuit_hash"), "{}", d.reason);
}

#[test]
fn wrong_authority_signature_denied() {
    let w = World::new();
    let rogue = generate_keypair();
    let forged = forge(&rogue.private_str, read_scope(3600));
    let d = verify(
        &verifier(&w),
        "read_file",
        json!({"path": "/projets/acme/q3.md"}),
        &biscuit_headers(&forged, None),
    );
    assert!(!d.allow && d.reason.contains("signature"), "{}", d.reason);
}

#[test]
fn corrupted_token_denied() {
    let w = World::new();
    let d = verify(
        &verifier(&w),
        "read_file",
        json!({"path": "/projets/acme/q3.md"}),
        &biscuit_headers("not-a-real-biscuit", None),
    );
    assert!(
        !d.allow && d.reason.contains("biscuit verification failed"),
        "{}",
        d.reason
    );
}

#[test]
fn expired_token_denied() {
    let w = World::new();
    let expired = forge(&w.authority.private_str, read_scope(10));
    let v = with_clock(&w, || Utc::now() + TimeDelta::seconds(20));
    let d = verify(
        &v,
        "read_file",
        json!({"path": "/projets/acme/q3.md"}),
        &biscuit_headers(&expired, None),
    );
    assert!(!d.allow && d.reason.contains("expired"), "{}", d.reason);
}

#[test]
fn revoked_token_denied() {
    let w = World::new();
    let token = forge(&w.authority.private_str, read_scope(3600));
    let list = w.dir.path().join("revoked.list");
    let doc = sign_revocation_list(
        &[capability_key(&token).unwrap()],
        &w.authority.private_str,
        None,
        None,
        3600,
    )
    .unwrap();
    std::fs::write(&list, tokencrumb_mcp_proxy::json::dumps(&doc)).unwrap();
    let mut opts = options();
    opts.revocation = Some(Arc::new(
        RevocationList::new(&list, &w.authority.public_str, None, None).unwrap(),
    ));
    let d = verify(
        &w.verifier(test_policy(), Some(opts)),
        "read_file",
        json!({"path": "/projets/acme/q3.md"}),
        &biscuit_headers(&token, None),
    );
    assert!(!d.allow);
    assert!(d.reason.contains("revoked"), "{}", d.reason);
}

#[test]
fn path_traversal_denied() {
    let w = World::new();
    let h = biscuit_headers(&w.native_token(), None);
    let d = verify(
        &verifier(&w),
        "read_file",
        json!({"path": "/projets/acme/../globex/secret"}),
        &h,
    );
    assert!(!d.allow && d.reason.contains("resource"), "{}", d.reason);
    assert!(
        verify(
            &verifier(&w),
            "read_file",
            json!({"path": "/projets/acme/safe"}),
            &h
        )
        .allow
    );
}

#[test]
fn nonce_cache_full_fails_closed() {
    let w = World::new();
    let fixed = Utc::now();
    let full = NonceCache::new(1, 120, None).unwrap();
    // fresh, not expired
    assert!(
        full.check_and_add("occupied", tokencrumb_mcp_proxy::isotime::timestamp(&fixed), None)
            .unwrap()
    );
    let mut opts = VerifierOptions::new(common::proxy::TEST_AUDIENCE);
    opts.nonce_cache = Some(Arc::new(full));
    opts.now_fn = Some(Box::new(move || fixed));
    let v = w.verifier(test_policy(), Some(opts));
    let token = w.hardened_token();
    let signed = build_attestation(
        "agent-rag-01",
        "execute_sql",
        &args(),
        &token,
        &w.agent.private_str,
        Some(fixed),
    )
    .unwrap();
    let d = verify(
        &v,
        "execute_sql",
        args(),
        &biscuit_headers(&token, Some(&signed)),
    );
    assert!(
        !d.allow && d.reason.contains("nonce replay or cache full"),
        "{}",
        d.reason
    );
}

#[test]
fn future_timestamp_denied() {
    let w = World::new();
    // The attestation is stamped ~now, but the verifier's clock is 1h behind.
    let v = with_clock(&w, || Utc::now() - TimeDelta::hours(1));
    let token = w.hardened_token();
    let d = verify(
        &v,
        "execute_sql",
        args(),
        &biscuit_headers(&token, Some(&att(&w.agent, &token))),
    );
    assert!(
        !d.allow && d.reason.contains("timestamp in the future"),
        "{}",
        d.reason
    );
}
