//! forge / attenuate / inspect + provenance-safe reads.
//!
//! Ported from `tests/test_biscuit_ops.py`.

mod common;

use common::proxy::{World, append_block, forge, mandate, str_term};
use tokencrumb_mcp_proxy::biscuit_ops::{
    Attenuation, ForgeRequest, attenuate, authority_pubkey, authority_required_profile,
    capability_key, inspect, min_budget_cap,
};
use tokencrumb_mcp_proxy::token_contract::Term;

fn s(value: &str) -> Term {
    Term::Str(value.to_owned())
}

#[test]
fn forge_inspect_roundtrip() {
    let w = World::new();
    let token = forge(
        &w.authority.private_str,
        ForgeRequest {
            resource_prefix: Some("/projects/acme/".into()),
            agent_pubkey: Some(w.agent.public_str.clone()),
            required_profile: "hardened_biscuit_anchored".into(),
            ..mandate("a1", "read_file", "read", 3600, 200)
        },
    );
    let r = inspect(&token).unwrap();
    assert_eq!(r.block_count, 1);
    assert_eq!(r.fact("agent_id"), Some(&vec![s("a1")]));
    assert_eq!(
        r.fact("required_profile"),
        Some(&vec![s("hardened_biscuit_anchored")])
    );
    assert_eq!(
        authority_pubkey(&token).unwrap(),
        Some(s(&w.agent.public_str))
    );
    assert_eq!(
        authority_required_profile(&token).unwrap(),
        Some(s("hardened_biscuit_anchored"))
    );
}

fn projets(w: &World) -> String {
    forge(
        &w.authority.private_str,
        ForgeRequest {
            resource_prefix: Some("/projects/".into()),
            ..mandate("a1", "read_file", "read", 3600, 200)
        },
    )
}

#[test]
fn attenuate_is_monotonic_and_appends() {
    let w = World::new();
    let att = attenuate(
        &projets(&w),
        &w.authority.public_str,
        &Attenuation {
            resource: Some("/projects/acme/".into()),
            budget: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(inspect(&att).unwrap().block_count, 2);
    assert_eq!(min_budget_cap(&att).unwrap(), Some(10), "lowered ceiling");
}

#[test]
fn capability_key_stable_across_attenuation() {
    let w = World::new();
    let token = projets(&w);
    let att = attenuate(
        &token,
        &w.authority.public_str,
        &Attenuation {
            budget: Some(5),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        capability_key(&token).unwrap(),
        capability_key(&att).unwrap()
    );
}

/// An attacker appending `agent_pubkey` in a later block must NOT be read by
/// provenance.
#[test]
fn provenance_ignores_attenuation_agent_pubkey() {
    let w = World::new();
    let token = forge(
        &w.authority.private_str,
        ForgeRequest {
            resource_prefix: Some("/projects/".into()),
            agent_pubkey: Some(w.agent.public_str.clone()),
            required_profile: "hardened_biscuit_anchored".into(),
            ..mandate("a1", "read_file", "read", 3600, 200)
        },
    );
    let evil = append_block(
        &token,
        &w.authority.public_str,
        "agent_pubkey({k});",
        &[("k", str_term(&w.attacker.public_str))],
    );
    // provenance still returns the authority-block key, not the attacker's
    assert_eq!(
        authority_pubkey(&evil).unwrap(),
        Some(s(&w.agent.public_str))
    );
}
