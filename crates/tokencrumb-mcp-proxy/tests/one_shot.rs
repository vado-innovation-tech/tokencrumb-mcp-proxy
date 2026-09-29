//! One-shot mandate bound to an approved draft version (scenario B4).
//!
//! What the gateway actually checks: the right, the version id, the budget cap and the
//! expiry. What it does NOT check: that a human approved anything — the issuance is
//! requested by the handler, which holds the OIDC secrets. Proof of approval still
//! lives in the harness, and these tests are written not to suggest otherwise.
//!
//! Ported from `tests/test_one_shot.py`.

mod common;

use std::sync::Arc;

use tokencrumb_mcp_proxy::biscuit_ops::{Attenuation, ForgeRequest, attenuate};
use tokencrumb_mcp_proxy::budget::BudgetStore;
use tokencrumb_mcp_proxy::policy::{Policy, parse_policy};
use tokencrumb_mcp_proxy::verifier::{Decision, Verifier};
use common::proxy::{World, biscuit_headers, forge, mandate, options, verify};
use serde_json::json;

const APPROVED: &str = "v-7";
const EDITED: &str = "v-8";

fn mail_policy() -> Policy {
    let mut p = parse_policy(&json!({
        "deny_unknown_tools": true,
        "tools": [
            {"name": "prepare_email_draft", "operation": "write", "allow": {"budget": 20}},
            {"name": "send_email", "operation": "write",
             "args": [{"from": "arguments.draft_version_id", "as": "draft_version_id"}],
             "allow": {"budget": 10}},
        ],
    }))
    .unwrap();
    p.policy_digest = "test".into();
    p
}

fn verifier(w: &World, store: Arc<BudgetStore>) -> Arc<Verifier> {
    let mut opts = options();
    opts.budget_store = Some(store);
    w.verifier(mail_policy(), Some(opts))
}

/// The drafting agent: prepare_email_draft only, no send_email.
fn writer_token(w: &World) -> String {
    forge(
        &w.authority.private_str,
        mandate("redacteur", "prepare_email_draft", "write", 3600, 20),
    )
}

fn send_mandate(w: &World, version: &str, ttl_seconds: i128, budget: i128) -> String {
    forge(
        &w.authority.private_str,
        ForgeRequest {
            facts: vec![format!(r#"draft_version_id("{version}")"#)],
            scope_args: vec!["draft_version_id=draft_version_id".into()],
            ..mandate("redacteur", "send_email", "write", ttl_seconds, budget)
        },
    )
}

/// Issued fresh by the control plane after approval.
///
/// Deliberately a fresh forge, not an attenuation of the writer's token: the budget
/// counter is keyed on the authority block's revocation id, so an attenuated one-shot
/// would share — and inherit — the parent's already-consumed count.
fn one_shot(w: &World) -> String {
    send_mandate(w, APPROVED, 300, 1)
}

fn send(v: &Verifier, token: &str, version: &str) -> Decision {
    verify(
        v,
        "send_email",
        json!({"draft_version_id": version}),
        &biscuit_headers(token, None),
    )
}

#[test]
fn b4a_no_send_right_before_approval() {
    let w = World::new();
    let v = verifier(&w, Arc::new(BudgetStore::in_memory()));
    assert!(!send(&v, &writer_token(&w), APPROVED).allow);
}

#[test]
fn b4b_one_shot_allows_the_approved_version() {
    let w = World::new();
    let v = verifier(&w, Arc::new(BudgetStore::in_memory()));
    assert!(send(&v, &one_shot(&w), APPROVED).allow);
}

#[test]
fn b4c_replaying_the_same_token_is_denied() {
    let w = World::new();
    let v = verifier(&w, Arc::new(BudgetStore::in_memory()));
    let token = one_shot(&w);
    assert!(send(&v, &token, APPROVED).allow);
    assert!(!send(&v, &token, APPROVED).allow, "budget_cap(1) is spent");
}

#[test]
fn b4d_editing_the_draft_produces_a_version_absent_from_the_token() {
    let w = World::new();
    let v = verifier(&w, Arc::new(BudgetStore::in_memory()));
    let token = one_shot(&w);
    assert!(!send(&v, &token, EDITED).allow);
    // ...while the approved version still sends exactly what was approved
    assert!(send(&v, &token, APPROVED).allow);
}

/// Why the one-shot must be forged, not attenuated.
///
/// The budget counter is keyed on the authority block, which survives attenuation. A
/// "one-shot" derived from a working token is dead on arrival — and it fails for a
/// reason that has nothing to do with the approval, which is exactly the kind of
/// confusion the CLI must avoid.
#[test]
fn one_shot_as_attenuation_would_inherit_the_parent_counter() {
    let w = World::new();
    let v = verifier(&w, Arc::new(BudgetStore::in_memory()));
    let parent = send_mandate(&w, APPROVED, 3600, 2);
    assert!(send(&v, &parent, APPROVED).allow);
    assert!(
        send(&v, &parent, APPROVED).allow,
        "parent budget now exhausted"
    );

    let derived = attenuate(
        &parent,
        &w.authority.public_str,
        &Attenuation {
            budget: Some(1),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!send(&v, &derived, APPROVED).allow);

    let fresh = one_shot(&w); // a fresh forge has its own counter
    assert!(send(&v, &fresh, APPROVED).allow);
}

/// Bench conditions: counters die with the process, so the one-shot replays.
#[test]
fn b4r_replay_after_restart_without_persistence() {
    let w = World::new();
    let token = one_shot(&w);
    let first = verifier(&w, Arc::new(BudgetStore::in_memory()));
    assert!(send(&first, &token, APPROVED).allow);
    assert!(!send(&first, &token, APPROVED).allow);

    let restarted = verifier(&w, Arc::new(BudgetStore::in_memory()));
    assert!(
        send(&restarted, &token, APPROVED).allow,
        "expected the documented limitation: without --budget-state, a consumed \
         one-shot replays after a restart"
    );
}

/// With --budget-state, consumption survives the restart on this instance.
#[test]
fn b4r_replay_after_restart_with_persistence() {
    let w = World::new();
    let state = w.dir.path().join("budget.state");
    let token = one_shot(&w);

    let first = verifier(&w, Arc::new(BudgetStore::open(&state).unwrap()));
    assert!(send(&first, &token, APPROVED).allow);

    let restarted = verifier(&w, Arc::new(BudgetStore::open(&state).unwrap()));
    assert!(!send(&restarted, &token, APPROVED).allow);
}
