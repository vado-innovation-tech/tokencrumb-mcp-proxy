//! Budgets are two counters, not one (architecture decision 5).
//!
//! The regression: the counter was keyed by the mandate alone while the ceiling was
//! computed per tool, so calls to a generous tool silently drained a strict one that
//! had never been used. The numbers in `policy.yaml` did not mean what they said.
//!
//! Ported from `tests/test_budget_two_level.py`.

mod common;

use std::sync::Arc;

use biscuit_auth::builder::Term;
use common::proxy::{
    TEST_AUDIENCE, World, biscuit_headers, build_token, date_term, in_seconds, options, str_term,
    verify,
};
use serde_json::json;
use tokencrumb_mcp_proxy::budget::BudgetStore;
use tokencrumb_mcp_proxy::policy::{Policy, parse_policy};
use tokencrumb_mcp_proxy::verifier::{Headers, Verifier};

fn policy(budget_total: Option<i64>, cheap: i64, rare: i64) -> Policy {
    let mut raw = json!({
        "deny_unknown_tools": true,
        "min_profile": "native",
        "tools": [
            {"name": "cheap", "operation": "read", "allow": {"budget": cheap}},
            {"name": "rare", "operation": "read", "allow": {"budget": rare}},
        ],
    });
    if let Some(total) = budget_total {
        raw["budget_total"] = json!(total);
    }
    let mut p = parse_policy(&raw).unwrap();
    p.policy_digest = "test-policy-digest".into();
    p
}

/// A mandate granting both tools — `forge` only ever grants one.
fn two_tool_token(w: &World, budget_cap: i64) -> String {
    build_token(
        &w.authority.private_str,
        r#"agent_id("agent-1"); required_profile("native"); audience({aud});
           right("cheap", "read"); right("rare", "read"); budget_cap({cap});
           expires_at({exp}); check if time($t), $t < {exp};"#,
        &[
            ("aud", str_term(TEST_AUDIENCE)),
            ("cap", Term::Integer(budget_cap)),
            ("exp", date_term(in_seconds(3600))),
        ],
    )
}

fn verifier(w: &World, policy: Policy) -> Arc<Verifier> {
    w.verifier(policy, Some(options()))
}

fn allowed(v: &Verifier, tool: &str, h: &Headers) -> bool {
    verify(v, tool, json!({}), h).allow
}

/// The bug, pinned: `rare` has a budget of 2 and must still have it after three
/// calls to `cheap`.
#[test]
fn calls_to_one_tool_do_not_spend_another_tool_s_budget() {
    let w = World::new();
    let v = verifier(&w, policy(None, 100, 2));
    let h = biscuit_headers(&two_tool_token(&w, 1000), None);
    for _ in 0..3 {
        assert!(allowed(&v, "cheap", &h));
    }
    for i in 0..2 {
        let d = verify(&v, "rare", json!({}), &h);
        assert!(d.allow, "call {i} on 'rare': {}", d.reason);
    }
}

#[test]
fn a_tool_budget_runs_out_on_its_own() {
    let w = World::new();
    let v = verifier(&w, policy(None, 100, 2));
    let h = biscuit_headers(&two_tool_token(&w, 1000), None);
    assert!(allowed(&v, "rare", &h));
    assert!(allowed(&v, "rare", &h));
    assert!(!allowed(&v, "rare", &h), "2 spent");
    assert!(allowed(&v, "cheap", &h), "untouched");
}

/// What the per-tool counter alone cannot express: N calls, all tools included.
#[test]
fn the_global_budget_caps_every_tool_together() {
    let w = World::new();
    let v = verifier(&w, policy(Some(3), 100, 2));
    let h = biscuit_headers(&two_tool_token(&w, 1000), None);
    assert!(allowed(&v, "cheap", &h));
    assert!(allowed(&v, "cheap", &h));
    assert!(allowed(&v, "rare", &h));
    // 3 calls spent globally: `cheap` still has 97 of its own, and is refused anyway.
    assert!(!allowed(&v, "cheap", &h));
}

#[test]
fn a_mandate_can_lower_the_global_ceiling_but_not_raise_it() {
    let w = World::new();
    let v = verifier(&w, policy(Some(100), 100, 2));
    let h = biscuit_headers(&two_tool_token(&w, 2), None);
    assert!(allowed(&v, "cheap", &h));
    assert!(allowed(&v, "cheap", &h));
    assert!(!allowed(&v, "cheap", &h));
}

/// `budget($b)` in Datalog must track the counter about to run out.
#[test]
fn remaining_reports_the_tighter_of_the_two() {
    let w = World::new();
    let v = verifier(&w, policy(Some(50), 100, 2));
    let h = biscuit_headers(&two_tool_token(&w, 1000), None);
    assert_eq!(verify(&v, "rare", json!({}), &h).remaining_budget, Some(1));
    assert_eq!(
        verify(&v, "cheap", json!({}), &h).remaining_budget,
        Some(48)
    );
}

#[test]
fn both_counters_survive_a_restart_together() {
    let w = World::new();
    let state = w.dir.path().join("budget.json");
    let policy = policy(Some(10), 100, 1);
    let h = biscuit_headers(&two_tool_token(&w, 1000), None);
    let with_store = || {
        let mut opts = options();
        opts.budget_store = Some(Arc::new(BudgetStore::open(&state).unwrap()));
        w.verifier(policy.clone(), Some(opts))
    };

    let first = with_store();
    assert!(allowed(&first, "rare", &h));

    let restarted = with_store();
    assert!(!allowed(&restarted, "rare", &h));
    assert!(allowed(&restarted, "cheap", &h));
}
