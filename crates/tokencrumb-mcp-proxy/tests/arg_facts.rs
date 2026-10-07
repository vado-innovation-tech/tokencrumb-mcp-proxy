//! Call arguments compared against facts signed into the token.
//!
//! This is the mechanism behind the "assigned incidents" scope: a token grants
//! `modify_incident`, but only over the incidents listed in its authority block. An
//! injection can therefore redirect an existing right, but never widen its perimeter.
//!
//! Ported from `tests/test_arg_facts.py`.

mod common;

use common::proxy::{World, append_block, biscuit_headers, forge, mandate, options, verify};
use serde_json::{Value, json};
use tokencrumb_mcp_proxy::ErrorKind;
use tokencrumb_mcp_proxy::biscuit_ops::{
    self, FactArg, ForgeRequest, parse_fact_spec, parse_scope_arg,
};
use tokencrumb_mcp_proxy::policy::{Policy, parse_policy};
use tokencrumb_mcp_proxy::verifier::{Decision, Verifier};

fn scoped_policy() -> Policy {
    let mut p = parse_policy(&json!({
        "deny_unknown_tools": true,
        "tools": [{
            "name": "modify_incident",
            "operation": "write",
            "args": [{"from": "arguments.incident_id", "as": "incident_id"}],
            "allow": {"budget": 50},
        }],
    }))
    .unwrap();
    p.policy_digest = "test".into();
    p
}

fn verifier(w: &World) -> std::sync::Arc<Verifier> {
    w.verifier(scoped_policy(), Some(options()))
}

fn scoped(w: &World, facts: &[&str]) -> String {
    forge(
        &w.authority.private_str,
        ForgeRequest {
            facts: facts.iter().map(|f| (*f).to_owned()).collect(),
            scope_args: vec!["incident_id=assigned_incident".into()],
            ..mandate("resolver", "modify_incident", "write", 3600, 50)
        },
    )
}

fn resolver_token(w: &World) -> String {
    scoped(
        w,
        &[
            r#"assigned_incident("INC-123")"#,
            r#"assigned_incident("INC-456")"#,
        ],
    )
}

fn call(verifier: &Verifier, token: &str, incident_id: Option<Value>) -> Decision {
    let args = match incident_id {
        None => json!({}),
        Some(id) => json!({"incident_id": id}),
    };
    verify(
        verifier,
        "modify_incident",
        args,
        &biscuit_headers(token, None),
    )
}

#[test]
fn assigned_incident_is_allowed() {
    let w = World::new();
    assert!(call(&verifier(&w), &resolver_token(&w), Some(json!("INC-123"))).allow);
}

/// The token carries the right; it does not carry this object.
#[test]
fn unassigned_incident_is_denied() {
    let w = World::new();
    assert!(!call(&verifier(&w), &resolver_token(&w), Some(json!("INC-999"))).allow);
}

#[test]
fn malformed_identifier_is_rejected() {
    let w = World::new();
    let (v, token) = (verifier(&w), resolver_token(&w));
    let long = "x".repeat(200);
    for bad in [
        "INC-123\"; drop",
        "INC 123",
        "INC/../INC-123",
        "INC-\u{0}123",
        long.as_str(),
    ] {
        let decision = call(&v, &token, Some(json!(bad)));
        assert!(!decision.allow, "{bad}");
        assert!(
            decision.reason.contains("argument rejected"),
            "{}",
            decision.reason
        );
    }
}

/// inc-123 is a different identifier from INC-123 — a DENY, not a silent match.
#[test]
fn case_variation_is_not_an_alias() {
    let w = World::new();
    assert!(!call(&verifier(&w), &resolver_token(&w), Some(json!("inc-123"))).allow);
}

#[test]
fn missing_argument_is_denied() {
    let w = World::new();
    assert!(!call(&verifier(&w), &resolver_token(&w), None).allow);
}

#[test]
fn multi_object_all_in_scope() {
    let w = World::new();
    assert!(
        call(
            &verifier(&w),
            &resolver_token(&w),
            Some(json!(["INC-123", "INC-456"]))
        )
        .allow
    );
}

/// Every identifier must be in scope, not just the first one.
#[test]
fn multi_object_one_out_of_scope_denies_the_whole_call() {
    let w = World::new();
    let (v, token) = (verifier(&w), resolver_token(&w));
    assert!(!call(&v, &token, Some(json!(["INC-123", "INC-999"]))).allow);
    assert!(!call(&v, &token, Some(json!(["INC-999", "INC-123"]))).allow);
}

#[test]
fn too_many_objects_is_refused() {
    let w = World::new();
    let ids: Vec<String> = (0..200).map(|i| format!("INC-{i}")).collect();
    let decision = call(&verifier(&w), &resolver_token(&w), Some(json!(ids)));
    assert!(!decision.allow);
    assert!(
        decision.reason.contains("too many argument combinations"),
        "{}",
        decision.reason
    );
}

/// Re-assigning the incident later cannot widen a token already issued.
#[test]
fn scope_is_frozen_at_issuance() {
    let w = World::new();
    let v = verifier(&w);
    let token = scoped(&w, &[r#"assigned_incident("INC-123")"#]);
    assert!(call(&v, &token, Some(json!("INC-123"))).allow);
    // A later assignment lives upstream; the token snapshot does not move.
    assert!(!call(&v, &token, Some(json!("INC-777"))).allow);
}

/// A holder appending their own fact must not satisfy an authority-block check.
#[test]
fn attenuation_cannot_add_itself_into_scope() {
    let w = World::new();
    let v = verifier(&w);
    let token = scoped(&w, &[r#"assigned_incident("INC-123")"#]);
    assert!(call(&v, &token, Some(json!("INC-123"))).allow);
    let widened = append_block(
        &token,
        &w.authority.public_str,
        r#"assigned_incident("INC-999");"#,
        &[],
    );
    assert!(call(&v, &widened, Some(json!("INC-123"))).allow);
    let denied = call(&v, &widened, Some(json!("INC-999")));
    assert!(
        !denied.allow && denied.reason.contains("policy denied"),
        "{}",
        denied.reason
    );
}

/// Mapping an argument in policy does not, by itself, constrain anything.
#[test]
fn token_without_scope_check_is_unaffected() {
    let w = World::new();
    let plain = forge(
        &w.authority.private_str,
        mandate("resolver", "modify_incident", "write", 3600, 50),
    );
    assert!(call(&verifier(&w), &plain, Some(json!("INC-999"))).allow);
}

// -- --fact / --scope-arg parsing: no raw Datalog from the CLI --------------------------

#[test]
fn fact_spec_parsing() {
    assert_eq!(
        parse_fact_spec(r#"assigned_incident("INC-123")"#).unwrap(),
        (
            "assigned_incident".to_owned(),
            vec![FactArg::Str("INC-123".into())]
        )
    );
    assert_eq!(
        parse_fact_spec(r#"pair("a", "b")"#).unwrap(),
        (
            "pair".to_owned(),
            vec![FactArg::Str("a".into()), FactArg::Str("b".into())]
        )
    );
    assert_eq!(
        parse_fact_spec("level(3)").unwrap(),
        ("level".to_owned(), vec![FactArg::Int(3)])
    );
}

#[test]
fn fact_spec_rejects_injection_attempts() {
    for bad in [
        r#"assigned_incident("A"); right("send_email", "write")"#,
        "not_a_fact",
        "assigned_incident()",
        "assigned_incident($x), allow if true",
        r#"Uppercase("A")"#,
    ] {
        let err = parse_fact_spec(bad).expect_err(bad);
        assert_eq!(err.kind, ErrorKind::FactSpec, "{bad}");
    }
}

#[test]
fn scope_arg_parsing() {
    assert_eq!(
        parse_scope_arg("incident_id=assigned_incident").unwrap(),
        ("incident_id".to_owned(), "assigned_incident".to_owned())
    );
    for bad in [
        "incident_id",
        "incident_id=",
        "=pred",
        "incident_id=Bad Pred",
    ] {
        let err = parse_scope_arg(bad).expect_err(bad);
        assert_eq!(err.kind, ErrorKind::FactSpec, "{bad}");
    }
}

/// A quote inside a value must stay a value, never become Datalog syntax.
#[test]
fn injected_fact_string_is_parameterized() {
    // Parameterized emission keeps a quoted value inside one term, but Biscuit prints
    // it unescaped, so the rendered block — which identity is read from — would be
    // ambiguous. Since 0.3.0 such a mandate is refused at forge time (and by the proxy).
    let w = World::new();
    let refused = biscuit_ops::forge(
        &w.authority.private_str,
        &ForgeRequest {
            facts: vec![r#"tag("weird \"quoted\" value")"#.into()],
            ..mandate("a", "modify_incident", "write", 60, 1)
        },
    );
    assert!(refused.unwrap_err().message.contains("quote or backslash"));
}
