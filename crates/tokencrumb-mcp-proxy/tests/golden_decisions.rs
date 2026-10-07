//! The differential decision matrix: every scenario the former verifier judged is
//! replayed here — same tokens, same headers, same clock — and must end in the same
//! decision, for the same reason, with the same audit fields.

mod common;

use std::collections::HashSet;
use std::sync::Arc;

use common::{golden, key, t0};
use serde_json::{Value, json};
use tokencrumb_mcp_proxy::policy::parse_policy;
use tokencrumb_mcp_proxy::revocation::StaticRevocations;
use tokencrumb_mcp_proxy::verifier::{Decision, Headers, Verifier, VerifierOptions};

fn render(d: &Decision) -> Value {
    json!({
        "allow": d.allow, "reason": d.reason, "profile": d.profile, "tool": d.tool,
        "agent_id": d.agent_id, "resource": d.resource, "arguments_hash": d.arguments_hash,
        "remaining_budget": d.remaining_budget.map(|r| r as i64), "mandate_id": d.mandate_id,
        "subject": d.subject, "issuer": d.issuer, "agent_key": d.agent_key,
    })
}

/// A reason whose tail is a Python library message (base64, json) keeps its prefix.
fn same_reason(want: &str, got: &str) -> bool {
    want == got
        || (want.starts_with("malformed attestation: ")
            && got.starts_with("malformed attestation: ")
            && ["Invalid base64", "Expecting value", "'sig'"]
                .iter()
                .any(|m| want.contains(m)))
}

#[test]
fn every_reference_decision_is_reproduced() {
    let corpus = golden("decisions.json");
    let audience = corpus["audience"].as_str().unwrap();
    let mut checked = 0;
    for (name, scenario) in corpus["scenarios"].as_object().unwrap() {
        let policy = parse_policy(&scenario["policy"]).unwrap_or_else(|e| panic!("{name}: {e}"));
        let now = t0() + chrono::Duration::seconds(scenario["now_offset"].as_i64().unwrap());
        let mut options = VerifierOptions::new(audience);
        options.now_fn = Some(Box::new(move || now));
        let revoked: HashSet<String> = scenario["revoked_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        if !revoked.is_empty() {
            options.revocation = Some(Arc::new(StaticRevocations(revoked)));
        }
        if let Some(registry) = scenario["registry"].as_object() {
            let registry = registry.clone();
            options.resolve_agent_pubkey = Some(Box::new(move |id| {
                registry.get(id).and_then(Value::as_str).map(str::to_owned)
            }));
        }
        if scenario["previous"] == json!(true) {
            options.previous_authority_keys = vec![key("previous", "public")];
        }
        let verifier = Verifier::new(&key("authority", "public"), policy, options).unwrap();
        for (i, call) in scenario["calls"].as_array().unwrap().iter().enumerate() {
            let headers = Headers::new(
                call["headers"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned())),
            );
            let decision = verifier
                .verify_call(
                    call["tool"].as_str().unwrap(),
                    &call["arguments"],
                    &headers,
                    call["endpoint"].as_str(),
                    None,
                )
                .unwrap_or_else(|e| panic!("{name}[{i}]: {e}"));
            let want = &scenario["decisions"][i];
            let got = render(&decision);
            assert!(
                same_reason(want["reason"].as_str().unwrap(), &decision.reason),
                "{name}[{i}]: reason\n  want {}\n  got  {}",
                want["reason"],
                decision.reason
            );
            for field in [
                "allow",
                "profile",
                "tool",
                "agent_id",
                "resource",
                "arguments_hash",
                "remaining_budget",
                "mandate_id",
                "subject",
                "issuer",
                "agent_key",
            ] {
                assert_eq!(got[field], want[field], "{name}[{i}]: {field}");
            }
            checked += 1;
        }
    }
    let total: usize = corpus["scenarios"]
        .as_object()
        .unwrap()
        .values()
        .map(|s| s["calls"].as_array().unwrap().len())
        .sum();
    assert_eq!(checked, total);
    assert!(total > 120, "the matrix shrank to {total} decisions");
}
