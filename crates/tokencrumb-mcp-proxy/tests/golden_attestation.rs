//! Differential tests on per-call attestations: headers built by the former
//! implementation must be accepted or refused identically, for the same reason.

mod common;

use tokencrumb_mcp_proxy::attestation::{Expected, build_attestation, verify_attestation};
use tokencrumb_mcp_proxy::canonical::arguments_hash;
use tokencrumb_mcp_proxy::nonce_cache::NonceCache;
use common::{golden, key, t0};
use serde_json::{Value, json};

/// Reasons built on Python library messages (base64, json, KeyError) only keep their
/// fixed prefix: the wording after it belonged to the old runtime, not to the contract.
fn same_reason(want: &Value, got: &Option<String>) -> bool {
    match (want.as_str(), got) {
        (None, None) => true,
        (Some(w), Some(g)) if w == g => true,
        (Some(w), Some(g)) => {
            w.starts_with("malformed attestation: ")
                && g.starts_with("malformed attestation: ")
                && !w.contains("unsupported attestation")
                && !w.contains("must")
                && !w.contains("exceeds")
                && !w.contains("duplicate")
        }
        _ => false,
    }
}

#[test]
fn python_attestations_verify_identically() {
    let corpus = golden("attestations.json");
    let tokens = golden("tokens.json");
    let token = tokens["tokens"]["hardened"].as_str().unwrap();
    let agent = key("agent", "public");
    let args_hash = arguments_hash(&corpus["args"]).unwrap();
    for (name, case) in corpus["results"].as_object().unwrap() {
        let cache = NonceCache::in_memory();
        let expected = Expected {
            agent_pubkey: &agent,
            tool: "execute_sql",
            arguments_hash: &args_hash,
            token_b64: token,
            now: t0(),
            freshness_seconds: 60,
            clock_skew_seconds: 30,
        };
        let header = case["header"].as_str().unwrap();
        for round in ["first", "second"] {
            let got = verify_attestation(header, &expected, &cache, true);
            let want = &case[round];
            assert_eq!(
                json!(got.ok),
                want["ok"],
                "{name}/{round}: ok ({:?})",
                got.reason
            );
            assert!(
                same_reason(&want["reason"], &got.reason),
                "{name}/{round}: reason {:?} vs {}",
                got.reason,
                want["reason"]
            );
            assert_eq!(
                json!(got.agent_id),
                want["agent_id"],
                "{name}/{round}: agent_id"
            );
            for flag in [
                "call_signature_valid",
                "nonce_fresh",
                "arguments_bound",
                "capability_bound",
            ] {
                let value = match flag {
                    "call_signature_valid" => got.call_signature_valid,
                    "nonce_fresh" => got.nonce_fresh,
                    "arguments_bound" => got.arguments_bound,
                    _ => got.capability_bound,
                };
                assert_eq!(json!(value), want[flag], "{name}/{round}: {flag}");
            }
            if want["ok"] == json!(true) {
                assert_eq!(json!(got.nonce_key), want["nonce_key"], "{name}: nonce_key");
                let delta =
                    got.nonce_expires_at.unwrap() - want["nonce_expires_at"].as_f64().unwrap();
                assert!(delta.abs() < 1e-6, "{name}: nonce_expires_at");
            }
        }
    }
}

#[test]
fn rust_attestations_verify_under_the_same_rules() {
    let tokens = golden("tokens.json");
    let token = tokens["tokens"]["hardened"].as_str().unwrap();
    let args = json!({"schema": "analytics", "query": "select 1"});
    let header = build_attestation(
        "agent-rag-01",
        "execute_sql",
        &args,
        token,
        &key("agent", "private"),
        Some(t0()),
    )
    .unwrap();
    let args_hash = arguments_hash(&args).unwrap();
    let agent = key("agent", "public");
    let expected = Expected {
        agent_pubkey: &agent,
        tool: "execute_sql",
        arguments_hash: &args_hash,
        token_b64: token,
        now: t0(),
        freshness_seconds: 60,
        clock_skew_seconds: 30,
    };
    let cache = NonceCache::in_memory();
    assert!(verify_attestation(&header, &expected, &cache, true).ok);
    assert_eq!(
        verify_attestation(&header, &expected, &cache, true)
            .reason
            .as_deref(),
        Some("nonce replay or cache full")
    );
}
