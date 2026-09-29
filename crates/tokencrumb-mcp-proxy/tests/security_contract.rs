//! Regression proofs for typed mandates, exact arguments and bounded state.
//!
//! Ported from `tests/test_security_contract.py`.

mod common;

use std::sync::{Arc, Mutex};

use tokencrumb_mcp_proxy::ErrorKind;
use tokencrumb_mcp_proxy::attestation::build_attestation;
use tokencrumb_mcp_proxy::biscuit_ops::{self, Attenuation, ForgeRequest, attenuate};
use tokencrumb_mcp_proxy::budget::BudgetStore;
use tokencrumb_mcp_proxy::canonical::{
    arguments_hash, canonicalize_arg, canonicalize_prefix, canonicalize_resource,
};
use tokencrumb_mcp_proxy::nonce_cache::{NonceCache, NonceStore};
use tokencrumb_mcp_proxy::policy::parse_policy;
use tokencrumb_mcp_proxy::revocation::{
    RevocationList, RevocationSource, sign_revocation_list, update_revocation_list,
};
use tokencrumb_mcp_proxy::token_contract::Term;
use tokencrumb_mcp_proxy::verifier::{Decision, Headers, Verifier};
use chrono::{TimeDelta, Utc};
use common::proxy::{
    TEST_AUDIENCE, World, append_block, bearer, biscuit_headers, build_token, date_term, forge,
    in_seconds, mandate, options, str_term, test_policy, verify,
};
use serde_json::{Value, json};

fn raw(w: &World, declaration: &str, checks: &str) -> String {
    build_token(
        &w.authority.private_str,
        &format!(
            r#"required_profile("native"); audience({{aud}}); right("read_file", "read");
               expires_at({{exp}}); budget_cap(10);{declaration}{checks}"#
        ),
        &[
            ("aud", str_term(TEST_AUDIENCE)),
            ("exp", date_term(in_seconds(600))),
        ],
    )
}

fn read(v: &Verifier, token: &str, path: Value) -> Decision {
    verify(
        v,
        "read_file",
        json!({"path": path}),
        &biscuit_headers(token, None),
    )
}

fn x() -> Value {
    json!("/projets/acme/x")
}

#[test]
fn issuer_cannot_supply_context_or_ambiguous_metadata() {
    for declaration in [
        r#"resource("/projets/acme/x");"#,
        "budget(1000);",
        r#"upstream("catalog");"#,
        r#"arg("tenant", "trusted");"#,
        "call_signature_valid(true);",
        "resource($x) <- innocent($x);",
        r#"required_profile("native", "extra");"#,
        r#"audience("second");"#,
        r#"budget_cap("50");"#,
        "budget_cap($b) <- candidate($b);",
        r#"expires_at("tomorrow");"#,
    ] {
        let w = World::new();
        let v = w.verifier(test_policy(), None);
        let good = read(&v, &raw(&w, "", ""), x());
        assert!(good.allow, "{}", good.reason);
        let bad = read(&v, &raw(&w, declaration, ""), x());
        assert!(
            !bad.allow && bad.reason.contains("schema"),
            "{declaration}: {}",
            bad.reason
        );
    }
}

#[test]
fn quoted_metadata_text_does_not_supply_metadata() {
    let w = World::new();
    let token = raw(
        &w,
        r#"comment("agent_pubkey(\"fake)\"); budget_cap(1000);");"#,
        "",
    );
    let result = read(&w.verifier(test_policy(), None), &token, x());
    assert!(result.allow, "{}", result.reason);
}

#[test]
fn unknown_tool_never_bypasses_checks() {
    let w = World::new();
    let v = w.verifier(
        parse_policy(&json!({"deny_unknown_tools": false})).unwrap(),
        Some(options()),
    );
    let d = verify(
        &v,
        "unknown",
        json!({}),
        &biscuit_headers(&raw(&w, "", ""), None),
    );
    assert!(
        !d.allow && d.reason.contains("mapping is required"),
        "{}",
        d.reason
    );
}

#[test]
fn adding_a_block_cannot_satisfy_a_depth_check() {
    let w = World::new();
    let parent = raw(&w, "", "check if delegation_depth($d), $d > 0;");
    let child = append_block(&parent, &w.authority.public_str, "", &[]);
    for token in [parent, child] {
        let d = read(&w.verifier(test_policy(), None), &token, x());
        assert!(
            !d.allow && d.reason.contains("policy denied"),
            "{}",
            d.reason
        );
    }
}

#[test]
fn every_business_argument_is_hashed() {
    for key in ["id", "_meta", "jsonrpc"] {
        assert_ne!(
            arguments_hash(&json!({key: "A"})).unwrap(),
            arguments_hash(&json!({key: "B"})).unwrap()
        );
        assert_eq!(
            arguments_hash(&json!({key: "A", "v": 1})).unwrap(),
            arguments_hash(&json!({"v": 1, key: "A"})).unwrap()
        );
    }
}

#[test]
fn final_resource_validation() {
    for value in ["%00", "%2500", "/a/..\\b", "//a"] {
        assert!(canonicalize_resource(value).is_err(), "{value}");
        assert_eq!(canonicalize_resource("/%41/x").unwrap(), "/A/x");
    }
}

#[test]
fn prefix_boundary_uses_decoded_path() {
    assert_eq!(
        canonicalize_prefix("%2Fa%2Fb").unwrap(),
        canonicalize_prefix("/a/b").unwrap()
    );
    assert_eq!(canonicalize_prefix("/a/b").unwrap(), "/a/b/");
    assert!(canonicalize_arg(&json!(" tenant ")).is_err());
}

/// Python also tried `budget=True`; an attenuation budget is an integer in Rust, so
/// a boolean cannot be expressed.
#[test]
fn invalid_attenuation_is_rejected() {
    let w = World::new();
    let token = w.native_token();
    for request in [
        Attenuation {
            budget: Some(-1),
            ..Default::default()
        },
        Attenuation {
            ttl_seconds: Some(0),
            ..Default::default()
        },
        Attenuation {
            max_delegation_depth: Some(0),
            ..Default::default()
        },
    ] {
        let err = attenuate(&token, &w.authority.public_str, &request)
            .expect_err(&format!("{request:?}"));
        assert_eq!(err.kind, ErrorKind::Value, "{request:?}");
    }
}

#[test]
fn a_budget_one_cannot_authorize_two_concurrent_calls() {
    let w = World::new();
    let token = forge(
        &w.authority.private_str,
        mandate("a", "read_file", "read", 600, 1),
    );
    let path = w.dir.path().join("budgets.json");
    let verifiers: Vec<Arc<Verifier>> = (0..4)
        .map(|_| {
            let mut opts = options();
            opts.budget_store = Some(Arc::new(BudgetStore::open(&path).unwrap()));
            w.verifier(test_policy(), Some(opts))
        })
        .collect();
    let results: Vec<Decision> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..16)
            .map(|i| {
                let (v, token) = (&verifiers[i % 4], &token);
                scope.spawn(move || read(v, token, x()))
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(results.iter().filter(|d| d.allow).count(), 1);
    assert!(
        results
            .iter()
            .all(|d| d.allow || d.reason.contains("budget exhausted")),
        "{:?}",
        results.iter().map(|d| &d.reason).collect::<Vec<_>>()
    );
}

#[test]
fn corrupt_budget_counters_cannot_add_calls() {
    for value in [json!(-1), json!(true), json!("2"), json!(1.5)] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state");
        std::fs::write(&path, json!({"cap": value}).to_string()).unwrap();
        let err = BudgetStore::open(&path)
            .err()
            .unwrap_or_else(|| panic!("{value} accepted"));
        assert_eq!(err.kind, ErrorKind::Value, "{value}: {}", err.message);
    }
}

#[test]
fn missing_revocations_fail_at_startup() {
    let w = World::new();
    let err = RevocationList::new(
        w.dir.path().join("missing"),
        &w.authority.public_str,
        None,
        None,
    )
    .err()
    .expect("missing revocation list accepted");
    assert_eq!(err.kind, ErrorKind::Revocation);
}

fn write_doc(path: &std::path::Path, doc: &Value) {
    std::fs::write(path, tokencrumb_mcp_proxy::json::dumps(doc)).unwrap();
}

#[test]
fn revocation_loss_retains_only_fresh_authenticated_view() {
    let w = World::new();
    let p = w.dir.path().join("revoked");
    let clock = Arc::new(Mutex::new(1000.0_f64));
    write_doc(
        &p,
        &sign_revocation_list(
            &["revoked-id".into()],
            &w.authority.private_str,
            Some(1),
            Some(1000.0),
            10,
        )
        .unwrap(),
    );
    let now = clock.clone();
    let rl = RevocationList::new(
        &p,
        &w.authority.public_str,
        None,
        Some(Box::new(move || *now.lock().unwrap())),
    )
    .unwrap();
    std::fs::remove_file(&p).unwrap();
    assert_eq!(
        rl.any_revoked(&["revoked-id".into()]).unwrap().as_deref(),
        Some("revoked-id")
    );
    assert!(rl.last_error().is_some());
    *clock.lock().unwrap() = 1011.0;
    let err = rl.any_revoked(&[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Revocation);
    write_doc(
        &p,
        &sign_revocation_list(&[], &w.authority.private_str, Some(2), Some(1011.0), 3600).unwrap(),
    );
    assert_eq!(rl.any_revoked(&["revoked-id".into()]).unwrap(), None);
}

#[test]
fn revocation_rollback_stays_refused_after_restart() {
    let w = World::new();
    let p = w.dir.path().join("revoked");
    let old = sign_revocation_list(&[], &w.authority.private_str, Some(1), None, 3600).unwrap();
    write_doc(
        &p,
        &sign_revocation_list(&["x".into()], &w.authority.private_str, Some(2), None, 3600)
            .unwrap(),
    );
    RevocationList::new(&p, &w.authority.public_str, None, None).unwrap();
    write_doc(&p, &old);
    let err = RevocationList::new(&p, &w.authority.public_str, None, None)
        .err()
        .expect("rollback accepted after restart");
    assert_eq!(err.kind, ErrorKind::Revocation);
    assert!(err.message.contains("rollback"), "{}", err.message);
}

#[test]
fn revocation_writers_preserve_each_others_additions() {
    let w = World::new();
    let p = w.dir.path().join("revoked");
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..12)
            .map(|i| {
                let (p, key) = (&p, &w.authority.private_str);
                scope.spawn(move || update_revocation_list(p, key, &[i.to_string()]).unwrap())
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
    });
    let rl = RevocationList::new(&p, &w.authority.public_str, None, None).unwrap();
    for i in 0..12 {
        assert_eq!(
            rl.any_revoked(&[i.to_string()]).unwrap(),
            Some(i.to_string())
        );
    }
    let mut doc: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    doc["revoked"] = json!([]);
    write_doc(&p, &doc);
    let err = update_revocation_list(&p, &w.authority.private_str, &["new".into()]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Revocation);
}

#[test]
fn nonce_is_retained_through_the_full_signed_window() {
    let cache = NonceCache::new(100_000, 120, None).unwrap();
    assert!(cache.check_and_add("nonce", 1000.0, Some(1241.0)).unwrap());
    assert!(!cache.check_and_add("nonce", 1200.0, Some(1241.0)).unwrap());
    assert!(cache.check_and_add("nonce", 1242.0, Some(1480.0)).unwrap());
}

#[test]
fn lowering_budget_cannot_supply_a_new_witness_to_parent_checks() {
    let w = World::new();
    let parent = build_token(
        &w.authority.private_str,
        r#"audience({a});required_profile("native");right("read_file","read");budget_cap(10);expires_at({e});check if budget($b), $b == 1;"#,
        &[
            ("a", str_term(TEST_AUDIENCE)),
            ("e", date_term(in_seconds(300))),
        ],
    );
    let child = attenuate(
        &parent,
        &w.authority.public_str,
        &Attenuation {
            budget: Some(1),
            ..Default::default()
        },
    )
    .unwrap();
    let v = w.verifier(test_policy(), Some(options()));
    assert!(!read(&v, &parent, x()).allow);
    assert!(!read(&v, &child, x()).allow);
}

#[test]
fn noncanonical_resources_are_not_authorized_then_forwarded_differently() {
    let w = World::new();
    let token = w.native_token();
    for resource in [
        json!("/projets/%61cme/x"),
        json!("/projets/acme/./x"),
        json!(123),
        json!({"path": "/projets/acme/x"}),
    ] {
        let v = w.verifier(test_policy(), None);
        assert!(read(&v, &token, x()).allow);
        let decision = read(&v, &token, resource.clone());
        assert!(
            !decision.allow && decision.reason.contains("resource rejected"),
            "{resource}: {}",
            decision.reason
        );
    }
}

#[test]
fn integer_argument_is_not_an_alias_for_a_string_identifier() {
    assert_eq!(canonicalize_arg(&json!("123")).unwrap(), "123");
    let err = canonicalize_arg(&json!(123)).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Argument);
}

#[test]
fn inspection_preserves_scalar_business_facts() {
    let w = World::new();
    assert_eq!(
        biscuit_ops::inspect(&w.native_token())
            .unwrap()
            .fact("right"),
        Some(&vec![
            Term::Str("read_file".into()),
            Term::Str("read".into())
        ])
    );
}

#[test]
fn policy_min_profile_is_an_independent_refusal() {
    let w = World::new();
    let token = w.native_token();
    let permissive = w.verifier(test_policy(), Some(options()));
    assert!(read(&permissive, &token, x()).allow);
    let mut required = test_policy();
    required.min_profile = "hardened_biscuit_anchored".into();
    let denied = read(&w.verifier(required, Some(options())), &token, x());
    assert!(
        !denied.allow && denied.reason.contains("profile below policy min"),
        "{}",
        denied.reason
    );
}

#[test]
fn present_attestation_without_a_key_source_is_refused() {
    for header in ["", "unverifiable"] {
        let w = World::new();
        let token = w.native_token();
        let v = w.verifier(test_policy(), None);
        assert!(read(&v, &token, x()).allow);
        let headers = Headers::new([
            ("authorization", bearer(&token)),
            ("agent-attestation", header.to_owned()),
        ]);
        let denied = verify(&v, "read_file", json!({"path": x()}), &headers);
        assert!(
            !denied.allow && denied.reason.contains("no trusted key source"),
            "{header:?}: {}",
            denied.reason
        );
    }
}

/// The two verifiers share one nonce cache here, so the second call proves the stale
/// refusal did not record the nonce. (The Python test built each verifier with its own
/// cache, which could not observe that.)
#[test]
fn stale_attestation_is_refused_without_spending_its_nonce() {
    let w = World::new();
    let token = w.hardened_token();
    let now = Utc::now();
    let args = json!({"schema": "analytics", "query": "select 1"});
    let header = build_attestation(
        "agent-rag-01",
        "execute_sql",
        &args,
        &token,
        &w.agent.private_str,
        Some(now),
    )
    .unwrap();
    let nonces: Arc<dyn NonceStore> = Arc::new(NonceCache::in_memory());
    let at = |instant: chrono::DateTime<Utc>| {
        let mut opts = options();
        opts.nonce_cache = Some(nonces.clone());
        opts.now_fn = Some(Box::new(move || instant));
        w.verifier(test_policy(), Some(opts))
    };
    let headers = biscuit_headers(&token, Some(&header));
    let late = at(now + TimeDelta::seconds(120));
    let denied = verify(&late, "execute_sql", args.clone(), &headers);
    assert!(
        !denied.allow && denied.reason.contains("attestation stale"),
        "{}",
        denied.reason
    );
    let timely = verify(&at(now), "execute_sql", args, &headers);
    assert!(timely.allow, "{}", timely.reason);
}

#[test]
fn token_size_boundary_has_a_valid_control() {
    let w = World::new();
    let token = w.native_token();
    for (size, allowed) in [(token.len(), true), (token.len() - 1, false)] {
        let mut bounded = test_policy();
        bounded.limits.max_token_size = size as i128;
        let result = read(&w.verifier(bounded, Some(options())), &token, x());
        assert_eq!(result.allow, allowed, "{size}: {}", result.reason);
        if !allowed {
            assert!(result.reason.contains("size"), "{}", result.reason);
        }
    }
}

#[test]
fn registry_profile_refusal_is_distinct_from_a_bad_token() {
    let w = World::new();
    let token = forge(
        &w.authority.private_str,
        ForgeRequest {
            required_profile: "registry_backed".into(),
            ..mandate("registered", "read_file", "read", 60, 3)
        },
    );
    let args = json!({"path": "/projets/acme/x"});
    let header = build_attestation(
        "registered",
        "read_file",
        &args,
        &token,
        &w.agent.private_str,
        None,
    )
    .unwrap();
    for (public, allowed) in [(Some(w.agent.public_str.clone()), true), (None, false)] {
        let mut opts = options();
        opts.resolve_agent_pubkey = Some(Box::new(move |_: &str| public.clone()));
        let result = verify(
            &w.verifier(test_policy(), Some(opts)),
            "read_file",
            args.clone(),
            &biscuit_headers(&token, Some(&header)),
        );
        assert_eq!(result.allow, allowed, "{}", result.reason);
        if !allowed {
            assert!(result.reason.contains("not found"), "{}", result.reason);
        }
    }
}
