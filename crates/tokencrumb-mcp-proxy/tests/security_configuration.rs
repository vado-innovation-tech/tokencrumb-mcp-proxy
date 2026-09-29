//! C-061/063/066/067/068/069: configuration mistakes must fail at the boundary.
//!
//! Ported from `tests/test_security_configuration.py`.

use std::path::PathBuf;

use tokencrumb_mcp_proxy::ErrorKind;
use tokencrumb_mcp_proxy::policy::{load_policy, parse_policy};
use tokencrumb_mcp_proxy::profiles::rank;
use serde_json::{Value, json};

#[test]
fn configuration_mistakes_never_load() {
    let cases = [
        Value::Null,
        json!([]),
        json!({"mode": "enfore"}),
        json!({"mode": null}),
        json!({"deny_unknown_tools": null}),
        json!({"deny_unknown_tools": "false"}),
        json!({"min_profile": "hardened-biscuit-anchored"}),
        json!({"max_ttl_seconds": 3600}),
        json!({"max_ttl": null}),
        json!({"max_ttl": 0}),
        json!({"max_ttl": -1}),
        json!({"max_ttl": true}),
        json!({"clock_skew_seconds": -1}),
        json!({"clock_skew_seconds": true}),
        json!({"limits": {"max_time_ms": 0}}),
        json!({"limits": {"max_fact": 1}}),
        json!({"limits": null}),
        json!({"upstreams": {"{x}": "http://a/mcp"}}),
        json!({"tools": [{"name": "read"}]}),
        json!({"tools": [{"name": "read", "operation": "read", "allow": {"resource_prefix": ""}}]}),
        json!({"tools": [{"name": "read", "operation": "read", "allow": {"budge": 1}}]}),
        json!({"tools": [{"name": "read", "operation": "read", "resource": {"form": "path"}}]}),
        json!({"mcp": {"allow_methods": ["resources/read"]}}),
        json!({"mcp": null}),
    ];
    for raw in cases {
        // Python raised ValueError (or a subclass: resource, duration) for every case.
        let err = parse_policy(&raw).expect_err(&raw.to_string());
        assert!(
            matches!(
                err.kind,
                ErrorKind::Value | ErrorKind::Resource | ErrorKind::Duration
            ),
            "{raw}: {err:?}"
        );
    }
}

#[test]
fn budget_has_a_strict_integer_domain() {
    for value in [json!(-1), json!(true), json!("1"), json!(1.5), Value::Null] {
        let raw =
            json!({"tools": [{"name": "t", "operation": "read", "allow": {"budget": value}}]});
        let err = parse_policy(&raw).expect_err(&value.to_string());
        assert_eq!(err.kind, ErrorKind::Value, "{value}");
    }
}

#[test]
fn valid_configuration_and_explicit_observation_still_load() {
    let p = parse_policy(&json!({"mode": "warn-only", "deny_unknown_tools": false})).unwrap();
    assert_eq!(p.mode, "warn-only");
    assert_eq!(p.max_ttl_seconds, 8 * 3600);
    let policy = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../policy.yaml");
    assert_eq!(load_policy(policy).unwrap().mode, "enforce");
}

#[test]
fn yaml_duplicate_keys_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.yaml");
    std::fs::write(&path, "mode: enforce\nmode: warn-only\n").unwrap();
    let err = load_policy(&path).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Value);
    assert!(err.message.contains("duplicate"), "{}", err.message);
}

#[test]
fn unknown_profile_has_no_fallback_rank() {
    let err = rank("typo").unwrap_err();
    assert_eq!(err.kind, ErrorKind::Value);
    assert!(err.message.contains("unknown"), "{}", err.message);
}
