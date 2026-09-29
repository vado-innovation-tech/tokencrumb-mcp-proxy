//! policy.yaml parsing + resource extraction.
//!
//! Ported from `tests/test_policy.py`.

use tokencrumb_mcp_proxy::ErrorKind;
use tokencrumb_mcp_proxy::policy::{extract_resource, parse_policy};
use serde_json::json;

#[test]
fn parse_and_canonicalize_prefix() {
    let pol = parse_policy(&json!({
        "deny_unknown_tools": false,
        "mode": "warn-only",
        "min_profile": "hardened_biscuit_anchored",
        "tools": [{
            "name": "read_file",
            "operation": "read",
            "resource": {"from": "arguments.path"},
            "allow": {"resource_prefix": "/projets/acme/", "budget": 200},
            "require": ["call_signature_valid"],
        }],
    }))
    .unwrap();
    assert!(!pol.deny_unknown_tools);
    assert_eq!(pol.mode, "warn-only");
    assert_eq!(pol.min_profile, "hardened_biscuit_anchored");
    let tp = pol.tool("read_file").unwrap();
    assert_eq!(tp.operation, "read");
    assert_eq!(tp.resource_prefix.as_deref(), Some("/projets/acme/"));
    assert_eq!(tp.budget, Some(200));
    assert_eq!(tp.require, vec!["call_signature_valid"]);
}

#[test]
fn extract_resource_from_arguments() {
    let pol = parse_policy(&json!({
        "tools": [{
            "name": "read_file",
            "operation": "read",
            "resource": {"from": "arguments.path"},
            "allow": {},
        }],
    }))
    .unwrap();
    let tp = pol.tool("read_file").unwrap();
    assert_eq!(
        extract_resource(tp, &json!({"path": "/x/y"})),
        Some(&json!("/x/y"))
    );
    assert_eq!(extract_resource(tp, &json!({})), None);
}

#[test]
fn unknown_require_fact_rejected() {
    let err = parse_policy(&json!({
        "tools": [{"name": "t", "operation": "read", "require": ["not_a_real_proof"]}],
    }))
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Value);
}
