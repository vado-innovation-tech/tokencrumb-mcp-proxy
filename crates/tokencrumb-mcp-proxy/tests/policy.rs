//! policy.yaml parsing + resource extraction.
//!
//! Ported from `tests/test_policy.py`.

use serde_json::json;
use tokencrumb_mcp_proxy::ErrorKind;
use tokencrumb_mcp_proxy::policy::{extract_resource, parse_policy};

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
            "allow": {"resource_prefix": "/projects/acme/", "budget": 200},
            "require": ["call_signature_valid"],
        }],
    }))
    .unwrap();
    assert!(!pol.deny_unknown_tools);
    assert_eq!(pol.mode, "warn-only");
    assert_eq!(pol.min_profile, "hardened_biscuit_anchored");
    let tp = pol.tool("read_file").unwrap();
    assert_eq!(tp.operation, "read");
    assert_eq!(tp.resource_prefix.as_deref(), Some("/projects/acme/"));
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

// -- Code Mode: tools_list and flows (ADR 0007) ------------------------------------------

fn two_upstreams(
    extra: serde_json::Value,
) -> tokencrumb_mcp_proxy::Result<tokencrumb_mcp_proxy::policy::Policy> {
    let mut raw =
        json!({"upstreams": {"a": "http://a/mcp", "b": "http://b/mcp", "c": "http://c/mcp"}});
    for (key, value) in extra.as_object().unwrap() {
        raw[key] = value.clone();
    }
    parse_policy(&raw)
}

#[test]
fn tools_list_defaults_to_declared_and_accepts_granted() {
    assert_eq!(two_upstreams(json!({})).unwrap().tools_list, "declared");
    assert_eq!(
        two_upstreams(json!({"tools_list": "granted"}))
            .unwrap()
            .tools_list,
        "granted"
    );
    assert!(two_upstreams(json!({"tools_list": "some"})).is_err());
}

#[test]
fn flows_resolve_deny_over_allow_over_default() {
    let flows = two_upstreams(json!({"flows": {
        "default": "deny",
        "allow": [{"from": "a", "to": "b"}, {"from": "b", "to": "c"}],
    }}))
    .unwrap()
    .flows;
    assert!(flows.permits("a", "b"));
    assert!(!flows.permits("b", "a"));
    assert!(flows.permits("c", "c"), "an upstream always reaches itself");
    let touched = ["a".to_owned(), "b".to_owned()];
    assert_eq!(flows.violation(&touched, "c"), Some(&touched[0]));
    let flows = two_upstreams(json!({"flows": {"deny": [{"from": "a", "to": "c"}]}}))
        .unwrap()
        .flows;
    assert!(flows.permits("a", "b") && !flows.permits("a", "c") && flows.permits("c", "a"));
}

#[test]
fn malformed_flows_are_refused() {
    for flows in [
        json!({"deny": [{"from": "a", "to": "zz"}]}),
        json!({"deny": [{"from": "a", "to": "a"}]}),
        json!({"deny": [{"from": "a", "to": "b"}, {"from": "a", "to": "b"}]}),
        json!({"deny": [{"from": "a", "to": "b"}], "allow": [{"from": "a", "to": "b"}]}),
        json!({"deny": [{"from": "a"}]}),
        json!({"default": "maybe"}),
        json!({"other": []}),
    ] {
        assert!(two_upstreams(json!({"flows": flows})).is_err(), "{flows}");
    }
    let single = parse_policy(&json!({"flows": {"default": "deny"}}));
    assert!(single.is_err(), "flows need named upstreams");
}
