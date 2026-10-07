//! Differential tests on `policy.yaml`: the same text must yield the same policy, or be
//! refused with the same message, as under the former PyYAML-based loader.

mod common;

use common::{assert_outcome, golden};
use serde_json::{Value, json};
use tokencrumb_mcp_proxy::policy::{Policy, parse_policy_text};

fn view(p: &Policy) -> Value {
    let mut tools = serde_json::Map::new();
    for t in &p.tools {
        tools.insert(t.name.clone(), json!({
            "name": t.name, "operation": t.operation, "upstream": t.upstream,
            "upstream_tool": t.upstream_tool, "resource_from": t.resource_from,
            "resource_prefix": t.resource_prefix, "resource_exact": t.resource_exact,
            "budget": t.budget.map(|b| b as i64), "require": t.require,
            "args": t.args.iter().map(|a| json!({"source_key": a.source_key, "name": a.name})).collect::<Vec<_>>(),
        }));
    }
    let upstreams: serde_json::Map<String, Value> = p
        .upstreams
        .iter()
        .map(|(k, v)| (k.clone(), json!(v)))
        .collect();
    json!({
        "deny_unknown_tools": p.deny_unknown_tools, "mode": p.mode, "min_profile": p.min_profile,
        "budget_total": p.budget_total.map(|b| b as i64), "max_ttl_seconds": p.max_ttl_seconds as i64,
        "revocation_path": p.revocation_path, "clock_skew_seconds": p.clock_skew_seconds as i64,
        "limits": {
            "max_facts": p.limits.max_facts as i64, "max_iterations": p.limits.max_iterations as i64,
            "max_time_ms": p.limits.max_time_ms as i64, "max_token_size": p.limits.max_token_size as i64,
        },
        "upstreams": upstreams, "tools": tools,
        "mcp": {"spec_version": p.mcp.spec_version, "allow_methods": p.mcp.allow_methods},
    })
}

#[test]
fn policies_parse_identically() {
    for (name, case) in golden("policies.json").as_object().unwrap() {
        let text = case["text"].as_str().unwrap();
        assert_outcome(name, &case["result"], &parse_policy_text(text), view);
    }
}
