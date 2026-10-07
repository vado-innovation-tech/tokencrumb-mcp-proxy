//! Offline attenuation by tool: the holder keeps a subset of the tools the issuer
//! granted. The proxy publishes the called tool as the context fact `tool(...)`, and the
//! appended block checks it against the kept set. Like every context fact, a token may
//! never declare it itself — otherwise a forged `tool("x")` would satisfy the check.

mod common;

use std::sync::Arc;

use common::proxy::{
    TEST_AUDIENCE, World, append_block, biscuit_headers, build_token, date_term, in_seconds,
    options, str_term, verify,
};
use serde_json::json;
use tokencrumb_mcp_proxy::biscuit_ops::{Attenuation, attenuate};
use tokencrumb_mcp_proxy::policy::parse_policy;
use tokencrumb_mcp_proxy::verifier::{Decision, Verifier};

fn token(w: &World, extra: &str) -> String {
    build_token(
        &w.authority.private_str,
        &format!(
            r#"agent_id("agent-1"); required_profile("native"); audience({{aud}});
               right("read_file", "read"); right("list_dir", "read"); {extra}
               expires_at({{exp}}); check if time($t), $t < {{exp}};"#
        ),
        &[
            ("aud", str_term(TEST_AUDIENCE)),
            ("exp", date_term(in_seconds(3600))),
        ],
    )
}

fn verifier(w: &World) -> Arc<Verifier> {
    let mut p = parse_policy(&json!({
        "min_profile": "native",
        "tools": [
            {"name": "read_file", "operation": "read"},
            {"name": "list_dir", "operation": "read"},
        ],
    }))
    .unwrap();
    p.policy_digest = "d".into();
    w.verifier(p, Some(options()))
}

fn call(v: &Verifier, token: &str, tool: &str) -> Decision {
    verify(v, tool, json!({}), &biscuit_headers(token, None))
}

fn keep(w: &World, token: &str, tools: &[&str]) -> String {
    attenuate(
        token,
        &w.authority.public_str,
        &Attenuation {
            tools: tools.iter().map(|t| t.to_string()).collect(),
            ..Default::default()
        },
    )
    .unwrap()
}

#[test]
fn only_the_kept_tools_remain_callable() {
    let w = World::new();
    let v = verifier(&w);
    let full = token(&w, "");
    assert!(call(&v, &full, "read_file").allow);
    assert!(call(&v, &full, "list_dir").allow);

    let narrowed = keep(&w, &full, &["read_file"]);
    assert!(call(&v, &narrowed, "read_file").allow);
    assert!(!call(&v, &narrowed, "list_dir").allow);
}

/// Each block is checked on its own: two attenuations keep their intersection.
#[test]
fn successive_attenuations_intersect() {
    let w = World::new();
    let v = verifier(&w);
    let both = keep(&w, &token(&w, ""), &["read_file", "list_dir"]);
    let one = keep(&w, &both, &["list_dir", "unknown_tool"]);
    assert!(!call(&v, &one, "read_file").allow);
    assert!(call(&v, &one, "list_dir").allow);
}

/// Keeping a tool never grants it: the issuer's right is still required.
#[test]
fn keeping_a_tool_does_not_grant_it() {
    let w = World::new();
    let v = verifier(&w);
    let full = build_token(
        &w.authority.private_str,
        r#"agent_id("agent-1"); required_profile("native"); audience({aud});
           right("read_file", "read"); expires_at({exp}); check if time($t), $t < {exp};"#,
        &[
            ("aud", str_term(TEST_AUDIENCE)),
            ("exp", date_term(in_seconds(3600))),
        ],
    );
    assert!(!call(&v, &keep(&w, &full, &["list_dir"]), "list_dir").allow);
}

/// `tool` is a context fact: declared by the issuer or by a later block, the whole
/// mandate is refused rather than letting the forged fact satisfy a kept-tools check.
#[test]
fn a_token_may_not_declare_the_tool_fact() {
    let w = World::new();
    let v = verifier(&w);
    let declared = keep(&w, &token(&w, r#"tool("list_dir");"#), &["read_file"]);
    assert!(!call(&v, &declared, "read_file").allow);
    assert!(!call(&v, &declared, "list_dir").allow);

    let narrowed = keep(&w, &token(&w, ""), &["read_file"]);
    let smuggled = append_block(
        &narrowed,
        &w.authority.public_str,
        r#"tool("list_dir");"#,
        &[],
    );
    assert!(!call(&v, &smuggled, "list_dir").allow);
}

#[test]
fn an_empty_tool_name_is_refused() {
    let w = World::new();
    let err = attenuate(
        &token(&w, ""),
        &w.authority.public_str,
        &Attenuation {
            tools: vec!["".into()],
            ..Default::default()
        },
    );
    assert!(err.is_err());
}
