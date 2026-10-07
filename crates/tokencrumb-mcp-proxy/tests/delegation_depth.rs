//! Depth is a signed bound checked outside Datalog (architecture decision 6).
//!
//! Ported from `tests/test_delegation_depth.py`.

mod common;

use common::proxy::{World, biscuit_headers, forge, mandate, options, test_policy, verify};
use serde_json::json;
use tokencrumb_mcp_proxy::biscuit_ops::{self, Attenuation, ForgeRequest, attenuate};
use tokencrumb_mcp_proxy::verifier::{Decision, Verifier};

fn verifier(w: &World) -> std::sync::Arc<Verifier> {
    w.verifier(test_policy(), Some(options()))
}

fn read(v: &Verifier, token: &str, path: &str) -> Decision {
    verify(
        v,
        "read_file",
        json!({"path": path}),
        &biscuit_headers(token, None),
    )
}

const Q3: &str = "/projects/acme/q3.md";

#[test]
fn forged_token_is_depth_zero() {
    let w = World::new();
    let v = verifier(&w);
    let root = forge(
        &w.authority.private_str,
        ForgeRequest {
            max_delegation_depth: Some(0),
            ..mandate("a", "read_file", "read", 60, 3)
        },
    );
    assert_eq!(biscuit_ops::inspect(&root).unwrap().block_count, 1);
    assert!(read(&v, &root, Q3).allow);
    let child = attenuate(
        &root,
        &w.authority.public_str,
        &Attenuation {
            budget: Some(2),
            ..Default::default()
        },
    )
    .unwrap();
    let denied = read(&v, &child, Q3);
    assert!(
        !denied.allow && denied.reason.contains("depth"),
        "{}",
        denied.reason
    );
}

fn depth_one(w: &World) -> String {
    attenuate(
        &w.native_token(),
        &w.authority.public_str,
        &Attenuation {
            max_delegation_depth: Some(1),
            ..Default::default()
        },
    )
    .unwrap()
}

#[test]
fn attenuation_within_max_depth_is_allowed() {
    let w = World::new();
    assert!(read(&verifier(&w), &depth_one(&w), Q3).allow);
}

#[test]
fn attenuation_beyond_max_depth_is_denied() {
    let w = World::new();
    let depth2 = attenuate(
        &depth_one(&w),
        &w.authority.public_str,
        &Attenuation {
            budget: Some(5),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!read(&verifier(&w), &depth2, Q3).allow);
}

/// A1b: the agent narrows its own token, then cannot reach past the sub-scope.
#[test]
fn intra_holder_attenuation_narrows_then_refuses() {
    let w = World::new();
    let v = verifier(&w);
    let sub = attenuate(
        &w.native_token(),
        &w.authority.public_str,
        &Attenuation {
            resource: Some("/projects/acme/reports/".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(read(&v, &sub, "/projects/acme/reports/2026.md").allow);
    assert!(!read(&v, &sub, Q3).allow);
}
