//! JCS canonicalization + resource canonicalization (traversal defense).
//!
//! Ported from `tests/test_canonical.py`.

use tokencrumb_mcp_proxy::ErrorKind;
use tokencrumb_mcp_proxy::canonical::{
    arguments_hash, canonicalize, canonicalize_prefix, canonicalize_resource,
};
use tokencrumb_mcp_proxy::json::strict_json;
use serde_json::json;

#[test]
fn jcs_key_order_independent() {
    assert_eq!(
        canonicalize(&json!({"b": 1, "a": 2})).unwrap(),
        canonicalize(&json!({"a": 2, "b": 1})).unwrap()
    );
    assert_eq!(
        arguments_hash(&json!({"b": 1, "a": 2})).unwrap(),
        arguments_hash(&json!({"a": 2, "b": 1})).unwrap()
    );
}

/// RFC 8785: sorted keys, no whitespace, minimal number forms.
#[test]
fn jcs_known_vector() {
    assert_eq!(
        canonicalize(&json!({"a": 1, "c": 3, "b": 2})).unwrap(),
        br#"{"a":1,"b":2,"c":3}"#
    );
    // array order preserved
    assert_eq!(
        canonicalize(&json!({"x": [3, 1, 2]})).unwrap(),
        br#"{"x":[3,1,2]}"#
    );
}

#[test]
fn arguments_hash_includes_business_fields() {
    assert_ne!(
        arguments_hash(&json!({"path": "/x", "_meta": {"t": 1}})).unwrap(),
        arguments_hash(&json!({"path": "/x"})).unwrap()
    );
}

/// NaN / Infinity can never be canonicalized. A `serde_json::Value` cannot hold a
/// non-finite number at all, so the refusal lives where such a value would enter: the
/// strict JSON decoder that feeds canonicalization.
#[test]
fn nan_infinity_rejected() {
    for raw in [
        r#"{"x": NaN}"#,
        r#"{"x": Infinity}"#,
        r#"{"x": -Infinity}"#,
        r#"{"x": 1e999}"#,
    ] {
        assert!(strict_json(raw).is_err(), "{raw}");
    }
    assert_eq!(
        tokencrumb_mcp_proxy::json::float(f64::NAN),
        serde_json::Value::Null,
        "no JSON number exists for NaN"
    );
}

#[test]
fn resource_percent_decoding() {
    assert_eq!(
        canonicalize_resource("/projets/%61cme/x").unwrap(),
        "/projets/acme/x"
    );
}

/// `..` resolved; the result is a clean absolute path that a prefix check will reject.
#[test]
fn resource_traversal_normalized_then_out_of_scope() {
    assert_eq!(
        canonicalize_resource("/projets/acme/../globex/x").unwrap(),
        "/projets/globex/x"
    );
    assert_eq!(
        canonicalize_resource("/projets/%2e%2e/etc/passwd").unwrap(),
        "/etc/passwd"
    );
}

#[test]
fn relative_traversal_rejected() {
    let err = canonicalize_resource("../../etc/passwd").unwrap_err();
    assert_eq!(err.kind, ErrorKind::Resource);
}

#[test]
fn null_byte_rejected() {
    let err = canonicalize_resource("/projets/acme/\u{0}evil").unwrap_err();
    assert_eq!(err.kind, ErrorKind::Resource);
}

/// Boundary safety: `/projets/acme/` must not match `/projets/acme2`.
#[test]
fn prefix_keeps_trailing_slash_boundary() {
    let prefix = canonicalize_prefix("/projets/acme/").unwrap();
    assert_eq!(prefix, "/projets/acme/");
    assert!(
        !canonicalize_resource("/projets/acme2/x")
            .unwrap()
            .starts_with(&prefix)
    );
    assert!(
        canonicalize_resource("/projets/acme/x")
            .unwrap()
            .starts_with(&prefix)
    );
}
