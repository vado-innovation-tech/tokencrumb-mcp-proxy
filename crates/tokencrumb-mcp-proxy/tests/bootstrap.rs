//! Issuer bootstrap: the exchange response is only a transport; the trust anchor is
//! provisioned beforehand. Ported from the bootstrap part of
//! `tests/test_security_deployment.py`, plus the `bootstrap` subcommand that replaces
//! Issuer responses are validated before accepting a capability token.

mod common;

use common::{TEST_AUDIENCE, bm, stderr};
use serde_json::json;
use tokencrumb_mcp_proxy::biscuit_ops::{self as ops, ForgeRequest};
use tokencrumb_mcp_proxy::bootstrap::{accept_exchange, validate_issuer_url};
use tokencrumb_mcp_proxy::keys::{biscuit_keypair, generate_keypair};

fn mandate(private: &str) -> String {
    ops::forge(
        private,
        &ForgeRequest {
            agent_id: "agent-1".into(),
            tool: "read_file".into(),
            ttl_seconds: 3600,
            resource_prefix: Some("/projects/acme/".into()),
            audience: TEST_AUDIENCE.into(),
            ..Default::default()
        },
    )
    .unwrap()
}

#[test]
fn issuer_bootstrap_refuses_insecure_or_ambiguous_urls() {
    for bad in [
        "http://issuer.example",
        "ftp://127.0.0.1",
        "https://user:secret@issuer",
        "https://issuer/#key",
        "https://",
        "https:issuer",
    ] {
        assert!(validate_issuer_url(bad).is_err(), "{bad}");
    }
    for good in [
        "https://issuer.example",
        "http://127.0.0.1:8080",
        "http://localhost:8080/realms/x",
        "http://[::1]:8080",
        "HTTPS://Issuer.Example/",
    ] {
        validate_issuer_url(good).unwrap_or_else(|e| panic!("{good}: {}", e.message));
    }
    assert_eq!(
        validate_issuer_url("http://issuer.example")
            .unwrap_err()
            .message,
        "issuer credentials require HTTPS outside loopback"
    );
    assert_eq!(
        validate_issuer_url("https://u:p@issuer")
            .unwrap_err()
            .message,
        "invalid issuer URL"
    );
}

#[test]
fn exchange_cannot_replace_the_preprovisioned_trust_anchor() {
    let authority = generate_keypair();
    let attacker = generate_keypair();
    let token = mandate(&authority.private_str);
    let raw = json!({"biscuit": token}).to_string();
    assert_eq!(
        accept_exchange(raw.as_bytes(), &authority.public_str).unwrap(),
        token
    );
    assert!(accept_exchange(raw.as_bytes(), &attacker.public_str).is_err());
}

/// An OIDC token response from the Keycloak mapper: the mandate rides in the access
/// token's `biscuit` claim, and is held to exactly the same trust anchor.
fn oidc_response(claims: serde_json::Value) -> String {
    use base64::Engine as _;
    let b64 = |v: serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
    };
    let jwt = format!(
        "{}.{}.c2ln",
        b64(json!({"alg": "RS256", "typ": "JWT"})),
        b64(claims)
    );
    json!({"access_token": jwt, "token_type": "DPoP", "expires_in": 7200}).to_string()
}

#[test]
fn oidc_response_yields_the_claimed_mandate_under_the_same_anchor() {
    let authority = generate_keypair();
    let attacker = generate_keypair();
    let token = mandate(&authority.private_str);
    let raw = oidc_response(json!({"sub": "u", "biscuit": token}));
    assert_eq!(
        accept_exchange(raw.as_bytes(), &authority.public_str).unwrap(),
        token
    );
    // An issuer, or anyone on the path, cannot substitute its own mandate.
    let forged = oidc_response(json!({"biscuit": mandate(&attacker.private_str)}));
    assert!(accept_exchange(forged.as_bytes(), &authority.public_str).is_err());
    // No claim, or a token that is not a JWT, is not a mandate.
    for raw in [
        oidc_response(json!({"sub": "u"})),
        json!({"access_token": "opaque"}).to_string(),
        json!({"access_token": "a.!!.c"}).to_string(),
    ] {
        assert_eq!(
            accept_exchange(raw.as_bytes(), &authority.public_str)
                .unwrap_err()
                .message,
            "invalid issuer response",
            "{raw}"
        );
    }
}

#[test]
fn a_malformed_or_unbounded_response_is_refused() {
    let authority = generate_keypair();
    for raw in [&b"[]"[..], b"{\"biscuit\": 1}", b"{}", b"not json"] {
        assert!(accept_exchange(raw, &authority.public_str).is_err());
    }
    assert_eq!(
        accept_exchange(b"{\"token\": \"x\"}", &authority.public_str)
            .unwrap_err()
            .message,
        "invalid issuer response"
    );
    // A validly signed mandate that carries no expiry is not accepted.
    let unbounded = biscuit_auth::Biscuit::builder()
        .code("right(\"read_file\", \"read\");")
        .unwrap()
        .build(&biscuit_keypair(&authority.private_str).unwrap())
        .unwrap()
        .to_base64()
        .unwrap();
    let raw = json!({"biscuit": unbounded}).to_string();
    assert_eq!(
        accept_exchange(raw.as_bytes(), &authority.public_str)
            .unwrap_err()
            .message,
        "issuer did not sign expires_at"
    );
}

#[test]
fn cli_bootstrap_checks_the_url_and_writes_only_a_verified_mandate() {
    let dir = tempfile::tempdir().unwrap();
    let authority = common::keyfiles(dir.path(), "authority");
    let attacker = generate_keypair();

    assert!(
        bm(dir.path(), &["bootstrap", "--url", "https://kc.example"])
            .status
            .success()
    );
    let refused = bm(dir.path(), &["bootstrap", "--url", "http://kc.example"]);
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(
        stderr(&refused).trim(),
        "error: issuer credentials require HTTPS outside loopback"
    );

    let token = mandate(&authority.private_str);
    std::fs::write(
        dir.path().join("response.json"),
        json!({"biscuit": token}).to_string(),
    )
    .unwrap();
    let args = [
        "bootstrap",
        "--authority-pub",
        "authority.pub",
        "--response",
        "response.json",
        "--out",
        "mandate.b64",
    ];
    let output = bm(dir.path(), &args);
    assert!(output.status.success(), "{}", stderr(&output));
    let written = dir.path().join("mandate.b64");
    assert_eq!(
        std::fs::read_to_string(&written).unwrap(),
        format!("{token}\n")
    );
    use std::os::unix::fs::PermissionsExt as _;
    assert_eq!(
        std::fs::metadata(&written).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // A mandate signed by anyone else never reaches the output file.
    let forged = mandate(&attacker.private_str);
    std::fs::write(
        dir.path().join("response.json"),
        json!({"biscuit": forged}).to_string(),
    )
    .unwrap();
    std::fs::remove_file(&written).unwrap();
    let output = bm(dir.path(), &args);
    assert_eq!(output.status.code(), Some(1));
    assert!(!written.exists());

    let output = bm(
        dir.path(),
        &["bootstrap", "--response", "response.json", "--out", "m"],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("--authority-pub"));
}
