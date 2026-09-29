//! Local checks of deployment artifacts and real transport integration.
//!
//! Ported from `tests/test_security_deployment.py`. The issuer bootstrap and CLI
//! wiring cases belong to the CLI port; the Kubernetes rendering case tests a Python
//! deployment script, not this crate.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Once};
use std::time::Duration;

use axum::http::StatusCode;
use tokencrumb_mcp_proxy::ErrorKind;
use tokencrumb_mcp_proxy::policy::{PolicyReloader, load_policy};
use tokencrumb_mcp_proxy::proxy::runtime::{ServeOptions, build_config};
use tokencrumb_mcp_proxy::proxy::upstream::{ForwardHeaders, HttpUpstream, SharedUpstream, Upstream};
use tokencrumb_mcp_proxy::storage::write_secure;
use bytes::Bytes;
use common::proxy::{Canned, Recorded, RecordingServer, World, post, test_policy};
use serde_json::{Value, json};

const UP_API: &str = "TOKENCRUMB_TEST_UP_API";
const ALICE_AUTH: &str = "TOKENCRUMB_TEST_ALICE_AUTH";

/// The credential variables, set once before any test reads the environment.
fn environment() {
    static SET: Once = Once::new();
    SET.call_once(|| {
        // SAFETY: runs once, before any test of this binary reads these variables.
        unsafe {
            std::env::set_var(UP_API, "secret-value");
            std::env::set_var(ALICE_AUTH, "Bearer alice");
        }
    });
}

#[test]
fn only_atomic_policy_publication_can_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy");
    std::fs::write(&path, "min_profile: hardened_biscuit_anchored\n").unwrap();
    let reload = PolicyReloader::new(
        &path,
        load_policy(&path).unwrap(),
        Duration::ZERO,
        Box::new(|_, _| {}),
    );
    std::fs::write(&path, "min_profile: native\n").unwrap(); // in place
    assert_eq!(reload.current().min_profile, "hardened_biscuit_anchored");
    write_secure(&path, b"min_profile: native\n").unwrap(); // atomic replacement
    assert_eq!(reload.current().min_profile, "native");
}

fn config_files(w: &World, upstream: &str) -> ServeOptions {
    let dir = w.dir.path();
    std::fs::write(dir.join("authority.pub"), &w.authority.public_str).unwrap();
    std::fs::write(dir.join("audit.key"), &w.audit_key.private_str).unwrap();
    std::fs::write(
        dir.join("policy.yaml"),
        "tools:\n- name: read_file\n  operation: read\n",
    )
    .unwrap();
    ServeOptions {
        authority_pub: dir.join("authority.pub"),
        policy: dir.join("policy.yaml"),
        audience: "test-gateway".into(),
        upstream: Some(upstream.into()),
        audit: dir.join("audit"),
        audit_key: Some(dir.join("audit.key")),
        budget_state: Some(dir.join("budget")),
        freshness: 60,
        ..Default::default()
    }
}

fn only_upstream(options: &ServeOptions) -> SharedUpstream {
    let runtime = build_config(options).unwrap();
    runtime.config.upstreams[0].1.clone()
}

#[tokio::test]
async fn runtime_applies_and_reapplies_cli_overrides() {
    let w = World::new();
    let options = ServeOptions {
        reload_policy: true,
        mode: Some("enforce".into()),
        min_profile: Some("hardened_biscuit_anchored".into()),
        ..config_files(&w, "https://upstream/custom")
    };
    let runtime = build_config(&options).unwrap();
    let verifier = runtime.config.verifier.clone();
    let before = verifier.policy();
    write_secure(
        w.dir.path().join("policy.yaml"),
        b"mode: warn-only\nmin_profile: native\ntools: []\n",
    )
    .unwrap();
    // The reloader re-reads at most every 2 s; Python patched the monotonic clock.
    std::thread::sleep(Duration::from_millis(2100));
    let after = verifier.policy();
    assert_eq!(after.tools.len(), 0, "the edit was reloaded");
    assert_eq!(after.mode, "enforce");
    assert_eq!(after.min_profile, "hardened_biscuit_anchored");
    assert_ne!(before.policy_digest, after.policy_digest);
    // The replay store lives next to the budget state.
    assert!(w.dir.path().join("budget.nonces.db").is_file());
    tokencrumb_mcp_proxy::proxy::app::close_upstreams(&runtime.config.upstreams).await;
}

fn echo_ok(request: &Recorded) -> Canned {
    let id = serde_json::from_slice::<Value>(&request.body)
        .ok()
        .and_then(|m| m.get("id").cloned())
        .unwrap_or(Value::Null);
    Canned::json(200, json!({"jsonrpc": "2.0", "id": id, "result": {}}))
}

/// Python read the configured header off the transport object; here the upstream is a
/// real server, and the header is observed where it lands.
#[tokio::test]
async fn runtime_credentials_are_explicit_environment_references() {
    environment();
    let server = RecordingServer::start(echo_ok).await;
    let w = World::new();
    let opts = config_files(&w, &server.url("/mcp"));
    let upstream = only_upstream(&ServeOptions {
        upstream_header: vec![format!("X-API-Key={UP_API}")],
        ..opts.clone()
    });
    upstream
        .forward(
            "POST",
            Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#),
            &ForwardHeaders::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        server.requests()[0].header("x-api-key"),
        Some("secret-value")
    );
    upstream.close().await;

    let err = build_config(&ServeOptions {
        upstream_header: vec!["X-API-Key=TOKENCRUMB_TEST_MISSING_ENV".into()],
        ..opts.clone()
    })
    .err()
    .expect("a missing credential variable was accepted");
    assert!(
        err.message.contains("missing credential"),
        "{}",
        err.message
    );
    let err = build_config(&ServeOptions {
        registry: Some("https://registry".into()),
        ..opts
    })
    .err()
    .expect("an unauthenticated registry was accepted");
    assert!(err.message.contains("registry-pub"), "{}", err.message);
}

/// An MCP server behind an API-key boundary: 401 without the key, and a minimal
/// Streamable HTTP responder with it.
fn protected_mcp(secret: &'static str) -> impl Fn(&Recorded) -> Canned + Send + Sync {
    move |request| {
        if request.header("x-api-key") != Some(secret) {
            return Canned::json(401, json!({"error": "unauthorized"}));
        }
        let message: Value = serde_json::from_slice(&request.body).unwrap();
        let Some(id) = message.get("id").cloned() else {
            return Canned::raw(202, &[], b"");
        };
        let result = match message["method"].as_str() {
            Some("initialize") => json!({
                "protocolVersion": message["params"]["protocolVersion"],
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "catalog", "version": "1"},
            }),
            Some("tools/list") => json!({"tools": [{"name": "search_objects"}]}),
            _ => json!({}),
        };
        Canned::json(200, json!({"jsonrpc": "2.0", "id": id, "result": result}))
    }
}

/// Python drove the real `mcp` client SDK against the Python Catalog mock behind its
/// API-key boundary. No Rust MCP client or mock exists yet, so this runs the same
/// sequence (direct refusals, then initialize / initialized / tools/list through the
/// gateway over a real socket) against a minimal protected server.
#[tokio::test]
async fn mcp_session_negotiates_through_gateway_and_real_upstream_auth() {
    let secret = "test-only-upstream-secret";
    let server = RecordingServer::start(protected_mcp(secret)).await;
    let ping = Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#);
    for bad in [None, Some("bad")] {
        let headers = bad
            .map(|b| vec![("x-api-key".to_owned(), b.to_owned())])
            .unwrap_or_default();
        let direct = HttpUpstream::new(&server.url("/mcp"), headers).unwrap();
        let response = direct
            .forward("POST", ping.clone(), &ForwardHeaders::default())
            .await
            .unwrap();
        assert_eq!(response.status, 401, "{bad:?}");
    }
    let up = HttpUpstream::new(
        &server.url("/mcp"),
        vec![("X-API-Key".into(), secret.into())],
    )
    .unwrap();
    let w = World::new();
    let app = w.proxy_with(
        vec![(None, Arc::new(up) as SharedUpstream)],
        Some("enforce"),
        w.verifier(test_policy(), None),
        true,
    );
    let init = post(
        &app,
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                          "clientInfo": {"name": "test", "version": "1"}}}),
        &[],
    )
    .await;
    assert_eq!(init.status, StatusCode::OK);
    assert_eq!(
        init.json()["result"]["protocolVersion"],
        json!("2025-06-18")
    );
    let notified = post(
        &app,
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        &[("mcp-protocol-version", "2025-06-18")],
    )
    .await;
    assert_eq!(notified.status, StatusCode::ACCEPTED);
    let tools = post(
        &app,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        &[("mcp-protocol-version", "2025-06-18")],
    )
    .await;
    // The test policy has no Catalog tool mapped.
    assert_eq!(tools.json()["result"]["tools"], json!([]));
}

fn write_json(path: &Path, value: &Value) {
    std::fs::write(path, value.to_string()).unwrap();
}

/// Python compared the transport's private credential map; here the credential is
/// observed on the wire for the verified principal, and refused for any other.
#[tokio::test]
async fn runtime_user_credentials_file_is_validated_and_enables_identity_binding() {
    environment();
    let server = RecordingServer::start(echo_ok).await;
    let w = World::new();
    let opts = config_files(&w, &server.url("/mcp"));
    let path: PathBuf = w.dir.path().join("users.json");
    let record = json!({
        "upstream": null,
        "issuer": "iam",
        "subject": "alice",
        "header": "Authorization",
        "env": ALICE_AUTH,
    });
    write_json(&path, &json!([record]));
    let with_file = ServeOptions {
        upstream_user_credentials: Some(path.clone()),
        ..opts
    };
    let upstream = only_upstream(&with_file);
    assert!(upstream.requires_user_credentials());
    let as_user = |subject: &str| ForwardHeaders {
        incoming: Default::default(),
        principal: Some((Some("iam".into()), Some(subject.into()))),
    };
    let body = Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#);
    upstream
        .forward("POST", body.clone(), &as_user("alice"))
        .await
        .unwrap();
    assert_eq!(
        server.requests()[0].header_all("authorization"),
        vec!["Bearer alice"]
    );
    let err = upstream
        .forward("POST", body, &as_user("bob"))
        .await
        .unwrap_err();
    assert!(
        err.message.contains("no upstream credential"),
        "{}",
        err.message
    );
    assert_eq!(server.requests().len(), 1);
    upstream.close().await;

    let with = |patch: Value| {
        let mut r = record.clone();
        for (k, v) in patch.as_object().unwrap() {
            r[k] = v.clone();
        }
        r
    };
    for bad in [
        json!([]),
        json!({}),
        json!([record, record]),
        json!([with(json!({"header": "Cookie"}))]),
        json!([with(json!({"env": "TOKENCRUMB_TEST_ABSENT_CREDENTIAL"}))]),
        json!([with(json!({"upstream": "unknown"}))]),
        json!([with(json!({"subjet": "typo"}))]),
    ] {
        write_json(&path, &bad);
        let err = build_config(&with_file)
            .err()
            .unwrap_or_else(|| panic!("{bad} accepted"));
        assert_eq!(err.kind, ErrorKind::Value, "{bad}: {}", err.message);
    }
}
