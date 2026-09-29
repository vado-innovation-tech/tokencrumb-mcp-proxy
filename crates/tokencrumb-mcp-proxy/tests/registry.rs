//! The agent registry (profile 3a): signed records, the store, the HTTP write path and
//! the proxy-side resolver.
//!
//! Ported from `tests/adversarial/test_registry_writes.py` and the registry parts of
//! `tests/test_security_lifecycle.py`. In 3a the proxy trusts whatever public key this
//! directory returns, so a write is an identity assertion: before the write path was
//! gated, reaching the registry was enough to become any agent.

mod common;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tokencrumb_mcp_proxy::ErrorKind;
use tokencrumb_mcp_proxy::keys::generate_keypair;
use tokencrumb_mcp_proxy::registry::{
    Store, create_registry_app, registry_resolver, signed_record, verify_record,
};
use common::stub::{self, StubResponse};
use common::{golden, key};
use serde_json::{Map, Value, json};
use tower::ServiceExt as _;

const TOKEN: &str = "s3cret-write-token";

fn attacker_key() -> String {
    format!("ed25519/{}", "aa".repeat(32))
}

fn real_key() -> String {
    format!("ed25519/{}", "bb".repeat(32))
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn object(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

// --------------------------------------------------------------------------- //
// Golden record (signed by the former implementation)
// --------------------------------------------------------------------------- //

#[test]
fn python_signed_record_verifies_and_is_reproduced() {
    let corpus = golden("registry.json");
    let record = &corpus["record"];
    let public = corpus["public"].as_str().unwrap();
    let now = corpus["now"].as_i64().unwrap();

    let (agent_key, expires, seq) =
        verify_record(record, "agent-reg", public, Some(now as f64)).unwrap();
    assert_eq!(
        json!([agent_key, expires as i64, seq as i64]),
        corpus["verify"]["ok"]
    );

    // Same key, same fields, same instant: Ed25519 is deterministic, so our record is
    // the one Python served, signature included.
    let ours = signed_record(
        "agent-reg",
        &object(json!({
            "agent_pubkey": record["agent_pubkey"],
            "status": "active",
            "owner_ref": "team-a",
            "seq": 12,
        })),
        &key("registry", "private"),
        Some(now),
    )
    .unwrap();
    assert_eq!(&ours, record);

    // Outside its 30-second window, under another key or for another agent: refused.
    assert!(verify_record(record, "agent-reg", public, Some((now + 31) as f64)).is_err());
    assert!(
        verify_record(
            record,
            "agent-reg",
            &key("authority", "public"),
            Some(now as f64)
        )
        .is_err()
    );
    assert!(verify_record(record, "agent-other", public, Some(now as f64)).is_err());
}

// --------------------------------------------------------------------------- //
// Signed records
// --------------------------------------------------------------------------- //

#[test]
fn registry_signature_identity_and_freshness() {
    let authority = generate_keypair();
    let agent = generate_keypair();
    let doc = signed_record(
        "alice",
        &object(json!({
            "agent_pubkey": agent.public_str, "status": "active", "seq": 1, "owner_ref": null,
        })),
        &authority.private_str,
        Some(100),
    )
    .unwrap();
    assert_eq!(
        verify_record(&doc, "alice", &authority.public_str, Some(101.0))
            .unwrap()
            .0,
        agent.public_str
    );
    for patch in [
        json!({"agent_id": "bob"}),
        json!({"agent_pubkey": generate_keypair().public_str}),
        json!({"status": "suspended"}),
        json!({"signature": "AA=="}),
        json!({"version": null}),
    ] {
        let mut tampered = doc.as_object().unwrap().clone();
        for (k, v) in patch.as_object().unwrap() {
            tampered.insert(k.clone(), v.clone());
        }
        assert!(
            verify_record(
                &Value::Object(tampered),
                "alice",
                &authority.public_str,
                Some(101.0)
            )
            .is_err(),
            "{patch}"
        );
    }
    let stale = verify_record(&doc, "alice", &authority.public_str, Some(131.0)).unwrap_err();
    assert!(stale.message.contains("stale"), "{}", stale.message);
}

// --------------------------------------------------------------------------- //
// Store
// --------------------------------------------------------------------------- //

#[test]
fn registry_concurrent_writers_preserve_all_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agents");
    let agent = generate_keypair();
    let record =
        object(json!({"agent_pubkey": agent.public_str, "status": "active", "owner_ref": null}));
    let stores: Vec<Arc<Store>> = (0..4).map(|_| Arc::new(Store::new(&path))).collect();
    let handles: Vec<_> = (0..12)
        .map(|i| {
            let store = stores[i % 4].clone();
            let record = record.clone();
            std::thread::spawn(move || store.put(&format!("agent-{i}"), record, false).unwrap())
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
    let stored: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(stored.as_object().unwrap().len(), 12);

    let mut replacement = record.clone();
    replacement.insert("agent_pubkey".into(), json!(generate_keypair().public_str));
    let conflict = stores[0]
        .put("agent-0", replacement.clone(), false)
        .unwrap_err();
    assert!(conflict.is(ErrorKind::Exists));
    stores[0].put("agent-0", replacement.clone(), true).unwrap();
    assert_eq!(
        Store::new(&path).get("agent-0").unwrap().unwrap()["agent_pubkey"],
        replacement["agent_pubkey"]
    );
}

#[test]
fn repeated_registration_preserves_suspension_and_owner() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().join("registry"));
    let agent = generate_keypair();
    store
        .put(
            "alice",
            object(json!({"agent_pubkey": agent.public_str, "status": "suspended", "owner_ref": "admin"})),
            false,
        )
        .unwrap();
    store
        .put(
            "alice",
            object(json!({"agent_pubkey": agent.public_str})),
            false,
        )
        .unwrap();
    let stored = store.get("alice").unwrap().unwrap();
    assert_eq!(stored["status"], "suspended");
    assert_eq!(stored["owner_ref"], "admin");
    store
        .put(
            "alice",
            object(json!({"agent_pubkey": agent.public_str, "status": "active"})),
            false,
        )
        .unwrap();
    assert_eq!(store.get("alice").unwrap().unwrap()["status"], "active");
}

#[test]
fn the_sequence_only_moves_forward() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().join("agents"));
    let record = object(json!({"agent_pubkey": real_key()}));
    store.put("a", record.clone(), false).unwrap();
    let first = store.get("a").unwrap().unwrap()["seq"].as_i64().unwrap();
    store.put("a", record, false).unwrap();
    let second = store.get("a").unwrap().unwrap()["seq"].as_i64().unwrap();
    assert!(second > first);
}

// --------------------------------------------------------------------------- //
// HTTP write path
// --------------------------------------------------------------------------- //

fn app(dir: &std::path::Path) -> (Router, std::path::PathBuf) {
    let path = dir.join("agents.json");
    let app =
        create_registry_app(&path, Some(TOKEN), Some(&generate_keypair().private_str)).unwrap();
    (app, path)
}

async fn post(app: &Router, body: Value, token: Option<&str>) -> (StatusCode, Value) {
    post_raw(app, serde_json::to_vec(&body).unwrap(), token).await
}

async fn post_raw(app: &Router, body: Vec<u8>, token: Option<&str>) -> (StatusCode, Value) {
    let mut request = Request::post("/agents").header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn get(app: &Router, uri: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(Request::get(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[test]
fn an_unauthenticated_registry_cannot_be_built() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_keypair().private_str;
    for bad in [None, Some(""), Some("   ")] {
        let error = create_registry_app(dir.path().join("a.json"), bad, Some(&key)).unwrap_err();
        assert!(error.message.contains("write token"), "{}", error.message);
    }
    let error = create_registry_app(dir.path().join("a.json"), Some(TOKEN), None).unwrap_err();
    assert!(error.message.contains("signing key"));
}

#[tokio::test]
async fn registering_without_a_token_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (app, path) = app(dir.path());
    let (status, body) = post(
        &app,
        json!({"agent_id": "agent-1", "agent_pubkey": real_key()}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"error": "unauthorized"}));
    assert!(!path.exists());
}

#[tokio::test]
async fn registering_with_a_wrong_token_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (app, path) = app(dir.path());
    let (status, _) = post(
        &app,
        json!({"agent_id": "agent-1", "agent_pubkey": real_key()}),
        Some("nope"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!path.exists());
}

/// The takeover: same agent_id, attacker's key, valid credential.
#[tokio::test]
async fn a_registered_key_is_never_silently_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let (app, path) = app(dir.path());
    let (status, body) = post(
        &app,
        json!({"agent_id": "agent-1", "agent_pubkey": real_key()}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"ok": true, "agent_id": "agent-1"}));

    let (status, body) = post(
        &app,
        json!({"agent_id": "agent-1", "agent_pubkey": attacker_key()}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body,
        json!({"error": "key replacement requires replace_key=true"})
    );

    let stored: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(stored["agent-1"]["agent_pubkey"], json!(real_key()));

    // An explicit rotation is still possible.
    let (status, _) = post(
        &app,
        json!({"agent_id": "agent-1", "agent_pubkey": attacker_key(), "replace_key": true}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

/// Replaying an unchanged registration must not be an error — only a CHANGE is.
#[tokio::test]
async fn re_registering_the_same_key_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _) = app(dir.path());
    let body = json!({"agent_id": "agent-1", "agent_pubkey": real_key()});
    assert_eq!(
        post(&app, body.clone(), Some(TOKEN)).await.0,
        StatusCode::OK
    );
    assert_eq!(post(&app, body, Some(TOKEN)).await.0, StatusCode::OK);
}

/// Resolution is what the proxy does on the decision path; only writes are gated.
#[tokio::test]
async fn the_read_path_stays_open() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _) = app(dir.path());
    post(
        &app,
        json!({"agent_id": "agent-1", "agent_pubkey": real_key()}),
        Some(TOKEN),
    )
    .await;
    let (status, body) = get(&app, "/agents/agent-1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["agent_pubkey"], json!(real_key()));
    assert_eq!(body["domain"], "biscuitmcp/agent-registry");
    assert_eq!(
        get(&app, "/healthz").await,
        (StatusCode::OK, json!({"status": "ok"}))
    );
}

#[tokio::test]
async fn a_revoked_agent_does_not_resolve() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _) = app(dir.path());
    post(
        &app,
        json!({"agent_id": "agent-1", "agent_pubkey": real_key(), "status": "revoked"}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(get(&app, "/agents/agent-1").await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        get(&app, "/agents/unknown").await,
        (StatusCode::NOT_FOUND, json!({"error": "not found"}))
    );
    assert_eq!(
        get(&app, "/agents/..%2Falice").await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn bad_registry_record_cannot_be_published() {
    let agent = generate_keypair();
    for patch in [
        json!({"agent_id": "../alice"}),
        json!({"agent_pubkey": "ed25519/bad"}),
        json!({"status": null}),
        json!({"status": "actvie"}),
        json!({"replace_key": "true"}),
        json!({"owner_ref": []}),
        json!({"typo": true}),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agents");
        let app = create_registry_app(&path, Some("secret"), Some(&generate_keypair().private_str))
            .unwrap();
        let mut body = object(json!({"agent_id": "alice", "agent_pubkey": agent.public_str}));
        for (k, v) in patch.as_object().unwrap() {
            body.insert(k.clone(), v.clone());
        }
        let (status, response) = post(&app, Value::Object(body), Some("secret")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{patch}");
        assert_eq!(response, json!({"error": "invalid registration"}));
        assert!(!path.exists(), "{patch}");
    }
}

#[tokio::test]
async fn an_oversized_registration_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (app, path) = app(dir.path());
    let (status, body) = post_raw(&app, vec![b' '; 9000], Some(TOKEN)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body, json!({"error": "too large"}));
    assert!(!path.exists());
}

// --------------------------------------------------------------------------- //
// Resolver
// --------------------------------------------------------------------------- //

#[test]
fn registry_resolver_does_not_trust_unsigned_or_oversize_http() {
    let authority = generate_keypair();
    let agent = generate_keypair();
    let unsigned = json!({"agent_id": "alice", "agent_pubkey": agent.public_str});
    let server = stub::serve(move |_| StubResponse::json(&unsigned));
    let resolve = registry_resolver(&server.url, &authority.public_str, 2).unwrap();
    assert!(resolve("../alice").is_none());
    assert!(
        server.calls().is_empty(),
        "an invalid name never reaches the network"
    );
    assert!(resolve("alice").is_none());
    assert_eq!(server.calls()[0].path, "/agents/alice");

    let huge = format!("{{\"pad\": \"{}\"}}", "x".repeat(9000));
    let server = stub::serve(move |_| StubResponse::new(200, "application/json", huge.clone()));
    let resolve = registry_resolver(&server.url, &authority.public_str, 2).unwrap();
    assert!(resolve("alice").is_none());
}

#[test]
fn the_resolver_caches_until_expiry_and_refuses_rollback() {
    let registry = generate_keypair();
    let agent = generate_keypair();
    let private = registry.private_str.clone();
    let key = agent.public_str.clone();
    let served = Arc::new(std::sync::Mutex::new(Vec::<(i64, i64)>::new()));
    let script = served.clone();
    // Each call pops (seq, issued_at offset) — a record valid for one more second.
    let server = stub::serve(move |_| {
        let (seq, offset) = script.lock().unwrap().remove(0);
        let record =
            object(json!({"agent_pubkey": key, "status": "active", "owner_ref": null, "seq": seq}));
        StubResponse::json(
            &signed_record("alice", &record, &private, Some(now() + offset)).unwrap(),
        )
    });
    served.lock().unwrap().extend([(5, -29), (4, -29)]);
    let resolve = registry_resolver(&server.url, &registry.public_str, 16).unwrap();
    assert_eq!(resolve("alice").as_deref(), Some(agent.public_str.as_str()));
    assert_eq!(resolve("alice").as_deref(), Some(agent.public_str.as_str()));
    assert_eq!(
        server.calls().len(),
        1,
        "a fresh record is served from the cache"
    );

    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert!(resolve("alice").is_none(), "a lower seq is a rollback");
    assert_eq!(server.calls().len(), 2);
}

#[test]
fn the_resolver_follows_no_redirect_and_reuses_no_expired_entry() {
    let registry = generate_keypair();
    let server = stub::serve(|_| {
        StubResponse::new(302, "text/plain", "")
            .header("Location", "http://127.0.0.1:1/agents/alice")
    });
    let resolve = registry_resolver(&server.url, &registry.public_str, 4).unwrap();
    assert!(resolve("alice").is_none());
    assert_eq!(server.calls().len(), 1);

    let server = stub::serve(|_| StubResponse::new(500, "text/plain", "boom"));
    let resolve = registry_resolver(&server.url, &registry.public_str, 4).unwrap();
    assert!(resolve("alice").is_none());
    assert!(registry_resolver(&server.url, "ed25519/bad", 4).is_err());
    assert!(registry_resolver(&server.url, &registry.public_str, 0).is_err());
}

/// End to end: the registry application, served, and the resolver in front of it.
#[test]
fn a_live_registry_resolves_what_was_registered() {
    let dir = tempfile::tempdir().unwrap();
    let signing = generate_keypair();
    let agent = generate_keypair();
    let app = create_registry_app(
        dir.path().join("agents.json"),
        Some(TOKEN),
        Some(&signing.private_str),
    )
    .unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    runtime.spawn(async move { axum::serve(listener, app).await.unwrap() });

    let resolve = registry_resolver(&url, &signing.public_str, 4).unwrap();
    assert!(resolve("alice").is_none());
    let response = ureq::post(&format!("{url}/agents"))
        .set("authorization", &format!("Bearer {TOKEN}"))
        .set("content-type", "application/json")
        .send_string(
            &json!({
                "agent_id": "alice",
                "agent_pubkey": agent.public_str.to_uppercase().replace("ED25519/", "ed25519/"),
            })
            .to_string(),
        )
        .unwrap();
    assert_eq!(response.status(), 200);
    // The registry stores the normalized (lowercase) key and the resolver returns it.
    assert_eq!(resolve("alice").as_deref(), Some(agent.public_str.as_str()));
    // Another registry key is not trusted.
    let other = registry_resolver(&url, &generate_keypair().public_str, 4).unwrap();
    assert!(other("alice").is_none());
}
