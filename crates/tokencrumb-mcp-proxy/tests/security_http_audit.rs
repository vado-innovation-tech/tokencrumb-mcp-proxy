//! Behavioral regression tests at the actual HTTP, storage and transport boundaries.
//!
//! Ported from `tests/test_security_http_audit.py`. Where the Python suite used
//! `httpx.MockTransport`, these tests run a real HTTP server on `127.0.0.1:0`.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::http::StatusCode;
use tokencrumb_mcp_proxy::ErrorKind;
use tokencrumb_mcp_proxy::audit::{
    AuditLog, Record, TrustedKeys, head_attestation, trusted_from, verify_log,
};
use tokencrumb_mcp_proxy::keys::{generate_keypair, key_id};
use tokencrumb_mcp_proxy::policy::Policy;
use tokencrumb_mcp_proxy::proxy::app::{ProxyConfig, create_app};
use tokencrumb_mcp_proxy::proxy::upstream::{ForwardHeaders, HttpUpstream, SharedUpstream, Upstream};
use tokencrumb_mcp_proxy::verifier::Headers;
use bytes::Bytes;
use common::proxy::{
    Canned, FakeUpstream, RecordingServer, World, audit_entries, bearer, options, post, test_policy,
};
use serde_json::{Value, json};

fn allow() -> Record {
    Record {
        decision: "ALLOW".into(),
        ..Default::default()
    }
}

fn forward_headers(pairs: &[(&str, &str)]) -> ForwardHeaders {
    ForwardHeaders {
        incoming: Headers::new(pairs.iter().copied()),
        principal: None,
    }
}

#[tokio::test]
async fn malformed_calls_are_audited_and_never_forwarded() {
    let cases: [&[u8]; 4] = [
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/bad","path":"/projets/acme/x"}}}"#,
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":false}"#,
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":false}}"#,
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"v":NaN}}}"#,
    ];
    for raw in cases {
        let w = World::new();
        let upstream = FakeUpstream::default_json();
        let app = w.proxy(upstream.clone(), Some("enforce"));
        let token = bearer(&w.native_token());
        post(&app, raw, &[("authorization", &token)]).await;
        let label = String::from_utf8_lossy(raw);
        assert!(!upstream.reached(), "{label}");
        assert_eq!(
            w.audit_entries().last().unwrap()["decision"],
            json!("DENY"),
            "{label}"
        );
    }
}

#[tokio::test]
async fn request_size_limit_is_applied_before_parsing() {
    let w = World::new();
    let upstream = FakeUpstream::default_json();
    let app = w.proxy(upstream.clone(), Some("enforce"));
    let reply = post(&app, vec![b' '; 1024 * 1024 + 1], &[]).await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(!upstream.reached());
}

#[tokio::test]
async fn origin_cannot_cross_the_gateway() {
    let w = World::new();
    let upstream = FakeUpstream::default_json();
    let app = w.proxy(upstream.clone(), Some("enforce"));
    let reply = post(
        &app,
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
        &[("origin", "https://untrusted.example")],
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert!(!upstream.reached());
}

fn read_call(path: Option<&str>) -> Value {
    let arguments = match path {
        Some(p) => json!({"path": p}),
        None => json!({}),
    };
    json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "read_file", "arguments": arguments}})
}

#[tokio::test]
async fn one_policy_snapshot_drives_decision_and_audit() {
    let w = World::new();
    let snapshots = Arc::new(AtomicUsize::new(0));
    let counter = snapshots.clone();
    let mut opts = options();
    opts.policy_source = Some(Box::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
        let mut snapshot: Policy = test_policy();
        snapshot.policy_digest = "actual-snapshot".into();
        Arc::new(snapshot)
    }));
    let v = w.verifier(test_policy(), Some(opts));
    let upstream = FakeUpstream::default_json();
    let app = w.proxy_with(
        vec![(None, upstream.clone() as SharedUpstream)],
        None,
        v,
        true,
    );
    let before = snapshots.load(Ordering::SeqCst);
    let token = bearer(&w.native_token());
    post(
        &app,
        read_call(Some("/projets/acme/x")),
        &[("authorization", &token)],
    )
    .await;
    assert!(upstream.reached());
    assert_eq!(snapshots.load(Ordering::SeqCst) - before, 1);
    assert_eq!(
        w.audit_entries().last().unwrap()["policy_digest"],
        json!("actual-snapshot")
    );
}

#[tokio::test]
async fn reload_from_observation_to_enforce_blocks() {
    let w = World::new();
    let v = w.verifier(test_policy(), None);
    let mut observing = test_policy();
    observing.mode = "warn-only".into();
    v.set_policy(observing);
    let upstream = FakeUpstream::default_json();
    let app = w.proxy_with(
        vec![(None, upstream.clone() as SharedUpstream)],
        None,
        v.clone(),
        true,
    );
    post(&app, read_call(None), &[]).await;
    assert_eq!(upstream.calls.lock().unwrap().len(), 1);
    assert_eq!(w.audit_entries().last().unwrap()["enforced"], json!(false));
    let mut enforcing = test_policy();
    enforcing.mode = "enforce".into();
    v.set_policy(enforcing);
    post(&app, read_call(None), &[]).await;
    assert_eq!(upstream.calls.lock().unwrap().len(), 1);
    assert_eq!(w.audit_entries().last().unwrap()["enforced"], json!(true));
}

#[tokio::test]
async fn complete_sse_events_are_filtered_or_refused() {
    for valid in [true, false] {
        let w = World::new();
        let upstream = FakeUpstream::customized(|u| {
            u.content_type = "text/event-stream".into();
            u.raw_body = Some(if valid {
                b"data: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1,\"result\":{\"tools\":[{\"name\":\"read_file\"},{\"name\":\"secret\"}]}}\n\n".to_vec()
            } else {
                b"data: bad-json\n\n".to_vec()
            });
        });
        let app = w.proxy(upstream, Some("enforce"));
        let reply = post(
            &app,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
            &[],
        )
        .await;
        let text = reply.text();
        if valid {
            assert!(
                text.contains("read_file") && !text.contains("secret"),
                "{text}"
            );
        } else {
            assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
            assert!(!text.contains("bad-json"));
        }
    }
}

#[tokio::test]
async fn http_has_no_cross_session_cookie_identity() {
    let server = RecordingServer::start(|_| {
        Canned::raw(
            200,
            &[
                ("content-type", "application/json"),
                ("set-cookie", "session=secret; Path=/"),
            ],
            br#"{"result": {}}"#,
        )
    })
    .await;
    let up = HttpUpstream::new(&server.url("/custom"), Vec::new()).unwrap();
    up.forward(
        "POST",
        Bytes::from_static(b"{}"),
        &forward_headers(&[("mcp-session-id", "A")]),
    )
    .await
    .unwrap();
    up.forward(
        "POST",
        Bytes::from_static(b"{}"),
        &forward_headers(&[("mcp-session-id", "B")]),
    )
    .await
    .unwrap();
    let calls = server.requests();
    assert_eq!(calls[1].header("mcp-session-id"), Some("B"));
    assert_eq!(calls[1].header("cookie"), None);
    assert_eq!(calls[0].path, "/custom");
    up.close().await;
}

#[tokio::test]
async fn upstream_key_valid_absent_and_invalid() {
    let server = RecordingServer::start(|request| {
        let status = if request.header("x-api-key") == Some("valid") {
            200
        } else {
            401
        };
        Canned::json(status, json!({"result": {}}))
    })
    .await;
    for (key, status) in [(Some("valid"), 200), (None, 401), (Some("invalid"), 401)] {
        let credentials = key
            .map(|k| vec![("x-api-key".to_owned(), k.to_owned())])
            .unwrap_or_default();
        let up = HttpUpstream::new(&server.url("/mcp"), credentials).unwrap();
        let response = up
            .forward(
                "POST",
                Bytes::from_static(b"{}"),
                &forward_headers(&[("x-api-key", "client-must-not-override")]),
            )
            .await
            .unwrap();
        assert_eq!(response.status, status, "{key:?}");
        up.close().await;
    }
}

#[tokio::test]
async fn out_of_mandate_never_sends_upstream_key() {
    let server = RecordingServer::start(|_| Canned::json(200, json!({"result": {}}))).await;
    let up = HttpUpstream::new(
        &server.url("/mcp"),
        vec![("x-api-key".into(), "valid".into())],
    )
    .unwrap();
    let w = World::new();
    let app = w.proxy_with(
        vec![(None, Arc::new(up) as SharedUpstream)],
        Some("enforce"),
        w.verifier(test_policy(), None),
        true,
    );
    let token = bearer(&w.native_token());
    post(
        &app,
        read_call(Some("/secret")),
        &[("authorization", &token)],
    )
    .await;
    assert!(server.requests().is_empty());
}

#[test]
fn corrupted_audit_cannot_resume_or_be_anchored() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("audit");
    let key = generate_keypair();
    let log = AuditLog::new(&p, &key.private_str, "gw", "d", TrustedKeys::new()).unwrap();
    log.record(allow()).unwrap();
    let mut record: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    record["entry"]["decision"] = json!("DENY");
    std::fs::write(&p, format!("{}\n", tokencrumb_mcp_proxy::json::dumps(&record))).unwrap();
    let err = AuditLog::new(&p, &key.private_str, "gw", "d", TrustedKeys::new())
        .err()
        .expect("resumed a corrupted chain");
    assert_eq!(err.kind, ErrorKind::Value);
    assert!(err.message.contains("invalid audit"), "{}", err.message);
    let err = head_attestation(&p, &key.private_str, None, TrustedKeys::new()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Value);
    assert!(err.message.contains("invalid audit"), "{}", err.message);
}

#[test]
fn two_audit_writers_keep_one_chain() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("audit");
    let key = generate_keypair();
    let logs: Vec<AuditLog> = (0..2)
        .map(|_| AuditLog::new(&p, &key.private_str, "gw", "d", TrustedKeys::new()).unwrap())
        .collect();
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..12)
            .map(|i| {
                let log = &logs[i % 2];
                scope.spawn(move || log.record(allow()).unwrap())
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
    });
    let result = verify_log(
        &p,
        &trusted_from(std::slice::from_ref(&key.public_str)).unwrap(),
    )
    .unwrap();
    assert!(result.ok, "{:?}", result.failures);
    assert_eq!(result.entries, 12);
}

#[test]
fn rotation_remains_verifiable_and_quota_is_closed() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("audit");
    let key = generate_keypair();
    let log = AuditLog::with_bounds(&p, &key.private_str, "gw", "d", TrustedKeys::new(), 2048, 2)
        .unwrap();
    for _ in 0..4 {
        log.record(allow()).unwrap();
    }
    let trusted = trusted_from(std::slice::from_ref(&key.public_str)).unwrap();
    assert!(verify_log(&p, &trusted).unwrap().ok);
    let err = (0..20)
        .map(|_| log.record(allow()))
        .find_map(Result::err)
        .expect("the quota never closed");
    assert_eq!(err.kind, ErrorKind::Io);
    assert!(err.message.contains("quota"), "{}", err.message);
    let used: u64 = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|f| f.extension().is_none_or(|ext| ext != "lock"))
        .map(|f| std::fs::metadata(f).unwrap().len())
        .sum();
    assert!(used <= 4096, "{used}");
}

#[test]
fn trusted_key_rotation_and_unknown_key_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("audit");
    let audit_key = generate_keypair();
    let old = AuditLog::new(&p, &audit_key.private_str, "gw", "d", TrustedKeys::new()).unwrap();
    old.record(allow()).unwrap();
    let new = generate_keypair();
    let mut ring = TrustedKeys::new();
    ring.insert(
        key_id(&audit_key.public_str).unwrap(),
        audit_key.public_str.clone(),
    );
    let log = AuditLog::new(&p, &new.private_str, "gw", "d", ring.clone()).unwrap();
    log.record(allow()).unwrap();
    ring.insert(key_id(&new.public_str).unwrap(), new.public_str.clone());
    assert!(verify_log(&p, &ring).unwrap().ok);
    let only_new = trusted_from(std::slice::from_ref(&new.public_str)).unwrap();
    assert!(!verify_log(&p, &only_new).unwrap().ok);
}

#[tokio::test]
async fn nonfinite_exponent_and_foreign_same_origin_never_forward() {
    let w = World::new();
    let upstream = FakeUpstream::default_json();
    let app = w.proxy(upstream.clone(), Some("enforce"));
    let reply = post(
        &app,
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"size":1e999}}}"#.as_slice(),
        &[],
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(!upstream.reached());
    let reply = post(
        &app,
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
        &[
            ("host", "rebound.example"),
            ("origin", "http://rebound.example"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert!(!upstream.reached());
}

/// The Python test monkeypatched `AuditLog.record` to raise `OSError`. Here the audit
/// file is replaced by a directory once the proxy is up, so the real `record` fails.
#[tokio::test]
async fn tools_list_is_not_dispatched_when_preflight_audit_fails() {
    let w = World::new();
    let upstream = FakeUpstream::default_json();
    let app = w.proxy(upstream.clone(), Some("enforce"));
    std::fs::create_dir(w.audit_path()).unwrap();
    let reply = post(
        &app,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        &[],
    )
    .await;
    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!upstream.reached());
}

#[tokio::test]
async fn rate_limit_refuses_before_upstream_and_is_audited() {
    for (origin, status) in [
        (None, StatusCode::OK),
        (Some("https://untrusted"), StatusCode::FORBIDDEN),
    ] {
        let w = World::new();
        let path = w.dir.path().join("rate-audit.log");
        let upstream = FakeUpstream::default_json();
        let audit = AuditLog::new(
            &path,
            &w.audit_key.private_str,
            "gw",
            "d",
            TrustedKeys::new(),
        )
        .unwrap();
        let mut config = ProxyConfig::new(
            w.verifier(test_policy(), None),
            vec![(None, upstream.clone() as SharedUpstream)],
            Some(Arc::new(audit)),
        );
        config.requests_per_minute = 1;
        let app = create_app(config).unwrap();
        let ping = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
        let headers: Vec<(&str, &str)> = origin.map(|o| ("origin", o)).into_iter().collect();
        assert_eq!(post(&app, ping.clone(), &headers).await.status, status);
        assert_eq!(
            post(&app, ping, &headers).await.status,
            StatusCode::TOO_MANY_REQUESTS
        );
        let expected_calls = usize::from(status == StatusCode::OK);
        assert_eq!(upstream.calls.lock().unwrap().len(), expected_calls);
        assert_eq!(
            audit_entries(&path).last().unwrap()["decision"],
            json!("DENY")
        );
    }
}

#[tokio::test]
async fn catalog_response_must_match_the_request_id() {
    let w = World::new();
    let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let good = FakeUpstream::new(
        Some(json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})),
        "application/json",
    );
    let app = w.proxy(good, Some("enforce"));
    assert_eq!(
        post(&app, request.clone(), &[]).await.status,
        StatusCode::OK
    );
    let bad = FakeUpstream::new(
        Some(json!({"jsonrpc": "2.0", "id": 2, "result": {"tools": []}})),
        "application/json",
    );
    let w = World::new();
    let app = w.proxy(bad, Some("enforce"));
    assert_eq!(
        post(&app, request, &[]).await.status,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

/// `gzip.compress(b"x" * 128, mtime=0)`.
const GZIP_128_X: [u8; 24] = [
    31, 139, 8, 0, 0, 0, 0, 0, 2, 19, 171, 168, 24, 88, 0, 0, 55, 138, 224, 172, 128, 0, 0, 0,
];

#[tokio::test]
async fn upstream_response_limit_has_a_small_positive_control() {
    for compressed in [false, true] {
        let server = RecordingServer::start(move |_| {
            if compressed {
                Canned::raw(200, &[("content-encoding", "gzip")], &GZIP_128_X)
            } else {
                Canned::raw(200, &[], &[b'x'; 128])
            }
        })
        .await;
        let mut upstream = HttpUpstream::new(&server.url("/mcp"), Vec::new()).unwrap();
        upstream.max_response = 32;
        let err = upstream
            .forward(
                "POST",
                Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#),
                &ForwardHeaders::default(),
            )
            .await
            .expect_err("an oversize or compressed reply was accepted");
        assert_eq!(err.kind, ErrorKind::Value);
        assert!(
            err.message.contains("compressed") || err.message.contains("size limit"),
            "{}",
            err.message
        );
        upstream.close().await;
    }
    let server = RecordingServer::start(|_| Canned::raw(200, &[], b"ok")).await;
    let mut small = HttpUpstream::new(&server.url("/mcp"), Vec::new()).unwrap();
    small.max_response = 32;
    let response = small
        .forward(
            "POST",
            Bytes::from_static(br#"{"method":"ping"}"#),
            &ForwardHeaders::default(),
        )
        .await
        .unwrap();
    assert_eq!(&response.body[..], b"ok");
    small.close().await;
}
