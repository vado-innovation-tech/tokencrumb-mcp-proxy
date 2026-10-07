//! Lifecycle regressions: restart, rotation, concurrency, client and issuer
//! interoperability.
//!
//! Ported from `tests/test_security_lifecycle.py`. The registry, CLI and client-wrap
//! cases belong to the CLI/registry port. Where the Python suite used
//! `httpx.MockTransport`, these tests run a real HTTP server on `127.0.0.1:0`; where it
//! ran `python -c` children, they run `/bin/sh` scripts.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Once};
use std::time::Duration;

use axum::http::StatusCode;
use base64::Engine as _;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use common::proxy::{
    Canned, FakeUpstream, RecordingServer, TEST_AUDIENCE, World, bearer, biscuit_headers,
    build_token, date_term, forge, in_seconds, mandate, options, post, str_term, test_policy,
    verify,
};
use serde_json::{Value, json};
use tokencrumb_mcp_proxy::ErrorKind;
use tokencrumb_mcp_proxy::audit::{AuditLog, Record, TrustedKeys, trusted_from, verify_log};
use tokencrumb_mcp_proxy::biscuit_ops::{Attenuation, attenuate, capability_key, inspect};
use tokencrumb_mcp_proxy::budget::BudgetStore;
use tokencrumb_mcp_proxy::canonical::canonicalize;
use tokencrumb_mcp_proxy::keys::{self, generate_keypair};
use tokencrumb_mcp_proxy::nonce_cache::{NonceCache, NonceStore};
use tokencrumb_mcp_proxy::policy::parse_policy;
use tokencrumb_mcp_proxy::proxy::upstream::{
    ForwardHeaders, HttpUpstream, SharedUpstream, StdioUpstream, Upstream,
};
use tokencrumb_mcp_proxy::revocation::{
    RevocationList, migrate_legacy_list, update_revocation_list, validate_document,
};
use tokencrumb_mcp_proxy::verifier::{Decision, Headers, Verifier};

#[test]
fn nonce_is_once_across_workers_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nonces.db");
    let open = || NonceCache::new(100_000, 120, Some(&path)).unwrap();
    let stores: Vec<NonceCache> = (0..4).map(|_| open()).collect();
    let fresh = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..12)
            .map(|i| {
                let store = &stores[i % 4];
                scope.spawn(move || store.check_and_add("nonce", 100.0, Some(500.0)).unwrap())
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|fresh| *fresh)
            .count()
    });
    assert_eq!(fresh, 1);
    assert!(!open().check_and_add("nonce", 101.0, None).unwrap());
    assert!(!open().check_and_add("other", 50.0, None).unwrap());
    assert!(open().check_and_add("other", 501.0, None).unwrap());
}

#[test]
fn budget_purge_retains_parent_until_its_own_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("budget");
    let store = BudgetStore::open(&path).unwrap();
    store.prepare(100).unwrap();
    store.consume(&["root"], Some(200)).unwrap();
    store.prepare(110).unwrap();
    store.consume(&["root"], Some(120)).unwrap();
    store.prepare(130).unwrap();
    assert_eq!(store.remaining("root", 3).unwrap(), 1);
    store.prepare(201).unwrap();
    assert_eq!(store.remaining("root", 3).unwrap(), 3);
    store.consume(&["next"], Some(250)).unwrap();
    let restarted = BudgetStore::open(&path).unwrap();
    let err = restarted.prepare(150).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Value);
    assert!(err.message.contains("clock rollback"), "{}", err.message);
}

fn allow() -> Record {
    Record {
        decision: "ALLOW".into(),
        ..Default::default()
    }
}

#[test]
fn audit_disappearance_cannot_start_a_new_chain() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("audit");
    let key = generate_keypair();
    let log = AuditLog::new(&p, &key.private_str, "gw", "d", TrustedKeys::new()).unwrap();
    log.record(allow()).unwrap();
    std::fs::remove_file(&p).unwrap();
    let err = log.record(allow()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Value);
    assert!(err.message.contains("disappeared"), "{}", err.message);
    let err = verify_log(
        &p,
        &trusted_from(std::slice::from_ref(&key.public_str)).unwrap(),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::NotFound);
}

#[test]
fn private_key_creation_never_changes_a_symlink_target() {
    let w = World::new();
    let original = w.dir.path().join("original");
    std::fs::write(&original, "untouched").unwrap();
    let output = w.dir.path().join("key");
    std::os::unix::fs::symlink(&original, &output).unwrap();
    keys::save_private_key(&output, &w.authority.private_str, None).unwrap();
    assert_eq!(std::fs::read_to_string(&original).unwrap(), "untouched");
    let meta = std::fs::symlink_metadata(&output).unwrap();
    assert!(!meta.file_type().is_symlink());
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
}

#[test]
fn only_explicit_authority_epochs_are_trusted() {
    let w = World::new();
    let other = generate_keypair();
    let token = forge(
        &other.private_str,
        mandate("a", "read_file", "read", 300, 10),
    );
    let call = |v: &Verifier| {
        verify(
            v,
            "read_file",
            json!({"path": "/projects/acme/x"}),
            &biscuit_headers(&token, None),
        )
        .allow
    };
    assert!(!call(&w.verifier(test_policy(), Some(options()))));
    let mut opts = options();
    opts.previous_authority_keys = vec![other.public_str.clone()];
    assert!(call(&w.verifier(test_policy(), Some(opts))));
}

#[test]
fn java_mandate_is_accepted_then_exhausted_and_cannot_change_rights() {
    let fixture_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/java_mandate.json");
    let fixture: Value =
        serde_json::from_str(&std::fs::read_to_string(fixture_path).unwrap()).unwrap();
    let policy = parse_policy(&json!({"tools": [
        {"name": "read_file", "operation": "read"},
        {"name": "write_file", "operation": "write"},
    ]}))
    .unwrap();
    let now: DateTime<Utc> = DateTime::parse_from_rfc3339(fixture["now"].as_str().unwrap())
        .unwrap()
        .with_timezone(&Utc);
    let mut opts = tokencrumb_mcp_proxy::verifier::VerifierOptions::new("biscuitmcp://interop");
    opts.now_fn = Some(Box::new(move || now));
    let v = Verifier::new(fixture["authority_pub"].as_str().unwrap(), policy, opts).unwrap();
    let headers = biscuit_headers(fixture["token"].as_str().unwrap(), None);
    assert!(!verify(&v, "write_file", json!({}), &headers).allow);
    let first = verify(&v, "read_file", json!({}), &headers);
    assert!(first.allow, "{}", first.reason);
    assert_eq!(first.subject.as_deref(), Some("interop-user"));
    assert_eq!(first.issuer.as_deref(), Some("test-issuer"));
    assert!(verify(&v, "read_file", json!({}), &headers).allow);
    assert!(!verify(&v, "read_file", json!({}), &headers).allow);
}

const SECRET_VARIABLE: &str = "TOKENCRUMB_UPSTREAM_SECRET";

fn environment() {
    static SET: Once = Once::new();
    SET.call_once(|| {
        // SAFETY: runs once, before any test of this binary spawns a child.
        unsafe { std::env::set_var(SECRET_VARIABLE, "do-not-forward") };
    });
}

fn sh(script: &str) -> Vec<String> {
    vec!["/bin/sh".into(), "-c".into(), script.into()]
}

/// Python asserted the private `_proc` handle was cleared; here the child's pid is
/// observed and must be gone once the timeout returns.
#[tokio::test]
async fn stdio_timeout_kills_child_and_does_not_inherit_proxy_secrets() {
    environment();
    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("pid");
    let mut up = StdioUpstream::new(sh(&format!(
        "echo $$ > '{}'; exec sleep 10",
        pidfile.display()
    )))
    .unwrap();
    up.timeout = Duration::from_millis(500);
    let err = up
        .forward(
            "POST",
            Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#),
            &ForwardHeaders::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        (err.kind, err.message.as_str()),
        (ErrorKind::Io, "TimeoutError")
    );
    let pid: i32 = std::fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // SAFETY: signal 0 only probes whether the process exists.
    let alive = unsafe { libc::kill(pid, 0) } == 0;
    assert!(!alive, "the timed-out child is still running");

    let script = format!(
        r#"read line
id=$(printf '%s' "$line" | sed 's/.*"id": *\([0-9]*\).*/\1/')
if [ -n "${{{SECRET_VARIABLE}+x}}" ]; then leaked=true; else leaked=false; fi
printf '{{"jsonrpc":"2.0","id":%s,"result":{{"leaked":%s}}}}\n' "$id" "$leaked""#
    );
    let up = StdioUpstream::new(sh(&script)).unwrap();
    let response = up
        .forward(
            "POST",
            Bytes::from_static(br#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#),
            &ForwardHeaders::default(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["result"]["leaked"], json!(false));
    up.close().await;
}

fn user_token(w: &World, user: &str, rights: &str) -> String {
    build_token(
        &w.authority.private_str,
        &format!(
            r#"user({{u}});issuer("iam");required_profile("native");audience({{a}});{rights}expires_at({{e}});"#
        ),
        &[
            ("u", str_term(user)),
            ("a", str_term(TEST_AUDIENCE)),
            ("e", date_term(in_seconds(300))),
        ],
    )
}

fn read_call(path: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "read_file", "arguments": {"path": path}}})
}

#[tokio::test]
async fn verified_user_credentials_remain_separate_and_out_of_scope_never_dispatches() {
    let server = RecordingServer::start(|request| {
        let id = request.json()["id"].clone();
        if request.header("authorization") != Some("Bearer alice-upstream") {
            return Canned::json(
                403,
                json!({"jsonrpc": "2.0", "id": id,
                       "error": {"code": -32001, "message": "upstream ACL denied"}}),
            );
        }
        Canned::json(
            200,
            json!({"jsonrpc": "2.0", "id": id, "result": {"content": []}}),
        )
    })
    .await;
    let mut up = HttpUpstream::new(&server.url("/mcp"), Vec::new()).unwrap();
    up.add_user_credential("iam", "alice", "Authorization", "Bearer alice-upstream")
        .unwrap();
    up.add_user_credential("iam", "bob", "Authorization", "Bearer bob-upstream")
        .unwrap();
    let w = World::new();
    let app = w.proxy_with(
        vec![(None, Arc::new(up) as SharedUpstream)],
        None,
        w.verifier(test_policy(), Some(options())),
        false,
    );
    let rights = r#"right("read_file","read");"#;
    let mut statuses = Vec::new();
    for user in ["alice", "bob", "missing"] {
        let token = bearer(&user_token(&w, user, rights));
        let reply = post(
            &app,
            read_call("/projects/acme/x"),
            &[
                ("authorization", &token),
                ("x-user", "alice"),
                ("authorization-override", "evil"),
            ],
        )
        .await;
        statuses.push(reply.status.as_u16());
    }
    assert_eq!(statuses, vec![200, 403, 503]);
    let reached: Vec<String> = server
        .requests()
        .iter()
        .map(|r| r.header("authorization").unwrap().to_owned())
        .collect();
    assert_eq!(
        reached,
        vec!["Bearer alice-upstream", "Bearer bob-upstream"]
    );
    let alice = bearer(&user_token(&w, "alice", rights));
    post(&app, read_call("/secret"), &[("authorization", &alice)]).await;
    assert_eq!(server.requests().len(), 2);
}

/// Python wrapped `forward` to add the header to `initialize` replies only; the fake
/// here sets it on every reply, which the owning mandate may refresh harmlessly.
#[tokio::test]
async fn session_id_is_bound_to_its_mandate() {
    let w = World::new();
    let up = FakeUpstream::customized(|u| {
        u.extra_headers = vec![("mcp-session-id".into(), "session-A".into())];
    });
    let app = w.proxy(up.clone(), Some("enforce"));
    let native = bearer(&w.native_token());
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"});
    assert_eq!(
        post(&app, init, &[("authorization", &native)]).await.status,
        StatusCode::OK
    );
    let other = bearer(&forge(
        &w.authority.private_str,
        mandate("other", "read_file", "read", 300, 10),
    ));
    let request = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
    let before = up.calls.lock().unwrap().len();
    let reply = post(
        &app,
        request.clone(),
        &[("authorization", &other), ("mcp-session-id", "session-A")],
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(up.calls.lock().unwrap().len(), before);
    let reply = post(
        &app,
        request,
        &[("authorization", &native), ("mcp-session-id", "session-A")],
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
}

#[tokio::test]
async fn stdio_restart_reinitializes_before_serving_requests() {
    let script = r#"initialized=false
while IFS= read -r line; do
  case "$line" in *'notifications/initialized'*) initialized=true; continue;; esac
  case "$line" in *'"slow"'*) sleep 5;; esac
  id=$(printf '%s' "$line" | sed 's/.*"id": *\([0-9]*\).*/\1/')
  printf '{"jsonrpc":"2.0","id":%s,"result":{"initialized":%s}}\n' "$id" "$initialized"
done"#;
    let mut up = StdioUpstream::new(sh(script)).unwrap();
    up.timeout = Duration::from_secs(1);
    let none = ForwardHeaders::default();
    up.forward(
        "POST",
        Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#),
        &none,
    )
    .await
    .unwrap();
    let err = up
        .forward(
            "POST",
            Bytes::from_static(br#"{"jsonrpc":"2.0","id":2,"method":"slow"}"#),
            &none,
        )
        .await
        .unwrap_err();
    assert_eq!(err.message, "TimeoutError");
    let response = up
        .forward(
            "POST",
            Bytes::from_static(br#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#),
            &none,
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["result"]["initialized"], json!(true));
    up.close().await;
}

const CHILD_STATE: &str = "TOKENCRUMB_TEST_SPEND_STATE";
const CHILD_PUBLIC: &str = "TOKENCRUMB_TEST_SPEND_PUBLIC";
const CHILD_TOKEN: &str = "TOKENCRUMB_TEST_SPEND_TOKEN";
const CHILD_MARK: &str = "SPEND-RESULT:";

/// Child half of `one_call_budget_is_atomic_across_processes`: a no-op unless that
/// test re-executes this binary with the spending environment set.
#[test]
fn spend_in_process_child() {
    let (Ok(state), Ok(public), Ok(token)) = (
        std::env::var(CHILD_STATE),
        std::env::var(CHILD_PUBLIC),
        std::env::var(CHILD_TOKEN),
    ) else {
        return;
    };
    let policy =
        parse_policy(&json!({"tools": [{"name": "read_file", "operation": "read"}]})).unwrap();
    let mut opts = options();
    opts.budget_store = Some(Arc::new(BudgetStore::open(state).unwrap()));
    let v = Verifier::new(&public, policy, opts).unwrap();
    let headers = Headers::new([("authorization", bearer(&token))]);
    let decision: Decision = verify(&v, "read_file", json!({}), &headers);
    println!("{CHILD_MARK}{}", decision.allow);
}

#[test]
fn one_call_budget_is_atomic_across_processes() {
    let w = World::new();
    let token = forge(
        &w.authority.private_str,
        mandate("a", "read_file", "read", 300, 1),
    );
    let state = w.dir.path().join("shared");
    let exe = std::env::current_exe().unwrap();
    let children: Vec<_> = (0..6)
        .map(|_| {
            std::process::Command::new(&exe)
                .args([
                    "--exact",
                    "spend_in_process_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD_STATE, &state)
                .env(CHILD_PUBLIC, &w.authority.public_str)
                .env(CHILD_TOKEN, &token)
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    // Collect every child before asserting: the shared state must outlive them all.
    let outputs: Vec<_> = children
        .into_iter()
        .map(|child| child.wait_with_output().unwrap())
        .collect();
    let mut allowed = 0;
    for output in outputs {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "{stdout}");
        let result = stdout
            .split(CHILD_MARK)
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .unwrap_or_else(|| panic!("child reported nothing: {stdout}"));
        allowed += usize::from(result == "true");
    }
    assert_eq!(allowed, 1);
}

#[test]
fn revocation_migration_authenticates_old_entries_and_keeps_them() {
    let w = World::new();
    let old_body = json!({"revoked": ["parent", "child"]});
    let signature =
        keys::sign(&w.authority.private_str, &canonicalize(&old_body).unwrap()).unwrap();
    let mut old = old_body.clone();
    old["sig"] = json!(base64::engine::general_purpose::STANDARD.encode(signature));
    let migrated =
        migrate_legacy_list(&old, &w.authority.public_str, &w.attacker.private_str).unwrap();
    validate_document(&migrated, &w.attacker.public_str, None, true).unwrap();
    assert_eq!(migrated["revoked"], json!(["child", "parent"]));
    let mut tampered = old.clone();
    tampered["revoked"] = json!([]);
    assert!(
        migrate_legacy_list(&tampered, &w.authority.public_str, &w.attacker.private_str).is_err()
    );
}

#[test]
fn republishing_a_missing_revocation_file_keeps_accepted_entries() {
    let w = World::new();
    let path = w.dir.path().join("revoked");
    update_revocation_list(&path, &w.authority.private_str, &["old".into()]).unwrap();
    RevocationList::new(&path, &w.authority.public_str, None, None).unwrap();
    std::fs::remove_file(&path).unwrap();
    let doc = update_revocation_list(&path, &w.authority.private_str, &["new".into()]).unwrap();
    let mut revoked: Vec<&str> = doc["revoked"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    revoked.sort_unstable();
    assert_eq!(revoked, vec!["new", "old"]);
}

#[tokio::test]
async fn empty_user_credentials_never_fall_back_to_a_shared_credential() {
    let server = RecordingServer::start(|_| Canned::raw(200, &[], b"")).await;
    let mut up = HttpUpstream::new(
        &server.url("/mcp"),
        vec![("Authorization".into(), "shared".into())],
    )
    .unwrap();
    up.requires_user_credentials = true; // `user_credentials={}` in Python
    let err = up
        .forward(
            "POST",
            Bytes::from_static(br#"{"method":"tools/call"}"#),
            &ForwardHeaders::default(),
        )
        .await
        .unwrap_err();
    assert!(
        err.message.contains("no upstream credential"),
        "{}",
        err.message
    );
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn user_authorization_replaces_shared_header_case_insensitively() {
    let server = RecordingServer::start(|_| Canned::raw(200, &[], b"")).await;
    let mut up = HttpUpstream::new(
        &server.url("/mcp"),
        vec![("Authorization".into(), "shared".into())],
    )
    .unwrap();
    up.add_user_credential("iam", "alice", "authorization", "alice")
        .unwrap();
    up.forward(
        "POST",
        Bytes::from_static(br#"{"method":"tools/call"}"#),
        &ForwardHeaders {
            incoming: Headers::default(),
            principal: Some((Some("iam".into()), Some("alice".into()))),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        server.requests()[0].header_all("authorization"),
        vec!["alice"]
    );
}

/// The last step of the Python test ran `tokencrumb revoke --from-token`; the CLI
/// port covers that wiring. Here the same addition — the token's capability key, as
/// the CLI computes it — goes through the library.
#[test]
fn revoke_child_can_be_targeted_but_from_token_revokes_the_root_family() {
    let w = World::new();
    let native = w.native_token();
    let narrow = |resource: &str| {
        attenuate(
            &native,
            &w.authority.public_str,
            &Attenuation {
                resource: Some(resource.into()),
                ..Default::default()
            },
        )
        .unwrap()
    };
    let child = narrow("/projects/acme/x/");
    let sibling = narrow("/projects/acme/y/");
    let path = w.dir.path().join("revoked");
    let child_id = inspect(&child)
        .unwrap()
        .revocation_ids
        .last()
        .unwrap()
        .clone();
    update_revocation_list(&path, &w.authority.private_str, &[child_id]).unwrap();
    let mut opts = options();
    opts.revocation = Some(Arc::new(
        RevocationList::new(&path, &w.authority.public_str, None, None).unwrap(),
    ));
    let verifier = w.verifier(test_policy(), Some(opts));
    let call = |token: &str, path: &str| {
        verify(
            &verifier,
            "read_file",
            json!({"path": path}),
            &biscuit_headers(token, None),
        )
        .allow
    };
    assert!(!call(&child, "/projects/acme/x/item"));
    assert!(call(&sibling, "/projects/acme/y/item") && call(&native, "/projects/acme/x/item"));

    assert_eq!(
        capability_key(&child).unwrap(),
        capability_key(&native).unwrap()
    );
    update_revocation_list(
        &path,
        &w.authority.private_str,
        &[capability_key(&child).unwrap()],
    )
    .unwrap();
    assert!(!call(&native, "/projects/acme/x/item") && !call(&sibling, "/projects/acme/y/item"));
}

#[tokio::test]
async fn user_upstream_credentials_apply_at_session_initialization() {
    let server = RecordingServer::start(|_| {
        Canned::json(
            200,
            json!({"jsonrpc": "2.0", "id": 1,
                   "result": {"protocolVersion": "2025-06-18", "capabilities": {}}}),
        )
    })
    .await;
    let mut up = HttpUpstream::new(
        &server.url("/mcp"),
        vec![("Authorization".into(), "shared-admin".into())],
    )
    .unwrap();
    up.add_user_credential("iam", "alice", "Authorization", "alice-only")
        .unwrap();
    let w = World::new();
    let app = w.proxy_with(
        vec![(None, Arc::new(up) as SharedUpstream)],
        None,
        w.verifier(test_policy(), Some(options())),
        false,
    );
    let token = bearer(&user_token(&w, "alice", ""));
    let request = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"});
    let anonymous = post(&app, request.clone(), &[]).await.json();
    assert!(anonymous.get("error").is_some(), "{anonymous}");
    assert!(server.requests().is_empty());
    let reply = post(&app, request, &[("authorization", &token)])
        .await
        .json();
    assert!(reply.get("result").is_some(), "{reply}");
    let reached: Vec<String> = server
        .requests()
        .iter()
        .map(|r| r.header("authorization").unwrap().to_owned())
        .collect();
    assert_eq!(reached, vec!["alice-only"]);
}
