//! Hot reload of policy.yaml (ROADMAP v0.2.0).
//!
//! Rules change under a live gateway, so the reloader has to be conservative: a policy
//! that does not load never takes effect, and the upstream set is fixed at startup
//! because endpoints are routes the running app already exposes.
//!
//! Ported from `tests/test_policy_reload.py`.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::proxy::{World, test_policy};
use tokencrumb_mcp_proxy::policy::{PolicyReloader, load_policy};
use tokencrumb_mcp_proxy::storage::write_secure;

/// Publish by atomic replacement, as the operator tooling does.
fn publish(path: &Path, text: &str) {
    write_secure(path, text.as_bytes()).unwrap();
}

const BASE: &str = "
deny_unknown_tools: true
min_profile: native
tools:
  - name: read_file
    operation: read
    allow: {budget: 100}
";

type Events = Arc<Mutex<Vec<(String, String)>>>;

fn policy_file() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.yaml");
    std::fs::write(&path, BASE).unwrap();
    (dir, path)
}

fn reloader(path: &Path) -> (PolicyReloader, Events) {
    let events: Events = Arc::default();
    let sink = events.clone();
    let r = PolicyReloader::new(
        path,
        load_policy(path).unwrap(),
        Duration::ZERO,
        Box::new(move |level, message| {
            sink.lock()
                .unwrap()
                .push((level.to_owned(), message.to_owned()))
        }),
    );
    (r, events)
}

fn any(events: &Events, predicate: impl Fn(&(String, String)) -> bool) -> bool {
    events.lock().unwrap().iter().any(predicate)
}

fn read_file_budget(r: &PolicyReloader) -> Option<i128> {
    r.current().tool("read_file").unwrap().budget
}

#[test]
fn an_edit_is_picked_up() {
    let (_dir, path) = policy_file();
    let (r, events) = reloader(&path);
    assert_eq!(r.current().min_profile, "native");

    publish(&path, &BASE.replace("native", "hardened_biscuit_anchored"));
    assert_eq!(r.current().min_profile, "hardened_biscuit_anchored");
    assert!(any(&events, |(level, _)| level == "info"));
}

#[test]
fn the_digest_changes_with_the_file() {
    let (_dir, path) = policy_file();
    let (r, _) = reloader(&path);
    let before = r.current().policy_digest.clone();
    publish(&path, &format!("{BASE}\nbudget_total: 10\n"));
    let after = r.current();
    assert_eq!(after.budget_total, Some(10));
    assert_ne!(after.policy_digest, before);
}

/// The failure that matters: an edit that does not parse must not disarm the gateway,
/// and must not fall back to a default.
#[test]
fn a_broken_policy_never_takes_effect() {
    let (_dir, path) = policy_file();
    let (r, events) = reloader(&path);
    assert_eq!(read_file_budget(&r), Some(100));

    publish(&path, "tools: [ this is not: valid: yaml");
    assert_eq!(read_file_budget(&r), Some(100));
    assert!(any(&events, |(level, _)| level == "error"));
}

#[test]
fn a_policy_rejected_by_validation_never_takes_effect() {
    let (_dir, path) = policy_file();
    let (r, events) = reloader(&path);
    publish(
        &path,
        "
tools:
  - name: read_file
    operation: read
  - name: read_file
    operation: write
",
    );
    assert_eq!(r.current().tool("read_file").unwrap().operation, "read");
    assert!(any(&events, |(_, msg)| msg.contains("mapped twice")));
}

/// Endpoints are routes built at startup: a policy describing a topology the server
/// does not serve would be enforced against calls that cannot arrive.
#[test]
fn changing_the_upstream_set_is_refused() {
    let (_dir, path) = policy_file();
    publish(
        &path,
        "
upstreams:
  catalog: http://a/mcp
tools:
  - name: read_file
    operation: read
    upstream: catalog
",
    );
    let (r, events) = reloader(&path);

    publish(
        &path,
        "
upstreams:
  catalog: http://a/mcp
  inventory: http://b/mcp
tools:
  - name: read_file
    operation: read
    upstream: catalog
",
    );
    let names: Vec<String> = r
        .current()
        .upstreams
        .iter()
        .map(|(n, _)| n.clone())
        .collect();
    assert_eq!(names, vec!["catalog"]);
    assert!(any(&events, |(_, msg)| msg.contains("upstream set is fixed")));
}

#[test]
fn an_unchanged_file_is_not_reloaded() {
    let (_dir, path) = policy_file();
    let (r, events) = reloader(&path);
    for _ in 0..3 {
        r.current();
    }
    assert!(events.lock().unwrap().is_empty());
}

#[test]
fn a_vanished_file_keeps_the_policy_in_force() {
    let (_dir, path) = policy_file();
    let (r, _) = reloader(&path);
    std::fs::remove_file(&path).unwrap();
    assert_eq!(read_file_budget(&r), Some(100));
}

/// Reload is opt-in: an unwired verifier must not consult anything.
#[test]
fn without_a_source_the_verifier_keeps_its_own_policy() {
    let w = World::new();
    let policy = test_policy();
    let v = w.verifier(
        policy.clone(),
        Some(tokencrumb_mcp_proxy::verifier::VerifierOptions::new("gw")),
    );
    assert_eq!(*v.policy(), policy);
    assert!(
        Arc::ptr_eq(&v.policy(), &v.policy()),
        "the same policy object, not a re-read"
    );
}
