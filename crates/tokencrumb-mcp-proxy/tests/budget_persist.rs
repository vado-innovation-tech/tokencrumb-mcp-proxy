//! Durable budget counters — opt-in, and fail-closed when they cannot be trusted.
//!
//! Ported from `tests/test_budget_persist.py`.

use tokencrumb_mcp_proxy::ErrorKind;
use tokencrumb_mcp_proxy::budget::BudgetStore;
use serde_json::{Value, json};

const KEY: &str = "revocation-id-1";

/// The documented bench behaviour, asserted rather than assumed.
#[test]
fn in_memory_store_forgets_on_restart() {
    let first = BudgetStore::in_memory();
    first.consume(&[KEY], None).unwrap();
    assert_eq!(first.remaining(KEY, 1).unwrap(), 0);
    assert_eq!(BudgetStore::in_memory().remaining(KEY, 1).unwrap(), 1);
}

#[test]
fn persistent_store_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("budget.state");
    let first = BudgetStore::open(&path).unwrap();
    first.consume(&[KEY], None).unwrap();
    assert_eq!(
        BudgetStore::open(&path).unwrap().remaining(KEY, 1).unwrap(),
        0
    );
}

#[test]
fn missing_state_file_starts_empty() {
    let dir = tempfile::tempdir().unwrap();
    let store = BudgetStore::open(dir.path().join("absent.state")).unwrap();
    assert_eq!(store.remaining(KEY, 5).unwrap(), 5);
}

/// Resetting every budget to zero on a corrupt file would be fail-open.
#[test]
fn corrupt_state_file_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("budget.state");
    std::fs::write(&path, "{not json").unwrap();
    let err = BudgetStore::open(&path)
        .err()
        .expect("corrupt state accepted");
    assert_eq!(err.kind, ErrorKind::Runtime);
    assert!(
        err.message.contains("unreadable budget state"),
        "{}",
        err.message
    );
}

#[test]
fn non_object_state_file_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("budget.state");
    std::fs::write(&path, r#"["unexpected"]"#).unwrap();
    let err = BudgetStore::open(&path)
        .err()
        .expect("non-object state accepted");
    assert_eq!(err.kind, ErrorKind::Runtime);
    assert!(
        err.message.contains("invalid budget state"),
        "{}",
        err.message
    );
}

/// If consumption cannot be recorded, the call must not be counted as allowed.
#[test]
fn unwritable_state_raises_so_the_call_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = BudgetStore::open(dir.path().join("budget.state")).unwrap();
    // The parent directory does not exist.
    store.path = Some(dir.path().join("sub").join("budget.state"));
    let err = store
        .consume(&[KEY], None)
        .expect_err("unrecorded consumption");
    assert!(
        matches!(err.kind, ErrorKind::Io | ErrorKind::NotFound),
        "{err:?}"
    );
}

#[test]
fn state_file_is_plain_readable_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("budget.state");
    let store = BudgetStore::open(&path).unwrap();
    store.consume(&[KEY], None).unwrap();
    store.consume(&[KEY], None).unwrap();
    let stored: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        stored,
        json!({"version": 2, "used": {KEY: 2}, "expires": {}, "clock": 0})
    );
}

#[test]
fn no_temporary_files_are_left_behind() {
    let dir = tempfile::tempdir().unwrap();
    let store = BudgetStore::open(dir.path().join("budget.state")).unwrap();
    for _ in 0..5 {
        store.consume(&[KEY], None).unwrap();
    }
    let mut names: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, vec!["budget.state", "budget.state.lock"]);
}
