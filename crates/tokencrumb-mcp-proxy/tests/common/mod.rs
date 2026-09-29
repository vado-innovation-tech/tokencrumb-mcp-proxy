//! Shared helpers for the integration tests: the golden corpus and test keys.
#![allow(dead_code)]

use std::path::PathBuf;

use serde_json::Value;

pub fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name)
}

/// One file of the reference corpus produced by the former Python implementation.
pub fn golden(name: &str) -> Value {
    let raw = std::fs::read_to_string(golden_path(name)).expect("golden file");
    serde_json::from_str(&raw).expect("golden json")
}

pub fn key(name: &str, part: &str) -> String {
    golden("keys.json")[name][part]
        .as_str()
        .expect("key")
        .to_owned()
}

/// `{"ok": v}` / `{"err": T, "message": m}` against a Rust result.
pub fn assert_outcome<T: std::fmt::Debug>(
    label: &str,
    expected: &Value,
    actual: &tokencrumb_mcp_proxy::Result<T>,
    render: impl Fn(&T) -> Value,
) {
    match (expected.get("ok"), actual) {
        (Some(want), Ok(got)) => assert_eq!(&render(got), want, "{label}: value"),
        (None, Err(err)) => assert_eq!(
            expected["message"].as_str().unwrap(),
            err.message,
            "{label}: message"
        ),
        (Some(want), Err(err)) => panic!("{label}: expected ok {want}, got error {}", err.message),
        (None, Ok(got)) => panic!(
            "{label}: expected error {}, got {got:?}",
            expected["message"]
        ),
    }
}

pub fn t0() -> chrono::DateTime<chrono::Utc> {
    let raw = golden("tokens.json")["t0"].as_str().unwrap().to_owned();
    chrono::DateTime::parse_from_rfc3339(&raw)
        .unwrap()
        .with_timezone(&chrono::Utc)
}
