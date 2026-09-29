//! Shared helpers for the integration tests: the golden corpus and test keys.
#![allow(dead_code)]

pub mod stub;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

/// Run the built `tokencrumb` binary in `dir` (colour disabled, as when piped).
pub fn bm(dir: &Path, args: &[&str]) -> Output {
    bm_stdin(dir, args, b"")
}

/// [`bm`] with `input` on stdin.
pub fn bm_stdin(dir: &Path, args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tokencrumb"))
        .args(args)
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("tokencrumb binary");
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input).unwrap();
    drop(stdin);
    child.wait_with_output().unwrap()
}

pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A fresh keypair written as `<dir>/<name>.key` / `.pub` (plaintext private key).
pub fn keyfiles(dir: &Path, name: &str) -> tokencrumb_mcp_proxy::keys::Keypair {
    let kp = tokencrumb_mcp_proxy::keys::generate_keypair();
    tokencrumb_mcp_proxy::keys::save_private_key(dir.join(format!("{name}.key")), &kp.private_str, None)
        .unwrap();
    tokencrumb_mcp_proxy::keys::save_public_key(dir.join(format!("{name}.pub")), &kp.public_str).unwrap();
    kp
}

/// The deployment name every test mandate is forged for.
pub const TEST_AUDIENCE: &str = "test-gw";

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
