//! Offline verification of the audit chain (scenario AUD-1) and the signed head
//! attestation for external anchoring — library and CLI.
//!
//! Ported from `tests/test_audit_verify.py` and `tests/test_audit_head.py`.
//!
//! What this proves: nobody without the audit key can alter a line undetected. What it
//! does not prove: that a compromised gateway did not rewrite AND re-sign its own log —
//! that needs external anchoring (`audit-head`), which is a separate claim: publishing
//! `{seq, head_hash}` signed, to a witness the proxy cannot reach, bounds that rewrite
//! to the interval since the last anchor.

mod common;

use std::path::{Path, PathBuf};

use base64::Engine as _;
use tokencrumb_mcp_proxy::audit::{
    AuditLog, GENESIS, Record, TrustedKeys, head_attestation, trusted_from,
    verify_head_attestation, verify_log,
};
use tokencrumb_mcp_proxy::canonical::{canonicalize, sha256_hex};
use tokencrumb_mcp_proxy::json::{dumps, strict_json};
use tokencrumb_mcp_proxy::keys::{self, Keypair, generate_keypair};
use common::{bm, stderr, stdout};
use serde_json::{Value, json};

fn trusted(public: &str) -> TrustedKeys {
    trusted_from(&[public.to_owned()]).unwrap()
}

fn record(decision: &str) -> Record {
    Record {
        decision: decision.into(),
        ..Default::default()
    }
}

/// Three entries: an allowed call, a refused call, a refused method.
fn written_log(dir: &Path, key: &Keypair) -> PathBuf {
    let path = dir.join("audit.log");
    let log = AuditLog::new(
        &path,
        &key.private_str,
        "gw-test",
        "digest-abc",
        TrustedKeys::new(),
    )
    .unwrap();
    log.record(Record {
        tool: Some("read_file".into()),
        method: Some("tools/call".into()),
        agent_id: Some("agent-1".into()),
        ..record("ALLOW")
    })
    .unwrap();
    log.record(Record {
        tool: Some("execute_sql".into()),
        method: Some("tools/call".into()),
        agent_id: Some("agent-1".into()),
        reason: Some("policy denied".into()),
        correlation_id: Some("abcd1234".into()),
        ..record("DENY")
    })
    .unwrap();
    log.record(Record {
        method: Some("resources/read".into()),
        correlation_id: Some("ffff0000".into()),
        ..record("DENY")
    })
    .unwrap();
    path
}

fn rewrite(path: &Path, line: usize, mutate: impl Fn(&mut Value)) {
    let text = std::fs::read_to_string(path).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let mut parsed = strict_json(&lines[line]).unwrap();
    mutate(&mut parsed);
    lines[line] = dumps(&parsed);
    std::fs::write(path, lines.join("\n") + "\n").unwrap();
}

// --------------------------------------------------------------------------- //
// audit-verify
// --------------------------------------------------------------------------- //

#[test]
fn intact_chain_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_keypair();
    let path = written_log(dir.path(), &key);
    let result = verify_log(&path, &trusted(&key.public_str)).unwrap();
    assert!(result.ok);
    assert_eq!(result.entries, 3);
    assert_ne!(result.head, GENESIS);
    assert!(result.failures.is_empty());
}

/// Flip a decision from DENY to ALLOW — the oldest trick there is.
#[test]
fn tampered_entry_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_keypair();
    let path = written_log(dir.path(), &key);
    rewrite(&path, 1, |r| r["entry"]["decision"] = json!("ALLOW"));
    let result = verify_log(&path, &trusted(&key.public_str)).unwrap();
    assert!(!result.ok);
    assert_eq!(result.failures[0].0, 2); // 1-indexed line number
    assert!(result.failures[0].1.contains("tampered"));
}

/// An attacker who recomputes the hash still cannot produce the signature.
#[test]
fn rehashed_entry_still_fails_on_signature() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_keypair();
    let path = written_log(dir.path(), &key);
    rewrite(&path, 1, |r| {
        r["entry"]["decision"] = json!("ALLOW");
        r["hash"] = json!(sha256_hex(&canonicalize(&r["entry"]).unwrap()));
    });
    let result = verify_log(&path, &trusted(&key.public_str)).unwrap();
    assert!(!result.ok);
    let reasons: Vec<&str> = result.failures.iter().map(|(_, r)| r.as_str()).collect();
    assert!(reasons.join(" ").contains("signature"));
}

#[test]
fn removed_line_breaks_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_keypair();
    let path = written_log(dir.path(), &key);
    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    std::fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
    let result = verify_log(&path, &trusted(&key.public_str)).unwrap();
    assert!(!result.ok);
    let reasons: Vec<&str> = result.failures.iter().map(|(_, r)| r.as_str()).collect();
    assert!(reasons.join(" ").contains("chain break"));
}

#[test]
fn wrong_key_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = written_log(dir.path(), &generate_keypair());
    assert!(
        !verify_log(&path, &trusted(&generate_keypair().public_str))
            .unwrap()
            .ok
    );
}

#[test]
fn chain_resumes_across_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_keypair();
    let path = dir.path().join("audit.log");
    let first = AuditLog::new(&path, &key.private_str, "gateway", "", TrustedKeys::new()).unwrap();
    first
        .record(Record {
            tool: Some("read_file".into()),
            ..record("ALLOW")
        })
        .unwrap();
    // a new process, same file and key
    let second = AuditLog::new(&path, &key.private_str, "gateway", "", TrustedKeys::new()).unwrap();
    second
        .record(Record {
            tool: Some("list_dir".into()),
            ..record("ALLOW")
        })
        .unwrap();
    assert!(verify_log(&path, &trusted(&key.public_str)).unwrap().ok);
    let seqs: Vec<Value> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|l| strict_json(l).unwrap()["entry"]["seq"].clone())
        .collect();
    assert_eq!(seqs, [json!(0), json!(1)]);
}

/// A log written before v0.1.1 has no seq/gateway_id — it must still verify.
#[test]
fn legacy_entries_without_new_fields_stay_verifiable() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_keypair();
    let path = dir.path().join("legacy.log");
    let entry = json!({
        "ts": "2026-07-01T10:00:00Z",
        "agent_id": "agent-1",
        "tool": "read_file",
        "resource": "/projets/acme/a.txt",
        "decision": "ALLOW",
        "reason": null,
        "arguments_hash": "deadbeef",
        "profile": "native",
        "prev_hash": GENESIS,
    });
    let payload = canonicalize(&entry).unwrap();
    let line = json!({
        "hash": sha256_hex(&payload),
        "sig": base64::engine::general_purpose::STANDARD.encode(keys::sign(&key.private_str, &payload).unwrap()),
        "entry": entry,
    });
    std::fs::write(&path, dumps(&line) + "\n").unwrap();
    let result = verify_log(&path, &trusted(&key.public_str)).unwrap();
    assert!(result.ok, "{:?}", result.failures);
}

// --------------------------------------------------------------------------- //
// audit-head
// --------------------------------------------------------------------------- //

fn three_entries(dir: &Path, key: &Keypair) -> PathBuf {
    let path = dir.join("audit.log");
    let log = AuditLog::new(&path, &key.private_str, "gw-test", "d", TrustedKeys::new()).unwrap();
    for i in 0..3 {
        log.record(Record {
            method: Some("tools/call".into()),
            tool: Some(format!("t{i}")),
            ..record("ALLOW")
        })
        .unwrap();
    }
    path
}

#[test]
fn the_attestation_carries_the_current_head() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_keypair();
    let path = three_entries(dir.path(), &key);
    let att =
        head_attestation(&path, &key.private_str, Some("gw-test"), TrustedKeys::new()).unwrap();
    assert_eq!(att["seq"], json!(2));
    assert_eq!(att["entries"], json!(3));
    assert_eq!(att["gateway_id"], json!("gw-test"));
    assert_eq!(att["key_id"], json!(keys::key_id(&key.public_str).unwrap()));
    assert_eq!(att["head_hash"].as_str().unwrap().len(), 64);
}

#[test]
fn it_verifies_against_the_audit_public_key_only_untampered() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_keypair();
    let path = three_entries(dir.path(), &key);
    let mut att = head_attestation(&path, &key.private_str, None, TrustedKeys::new()).unwrap();
    assert!(verify_head_attestation(&att, &key.public_str));
    assert!(!verify_head_attestation(
        &att,
        &generate_keypair().public_str
    ));
    att["head_hash"] = json!("0".repeat(64));
    assert!(!verify_head_attestation(&att, &key.public_str));
}

#[test]
fn the_head_moves_as_the_log_grows() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_keypair();
    let path = three_entries(dir.path(), &key);
    let first = head_attestation(&path, &key.private_str, None, TrustedKeys::new()).unwrap();
    AuditLog::new(&path, &key.private_str, "gw-test", "d", TrustedKeys::new())
        .unwrap()
        .record(Record {
            method: Some("tools/call".into()),
            tool: Some("t3".into()),
            ..record("DENY")
        })
        .unwrap();
    let second = head_attestation(&path, &key.private_str, None, TrustedKeys::new()).unwrap();
    assert_eq!(second["seq"], json!(3));
    assert_ne!(second["head_hash"], first["head_hash"]);
    assert!(verify_head_attestation(&second, &key.public_str));
}

#[test]
fn an_empty_log_anchors_at_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_keypair();
    let path = dir.path().join("empty.log");
    std::fs::write(&path, "").unwrap();
    let att = head_attestation(&path, &key.private_str, None, TrustedKeys::new()).unwrap();
    assert_eq!(att["head_hash"], json!(GENESIS));
    assert_eq!(att["seq"], json!(-1));
    assert!(verify_head_attestation(&att, &key.public_str));
}

// --------------------------------------------------------------------------- //
// The same, through the CLI (stable command output)
// --------------------------------------------------------------------------- //

#[test]
fn cli_audit_verify_reports_intact_and_tampered_chains() {
    let dir = tempfile::tempdir().unwrap();
    let key = common::keyfiles(dir.path(), "audit");
    let path = written_log(dir.path(), &key);
    let head = verify_log(&path, &trusted(&key.public_str)).unwrap().head;

    let output = bm(
        dir.path(),
        &["audit-verify", "--log", "audit.log", "--pub", "audit.pub"],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines[0].starts_with("╭") && lines[0].contains(" audit-verify "));
    assert_eq!(
        lines[1].split_whitespace().collect::<Vec<_>>(),
        ["│", "log", "audit.log", "│"]
    );
    assert_eq!(
        lines[2].split_whitespace().collect::<Vec<_>>(),
        ["│", "entries", "3", "│"]
    );
    let key_id = keys::key_id(&key.public_str).unwrap();
    assert_eq!(
        lines[3].split_whitespace().collect::<Vec<_>>(),
        ["│", "key_id", &key_id, "│"]
    );
    assert_eq!(
        lines[4].split_whitespace().collect::<Vec<_>>(),
        ["│", "head", &head, "│"]
    );
    assert!(lines[5].starts_with("╰"));
    assert_eq!(
        lines[6],
        "chain intact — hashes, signatures and links all verify"
    );
    assert!(!text.contains('\x1b'), "no escape codes when piped");

    // The literal key form is accepted as well as a file.
    let output = bm(
        dir.path(),
        &[
            "audit-verify",
            "--log",
            "audit.log",
            "--pub",
            &key.public_str,
        ],
    );
    assert!(output.status.success());

    rewrite(&path, 1, |r| r["entry"]["decision"] = json!("ALLOW"));
    let output = bm(
        dir.path(),
        &["audit-verify", "--log", "audit.log", "--pub", "audit.pub"],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).contains(" audit-verify "));
    assert_eq!(
        stderr(&output).trim(),
        "line 2: entry hash does not match its content (tampered)"
    );

    let output = bm(
        dir.path(),
        &["audit-verify", "--log", "missing.log", "--pub", "audit.pub"],
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        stderr(&output).trim(),
        "error: audit log not found: missing.log"
    );
}

#[test]
fn cli_audit_head_prints_a_sorted_verifiable_attestation() {
    let dir = tempfile::tempdir().unwrap();
    let key = common::keyfiles(dir.path(), "audit");
    three_entries(dir.path(), &key);
    let output = bm(
        dir.path(),
        &["audit-head", "--log", "audit.log", "--key", "audit.key"],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    let att = strict_json(text.trim()).unwrap();
    assert!(verify_head_attestation(&att, &key.public_str));
    // json.dumps(indent=2, sort_keys=True), byte for byte.
    assert_eq!(
        text,
        tokencrumb_mcp_proxy::json::dumps_indent(&tokencrumb_mcp_proxy::json::sort_keys(&att), 2) + "\n"
    );
    let keys_in_order: Vec<&str> = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix('"')?.split('"').next())
        .collect();
    assert_eq!(
        keys_in_order,
        [
            "entries",
            "gateway_id",
            "head_hash",
            "key_id",
            "seq",
            "signature",
            "ts",
            "type"
        ]
    );

    let output = bm(
        dir.path(),
        &[
            "audit-head",
            "--log",
            "audit.log",
            "--key",
            "audit.key",
            "--out",
            "head.json",
        ],
    );
    assert!(output.status.success());
    assert_eq!(
        stdout(&output).trim(),
        "head attestation -> head.json  (seq 2)"
    );
    let written = strict_json(std::fs::read(dir.path().join("head.json")).unwrap()).unwrap();
    assert!(verify_head_attestation(&written, &key.public_str));

    let output = bm(
        dir.path(),
        &["audit-head", "--log", "nope.log", "--key", "audit.key"],
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        stderr(&output).trim(),
        "error: audit log not found: nope.log"
    );
    let output = bm(
        dir.path(),
        &["audit-head", "--log", "audit.log", "--key", "nope.key"],
    );
    assert_eq!(
        stderr(&output).trim(),
        "error: cannot load audit private key: [Errno 2] No such file or directory: 'nope.key'"
    );
}

#[test]
fn cli_audit_head_refuses_to_anchor_a_corrupted_log() {
    let dir = tempfile::tempdir().unwrap();
    let key = common::keyfiles(dir.path(), "audit");
    let path = three_entries(dir.path(), &key);
    rewrite(&path, 1, |r| r["entry"]["tool"] = json!("tX"));
    let output = bm(
        dir.path(),
        &["audit-head", "--log", "audit.log", "--key", "audit.key"],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).is_empty());
    assert_eq!(
        stderr(&output).trim(),
        "error: refusing to sign invalid audit history: [(2, 'entry hash does not match its content (tampered)')]"
    );
}

#[test]
fn cli_previous_audit_keys_are_trusted_after_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let old = common::keyfiles(dir.path(), "old");
    let new = common::keyfiles(dir.path(), "new");
    let path = dir.path().join("audit.log");
    AuditLog::new(&path, &old.private_str, "gw", "d", TrustedKeys::new())
        .unwrap()
        .record(record("ALLOW"))
        .unwrap();
    AuditLog::new(&path, &new.private_str, "gw", "d", trusted(&old.public_str))
        .unwrap()
        .record(record("ALLOW"))
        .unwrap();
    let alone = bm(
        dir.path(),
        &["audit-verify", "--log", "audit.log", "--pub", "new.pub"],
    );
    assert_eq!(alone.status.code(), Some(1));
    let both = bm(
        dir.path(),
        &[
            "audit-verify",
            "--log",
            "audit.log",
            "--pub",
            "new.pub",
            "--previous-pub",
            "old.pub",
        ],
    );
    assert!(both.status.success(), "{}", stderr(&both));
    let head = bm(
        dir.path(),
        &[
            "audit-head",
            "--log",
            "audit.log",
            "--key",
            "new.key",
            "--previous-pub",
            "old.pub",
        ],
    );
    assert!(head.status.success(), "{}", stderr(&head));
}
