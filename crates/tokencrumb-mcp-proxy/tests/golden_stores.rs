//! Differential tests on stored formats: an audit chain, a head attestation and a
//! revocation snapshot written by the former implementation stay valid, and ours are
//! serialized byte for byte the way it wrote them.

mod common;

use tokencrumb_mcp_proxy::audit::{
    self, AuditLog, Record, trusted_from, verify_head_attestation, verify_log,
};
use tokencrumb_mcp_proxy::json::{dumps, strict_json};
use tokencrumb_mcp_proxy::revocation::{migrate_legacy_list, validate_document};
use common::{golden, key};
use serde_json::json;

#[test]
fn python_audit_chain_verifies_and_resumes() {
    let corpus = golden("audit.json");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let text = corpus["log"].as_str().unwrap();
    std::fs::write(&path, text).unwrap();
    let public = corpus["public"].as_str().unwrap().to_owned();
    let trusted = trusted_from(&[public.clone()]).unwrap();

    let result = verify_log(&path, &trusted).unwrap();
    assert!(result.ok, "{:?}", result.failures);
    assert_eq!(json!(result.entries), corpus["verify"]["entries"]);
    assert_eq!(json!(result.head), corpus["verify"]["head"]);
    assert!(verify_head_attestation(&corpus["head"], &public));

    // Our rendering of each stored line is the line itself.
    for line in text.lines() {
        assert_eq!(dumps(&strict_json(line).unwrap()), line);
    }

    // Resume the chain the Python proxy started, then re-verify the whole of it.
    let log = AuditLog::new(
        &path,
        &key("audit", "private"),
        "gw-golden",
        "digest-2",
        Default::default(),
    )
    .unwrap();
    let record = log
        .record(Record {
            decision: "ALLOW".into(),
            method: Some("tools/call".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(record["entry"]["seq"], json!(3));
    assert_eq!(record["entry"]["prev_hash"], corpus["verify"]["head"]);
    let result = verify_log(&path, &trusted).unwrap();
    assert!(result.ok && result.entries == 4);
    let head =
        audit::head_attestation(&path, &key("audit", "private"), None, Default::default()).unwrap();
    assert!(verify_head_attestation(&head, &public));
    assert_eq!(head["seq"], json!(3));
    assert_eq!(head["gateway_id"], json!("gw-golden"));
}

#[test]
fn python_revocation_snapshots_validate() {
    let corpus = golden("revocation.json");
    let now = corpus["now"].as_f64().unwrap();
    let public = corpus["public"].as_str().unwrap();
    validate_document(&corpus["doc"], public, Some(now), true).unwrap();
    assert_eq!(corpus["doc"]["revoked"], json!(["a", "b"]));
    let expired = validate_document(&corpus["doc"], public, Some(now + 3600.0), true).unwrap_err();
    assert_eq!(
        expired.message,
        "invalid revocation snapshot: revocation snapshot expired or from the future"
    );
    let mut forged = corpus["doc"].clone();
    forged["revoked"] = json!(["a"]);
    let refused = validate_document(&forged, public, Some(now), true).unwrap_err();
    assert_eq!(refused.message, "invalid revocation snapshot: ");
    let migrated = migrate_legacy_list(
        &corpus["legacy"],
        corpus["legacy_public"].as_str().unwrap(),
        &key("authority", "private"),
    )
    .unwrap();
    assert_eq!(migrated["revoked"], json!(["x", "y"]));
    validate_document(&migrated, public, None, true).unwrap();
}
