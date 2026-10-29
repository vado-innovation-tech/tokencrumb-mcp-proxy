//! `approve` and `inspect-receipt`: the approver's side of a held call (HOLD, lot 1).
//!
//! The request file travels through the agent's side, which can alter it: everything
//! shown is recomputed (arguments hash, intent hash) or neutralized before display,
//! and nothing is signed that the approver was not shown.

use std::io::{BufRead as _, Read as _};

use chrono::Utc;
use serde_json::Value;
use tokencrumb_mcp_proxy::approval::{self, Receipt, check_request, neutralize, sign_receipt};
use tokencrumb_mcp_proxy::json::{dumps_indent, strict_json};
use tokencrumb_mcp_proxy::storage;

use super::render::{Stream, paint};
use super::{Outcome, fail, load_private, say, status};

const MAX_REQUEST_FILE: u64 = 1024 * 1024;

fn read_json(path: &str, what: &str) -> Result<Value, super::Exit> {
    let file = std::fs::File::open(path).or_else(|e| fail(format!("cannot read {what}: {e}")))?;
    let mut raw = Vec::new();
    file.take(MAX_REQUEST_FILE + 1)
        .read_to_end(&mut raw)
        .or_else(|e| fail(format!("cannot read {what}: {e}")))?;
    if raw.len() as u64 > MAX_REQUEST_FILE {
        return fail(format!("{what} exceeds 1 MiB"));
    }
    strict_json(&raw).or_else(|e| fail(format!("invalid {what}: {}", e.message)))
}

/// One `label : value` line, neutralized; true when the value had to be escaped.
fn line(label: &str, value: &Value) -> (String, bool) {
    let text = match value {
        Value::String(s) => s.clone(),
        Value::Null => "-".to_owned(),
        other => other.to_string(),
    };
    let (shown, flagged) = neutralize(&text);
    (format!("  {label:<15}: {shown}"), flagged)
}

pub fn approve(
    request: &str,
    key: &str,
    approver_id: &str,
    ttl: &str,
    passphrase: Option<&str>,
    out: Option<&str>,
    yes: bool,
) -> Outcome {
    let document = read_json(request, "request")?;
    let checked = check_request(&document).or_else(|e| fail(format!("refused: {}", e.message)))?;
    let ttl_seconds = tokencrumb_mcp_proxy::duration::parse_duration(ttl)
        .or_else(|e| fail(format!("invalid --ttl: {}", e.message)))?;
    let private =
        load_private(key, passphrase).or_else(|e| fail(format!("cannot load private key: {e}")))?;

    // Everything shown is what the intent hash covers, recomputed above.
    let intent = &checked.intent;
    let mut flagged = false;
    let mut lines = vec![paint("approval request", "1", Stream::Stderr)];
    for (label, value) in [
        ("request", Value::String(checked.request_id.clone())),
        ("tool", intent["tool"].clone()),
        ("operation", intent["operation"].clone()),
        ("resource", intent["resource"].clone()),
        ("agent_id", intent["agent_id"].clone()),
        ("agent_key", intent["agent_key"].clone()),
        ("mandate_hash", intent["mandate_hash"].clone()),
        ("audience", intent["audience"].clone()),
        ("arguments_hash", intent["arguments_hash"].clone()),
        ("intent_hash", Value::String(checked.intent_hash.clone())),
        ("approvers", Value::String(checked.approvers.join(", "))),
    ] {
        let (text, escaped) = line(label, &value);
        flagged |= escaped;
        lines.push(text);
    }
    lines.push("  arguments      :".to_owned());
    let pretty = serde_json::to_string_pretty(&checked.arguments).unwrap_or_default();
    for raw in pretty.lines() {
        // serde escapes control characters inside strings; bidi and invisible ones
        // pass through JSON untouched and are caught here. Long values are shown whole.
        let (shown, escaped) = neutralize(raw);
        flagged |= escaped;
        lines.push(format!("    {shown}"));
    }
    if pretty.contains("\\u00") {
        flagged = true;
    }
    for text in &lines {
        status(text);
    }
    if flagged {
        status(&paint(
            "WARNING: the request contains control, invisible or direction characters; \
             they are shown escaped. Read the values above carefully.",
            "1;33",
            Stream::Stderr,
        ));
    }

    if !yes {
        status("Sign an approval for exactly this call? [y/N]");
        let mut answer = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut answer)
            .or_else(|e| fail(format!("cannot read the confirmation: {e}")))?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            return fail("approval not confirmed; nothing signed");
        }
    }
    let receipt = sign_receipt(
        &private,
        approver_id,
        &checked.request_id,
        &checked.intent_hash,
        Utc::now(),
        ttl_seconds,
    )?;
    let text = dumps_indent(&receipt, 2);
    let label = paint("approval receipt", "32", Stream::Stderr);
    match out.filter(|o| !o.is_empty()) {
        Some(out) => {
            storage::write_secure(out, format!("{text}\n").as_bytes())?;
            status(&format!("{label} -> {out}"));
        }
        None => {
            status(&format!("{label}:"));
            say(&text);
        }
    }
    Ok(())
}

/// Decode a receipt and check what can be checked offline: its form, its signature by
/// the key it names and, with the request, that it covers that intent. Whether the key
/// belongs to a registered approver is the gateway's policy, not checked here.
pub fn inspect_receipt(receipt: &str, request: Option<&str>) -> Outcome {
    let raw = read_json(receipt, "receipt")?;
    let decoded =
        Receipt::from_json(&raw).or_else(|_| fail(approval::reason::MALFORMED.to_string()))?;
    let mut rows = vec![
        ("receipt_id", decoded.receipt_id.clone()),
        ("request_id", decoded.request_id.clone()),
        ("intent_hash", decoded.intent_hash.clone()),
        ("approver", decoded.approver_id.clone()),
        ("key", decoded.approver_key.clone()),
        ("issued_at", decoded.issued_at.to_rfc3339()),
        ("expires_at", decoded.expires_at.to_rfc3339()),
    ];
    let signature = decoded.signature_valid();
    rows.push((
        "signature",
        if signature { "valid" } else { "INVALID" }.to_owned(),
    ));
    let mut matches = true;
    if let Some(request) = request {
        let checked = check_request(&read_json(request, "request")?)
            .or_else(|e| fail(format!("refused: {}", e.message)))?;
        matches = checked.intent_hash == decoded.intent_hash;
        rows.push((
            "request",
            if matches { "matches" } else { "MISMATCH" }.to_owned(),
        ));
    }
    for (label, value) in rows {
        say(&format!("{label:<11}: {}", neutralize(&value).0));
    }
    if !signature {
        return fail(approval::reason::SIGNATURE);
    }
    if !matches {
        return fail(approval::reason::INTENT);
    }
    Ok(())
}
