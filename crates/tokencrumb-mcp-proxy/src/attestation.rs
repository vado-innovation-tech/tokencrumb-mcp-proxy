//! Per-call attestation (profiles 3a / 3b).
//!
//! The agent signs a canonical (JCS) payload binding the exact call to the exact
//! capability. The proxy re-derives every bound value from the real request and
//! verifies the Ed25519 signature against the agent public key obtained via the
//! provenance rule (3b: anchored in the Biscuit) or the registry (3a).
//!
//! Header wire format:  `Agent-Attestation: base64url( JSON({"payload":..,"sig":..}) )`

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde_json::{Map, Value, json};

use crate::canonical::{arguments_hash, canonicalize, sha256_hex};
use crate::error::{Error, Result};
use crate::isotime::{Parsed, fromisoformat, iso_z, timestamp};
use crate::json::{dumps, strict_json};
use crate::keys;
use crate::nonce_cache::NonceStore;
use crate::validation::string;

pub const DOMAIN: &str = "biscuitmcp/tools-call";
pub const VERSION: i64 = 2;

/// SHA-256 (hex) of the exact presented base64 token string.
pub fn biscuit_hash(token_b64: &str) -> String {
    sha256_hex(token_b64.as_bytes())
}

pub fn b64u_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// `urlsafe_b64decode(text + padding)` with Python's lenient decoder: characters
/// outside the alphabet are discarded and decoding stops at the first padding.
pub fn b64u_decode(text: &str) -> Result<Vec<u8>> {
    let mut data = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '-' => data.push('+'),
            '_' => data.push('/'),
            'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '/' => data.push(c),
            '=' => break,
            _ => {}
        }
    }
    if data.len() % 4 == 1 {
        return Err(Error::value(format!(
            "Invalid base64-encoded string: number of data characters ({}) cannot be 1 more than a multiple of 4",
            data.len()
        )));
    }
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(true),
    );
    engine
        .decode(data.as_bytes())
        .map_err(|e| Error::value(e.to_string()))
}

/// The `Agent-Attestation` header value for one call (client-wrap side).
pub fn build_attestation(
    agent_id: &str,
    tool: &str,
    arguments: &Value,
    token_b64: &str,
    agent_private_str: &str,
    now: Option<DateTime<Utc>>,
) -> Result<String> {
    let ts = now.unwrap_or_else(Utc::now);
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce); // 128-bit CSPRNG
    let payload = json!({
        "version": VERSION,
        "domain": DOMAIN,
        "agent_id": agent_id,
        "tool": tool,
        "arguments_hash": arguments_hash(arguments)?,
        "nonce": hex::encode(nonce),
        "timestamp": iso_z(&ts),
        "biscuit_hash": biscuit_hash(token_b64),
    });
    let sig = keys::sign(agent_private_str, &canonicalize(&payload)?)?;
    let envelope = json!({"payload": payload, "sig": b64u_encode(&sig)});
    Ok(b64u_encode(dumps(&envelope).as_bytes()))
}

/// Per-check proof flags: each is only set after the corresponding real check.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AttestationResult {
    pub ok: bool,
    pub reason: Option<String>,
    pub agent_id: Option<String>,
    pub call_signature_valid: bool,
    pub nonce_fresh: bool,
    pub arguments_bound: bool,
    pub capability_bound: bool,
    pub nonce_key: Option<String>,
    pub nonce_expires_at: Option<f64>,
}

impl AttestationResult {
    fn refused(reason: impl Into<String>, agent_id: Option<String>, signature_valid: bool) -> Self {
        Self {
            ok: false,
            reason: Some(reason.into()),
            agent_id,
            call_signature_valid: signature_valid,
            ..Default::default()
        }
    }
}

/// Everything a verification compares the attestation against.
pub struct Expected<'a> {
    pub agent_pubkey: &'a str,
    pub tool: &'a str,
    pub arguments_hash: &'a str,
    pub token_b64: &'a str,
    pub now: DateTime<Utc>,
    pub freshness_seconds: i128,
    pub clock_skew_seconds: i128,
}

fn key<'a>(map: &'a Map<String, Value>, name: &str) -> Result<&'a Value> {
    map.get(name)
        .ok_or_else(|| Error::value(format!("'{name}'")))
}

struct Envelope {
    payload: Map<String, Value>,
    sig: Vec<u8>,
    nonce: String,
    ts: DateTime<chrono::FixedOffset>,
}

fn parse(header: &str) -> Result<Envelope> {
    if header.chars().count() > 8192 {
        return Err(Error::value("attestation exceeds size limit"));
    }
    let envelope = strict_json(b64u_decode(header)?)?;
    let Value::Object(envelope) = envelope else {
        return Err(Error::value(format!(
            "'{}' object is not subscriptable",
            crate::json::py_type_name(&envelope)
        )));
    };
    let payload = key(&envelope, "payload")?.clone();
    let sig = match key(&envelope, "sig")? {
        Value::String(s) => b64u_decode(s)?,
        other => {
            return Err(Error::value(format!(
                "sig must be a string, not {}",
                crate::json::py_type_name(other)
            )));
        }
    };
    let Value::Object(payload) = payload else {
        return Err(Error::value("payload must be an object"));
    };
    let text = |name: &str, place: &str| -> Result<()> {
        match payload.get(name) {
            Some(Value::String(s)) => string(s, place, 256).map(|_| ()),
            _ => Err(Error::value(format!(
                "{place}: expected a nonempty string without surrounding whitespace"
            ))),
        }
    };
    text("agent_id", "attestation agent_id")?;
    text("tool", "attestation tool")?;
    let nonce = match payload.get("nonce") {
        Some(Value::String(n)) if (16..=128).contains(&n.chars().count()) && n.is_ascii() => {
            n.clone()
        }
        _ => return Err(Error::value("nonce must be 16–128 ASCII characters")),
    };
    let ts = match key(&payload, "timestamp")? {
        Value::String(t) => match fromisoformat(t)? {
            Parsed::Aware(ts) => ts,
            Parsed::Naive(_) => return Err(Error::value("timestamp must include timezone")),
        },
        _ => return Err(Error::value("fromisoformat: argument must be str")),
    };
    let version_ok = matches!(payload.get("version"), Some(v) if crate::json::as_integer(v) == Some(VERSION.into()));
    if !version_ok || payload.get("domain").and_then(Value::as_str) != Some(DOMAIN) {
        return Err(Error::value(
            "unsupported attestation version/domain; regenerate with client-wrap",
        ));
    }
    Ok(Envelope {
        payload,
        sig,
        nonce,
        ts,
    })
}

/// Verify one attestation against the real call (proxy side).
///
/// With `commit_nonce` false the nonce is only checked for shape and freshness; the
/// caller records it once every other check has passed.
pub fn verify_attestation(
    header: &str,
    expected: &Expected<'_>,
    nonce_cache: &dyn NonceStore,
    commit_nonce: bool,
) -> AttestationResult {
    let parsed = match parse(header) {
        Ok(p) => p,
        Err(e) => {
            return AttestationResult::refused(
                format!("malformed attestation: {}", e.message),
                None,
                false,
            );
        }
    };
    let payload = Value::Object(parsed.payload.clone());
    let agent_id = parsed
        .payload
        .get("agent_id")
        .and_then(Value::as_str)
        .map(str::to_owned);

    // 1) signature over the canonical payload (constant-time Ed25519)
    let signed = canonicalize(&payload)
        .and_then(|message| keys::verify(expected.agent_pubkey, &parsed.sig, &message));
    if let Err(e) = signed {
        return AttestationResult::refused(
            format!("attestation signature invalid: {}", e.message),
            agent_id,
            false,
        );
    }

    // 2) tool binding — the signed tool must match the invoked tool
    if parsed.payload.get("tool").and_then(Value::as_str) != Some(expected.tool) {
        return AttestationResult::refused("attestation tool mismatch", agent_id, true);
    }
    // 3) argument binding — compare against the hash of the REAL arguments
    if parsed.payload.get("arguments_hash").and_then(Value::as_str) != Some(expected.arguments_hash)
    {
        return AttestationResult::refused("arguments_hash mismatch (tampering)", agent_id, true);
    }
    // 4) capability binding — attestation is bound to THIS token
    if parsed.payload.get("biscuit_hash").and_then(Value::as_str)
        != Some(biscuit_hash(expected.token_b64).as_str())
    {
        return AttestationResult::refused(
            "biscuit_hash mismatch (token substitution)",
            agent_id,
            true,
        );
    }

    // 5) freshness — reject stale and clock-aberrant (future) timestamps
    let delta = timestamp(&expected.now) - timestamp(&parsed.ts);
    if delta < -(expected.clock_skew_seconds as f64) {
        return AttestationResult::refused(
            "timestamp in the future (clock aberrant)",
            agent_id,
            true,
        );
    }
    if delta > (expected.freshness_seconds + expected.clock_skew_seconds) as f64 {
        return AttestationResult::refused("attestation stale", agent_id, true);
    }

    // 6) anti-replay — nonce must be unseen (fail-closed if cache full)
    let nonce_key = sha256_hex(format!("{}:{}", expected.agent_pubkey, parsed.nonce).as_bytes());
    let nonce_expires_at = timestamp(&parsed.ts)
        + (expected.freshness_seconds + expected.clock_skew_seconds + 1) as f64;
    let mut result = AttestationResult {
        ok: true,
        reason: None,
        agent_id: agent_id.clone(),
        call_signature_valid: true,
        nonce_fresh: false,
        arguments_bound: true,
        capability_bound: true,
        nonce_key: Some(nonce_key.clone()),
        nonce_expires_at: Some(nonce_expires_at),
    };
    if commit_nonce {
        let fresh = nonce_cache
            .check_and_add(&nonce_key, timestamp(&expected.now), Some(nonce_expires_at))
            .unwrap_or(false);
        if !fresh {
            return AttestationResult::refused("nonce replay or cache full", agent_id, true);
        }
    }
    result.nonce_fresh = true;
    result
}
