//! Human approval of one exact tool call (HOLD, lot 1).
//!
//! A tool declared with `approval:` in the policy is *confirmed*: the gateway never
//! forwards a call to it without a receipt — an Ed25519 signature by a registered
//! approver over the hash of the call's *intent* (tool, operation, canonical resource,
//! arguments hash, mandate hash, agent and audience). A call without a receipt is held:
//! the gateway answers "approval required" with the intent to sign, consumes the
//! attestation nonce, and charges nothing. The replay carries a fresh attestation and
//! the receipt, which is consumed exactly once, durably, before the call is forwarded.
//!
//! An approval never creates a right: every other check still runs first, and the
//! receipt is only looked at once the mandate, the policy and the budget allow the call.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, SecondsFormat, Utc};
use rand::RngCore;
use serde_json::{Map, Value, json};

use crate::canonical::{arguments_hash, canonicalize, sha256_hex};
use crate::duration::parse_duration;
use crate::error::{Error, Result, py_repr};
use crate::json::{dumps, strict_json};
use crate::keys;
use crate::policy::{Policy, ThirdPartyAuthority};
use crate::validation::{integer, mapping, public_key, string_value};

/// The request header carrying a receipt: `base64url(JSON(receipt))`. It is never
/// propagated upstream (only the session headers are, `proxy::upstream::PROPAGATE`).
pub const RECEIPT_HEADER: &str = "approval-receipt";
/// Largest receipt header accepted, in bytes.
pub const MAX_RECEIPT_HEADER: usize = 4096;
pub const INTENT_VERSION: i64 = 1;
pub const RECEIPT_VERSION: i64 = 1;
/// At most this many keys per approver: the current one and its predecessors.
pub const MAX_APPROVER_KEYS: usize = 8;
/// Bounds of `approval.receipt_ttl`, in seconds.
pub const MIN_RECEIPT_TTL: i128 = 1;
pub const MAX_RECEIPT_TTL: i128 = 3600;

/// The proofs whose facts an approval intent depends on: the agent key and the
/// arguments hash bound by the attestation.
pub const REQUIRED_PROOFS: &[&str] = &["call_signature_valid", "nonce_fresh", "arguments_bound"];

/// Refusal reasons written to the audit log; their text is stable and tested.
pub mod reason {
    pub const MALFORMED: &str = "receipt malformed";
    pub const NOT_REGISTERED: &str = "receipt signer not registered for this tool";
    pub const AGENT_KEY: &str = "receipt signed by the agent key";
    pub const SIGNATURE: &str = "receipt signature invalid";
    pub const INTENT: &str = "receipt intent mismatch";
    pub const EXPIRED: &str = "receipt expired";
    pub const LIFETIME: &str = "receipt lifetime exceeds policy";
    /// Not in the lot-1 list: `issued_at` beyond the tolerated clock skew.
    pub const FUTURE: &str = "receipt issued in the future";
    pub const USED: &str = "receipt already used";
    /// The receipt table is at capacity; nothing is reserved (fail closed).
    pub const FULL: &str = "receipt store full";
}

// --------------------------------------------------------------------------- //
// policy
// --------------------------------------------------------------------------- //

/// One registered person and the keys that sign for them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproverMember {
    pub id: String,
    /// `ed25519/<hex>`, lowercase; alternatives for rotation, never a quorum.
    pub keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproverGroup {
    pub name: String,
    pub members: Vec<ApproverMember>,
}

/// `approval:` on a tool: the tool is confirmed, one receipt per call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequirement {
    /// Group names, each declared under `approvers:`.
    pub approvers: Vec<String>,
    pub receipt_ttl_seconds: i128,
}

fn is_group_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn is_member_id(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._@-".contains(&b))
}

/// Parse `approvers:`. A key belongs to one member in the whole policy and is never a
/// third-party authority key; root and audit keys are checked by [`separated`].
pub fn parse_approvers(
    raw: &Value,
    third_party: &[ThirdPartyAuthority],
) -> Result<Vec<ApproverGroup>> {
    let Value::Object(entries) = raw else {
        return Err(Error::value("approvers: expected an object"));
    };
    let mut groups: Vec<ApproverGroup> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for (name, entry) in entries {
        if !is_group_name(name) {
            return Err(Error::value(format!(
                "approvers: invalid group name {}",
                py_repr(name)
            )));
        }
        let place = format!("approvers.{name}");
        let entry = mapping(entry, &["members"], &place)?;
        let members_raw = entry
            .get("members")
            .and_then(Value::as_array)
            .filter(|m| !m.is_empty())
            .ok_or_else(|| Error::value(format!("{place}.members: expected a non-empty list")))?;
        let mut members: Vec<ApproverMember> = Vec::new();
        for member in members_raw {
            let member = mapping(member, &["id", "keys"], &format!("{place}.members"))?;
            let id = string_value(member.get("id"), &format!("{place}.members.id"), 128)?;
            if !is_member_id(id) {
                return Err(Error::value(format!(
                    "{place}.members: invalid id {}",
                    py_repr(id)
                )));
            }
            if members.iter().any(|m| m.id == id) {
                return Err(Error::value(format!(
                    "{place}.members: id {} declared twice",
                    py_repr(id)
                )));
            }
            let keys_raw = member
                .get("keys")
                .and_then(Value::as_array)
                .ok_or_else(|| Error::value(format!("{place}.{id}.keys: expected a list")))?;
            if keys_raw.is_empty() || keys_raw.len() > MAX_APPROVER_KEYS {
                return Err(Error::value(format!(
                    "{place}.{id}.keys: expected 1 to {MAX_APPROVER_KEYS} keys"
                )));
            }
            let mut keys: Vec<String> = Vec::new();
            for key in keys_raw {
                let text = string_value(Some(key), &format!("{place}.{id}.keys"), 72)?;
                let key = public_key(text).map_err(|_| {
                    Error::value(format!(
                        "{place}.{id}.keys: expected ed25519/<64 hex digits>"
                    ))
                })?;
                // Two keys do not prove two persons: one key, one member, policy-wide.
                if keys.contains(&key) || seen.contains(&key) {
                    return Err(Error::value(format!(
                        "{place}.{id}.keys: a key belongs to one approver only"
                    )));
                }
                if third_party.iter().any(|a| a.keys.contains(&key)) {
                    return Err(Error::value(format!(
                        "{place}.{id}.keys: an approver key cannot be a third-party authority key"
                    )));
                }
                seen.push(key.clone());
                keys.push(key);
            }
            members.push(ApproverMember {
                id: id.to_owned(),
                keys,
            });
        }
        groups.push(ApproverGroup {
            name: name.clone(),
            members,
        });
    }
    Ok(groups)
}

/// Parse a tool's `approval:` block. The intent needs the agent key and the arguments
/// hash the attestation binds, so the three proofs are mandatory.
pub fn parse_requirement(
    tool: &str,
    raw: &Value,
    groups: &[ApproverGroup],
    require: &[String],
) -> Result<ApprovalRequirement> {
    let place = format!("{tool}.approval");
    let entry = mapping(raw, &["approvers", "receipt_ttl"], &place)?;
    let names = entry
        .get("approvers")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| Error::value(format!("{place}.approvers: expected a non-empty list")))?;
    let mut approvers: Vec<String> = Vec::new();
    for name in names {
        let name = string_value(Some(name), &format!("{place}.approvers"), 64)?;
        if !groups.iter().any(|g| g.name == name) {
            return Err(Error::value(format!(
                "tool {}: approver group {} is not declared in `approvers:`",
                py_repr(tool),
                py_repr(name)
            )));
        }
        if !approvers.iter().any(|a| a == name) {
            approvers.push(name.to_owned());
        }
    }
    let ttl = match entry.get("receipt_ttl") {
        Some(Value::String(s)) => parse_duration(s)?,
        Some(_) => {
            return Err(Error::value(format!(
                "{place}.receipt_ttl: expected a duration such as 5m"
            )));
        }
        None => 300,
    };
    let receipt_ttl_seconds = integer(
        ttl,
        &format!("{place}.receipt_ttl"),
        MIN_RECEIPT_TTL,
        MAX_RECEIPT_TTL,
    )?;
    for proof in REQUIRED_PROOFS {
        if !require.iter().any(|r| r == proof) {
            return Err(Error::value(format!(
                "tool {}: approval requires `require: [{}]`",
                py_repr(tool),
                REQUIRED_PROOFS.join(", ")
            )));
        }
    }
    Ok(ApprovalRequirement {
        approvers,
        receipt_ttl_seconds,
    })
}

/// Self-approval guard: no approver key may be a root authority key, a third-party
/// authority key or one of `forbidden` (the audit signer). Checked at startup, on
/// every reload and on every call.
pub fn separated(policy: &Policy, authority_keys: &[String], forbidden: &[String]) -> Result<()> {
    for group in &policy.approvers {
        for member in &group.members {
            for key in &member.keys {
                let same = |other: &String| other.eq_ignore_ascii_case(key);
                let role = if authority_keys.iter().any(same) {
                    Some("a root authority key")
                } else if policy.third_party.iter().any(|a| a.keys.iter().any(same)) {
                    Some("a third-party authority key")
                } else if forbidden.iter().any(same) {
                    Some("the audit key")
                } else {
                    None
                };
                if let Some(role) = role {
                    return Err(Error::value(format!(
                        "approver {}.{} reuses {role}",
                        group.name, member.id
                    )));
                }
            }
        }
    }
    Ok(())
}

/// The member of `groups` holding `key`, if any.
pub fn member_for<'a>(
    policy: &'a Policy,
    groups: &[String],
    key: &str,
) -> Option<&'a ApproverMember> {
    policy
        .approvers
        .iter()
        .filter(|g| groups.contains(&g.name))
        .flat_map(|g| g.members.iter())
        .find(|m| m.keys.iter().any(|k| k.eq_ignore_ascii_case(key)))
}

// --------------------------------------------------------------------------- //
// intent
// --------------------------------------------------------------------------- //

/// What the gateway saw of one call, as the approver signs it.
pub struct IntentInput<'a> {
    pub tool: &'a str,
    pub operation: &'a str,
    pub resource: Option<&'a str>,
    pub arguments_hash: &'a str,
    pub mandate_hash: &'a str,
    pub agent_id: Option<&'a str>,
    pub agent_key: &'a str,
    pub audience: &'a str,
}

const INTENT_FIELDS: &[&str] = &[
    "v",
    "tool",
    "operation",
    "resource",
    "arguments_hash",
    "mandate_hash",
    "agent_id",
    "agent_key",
    "audience",
];

/// The intent (version 1). It depends only on the call, the mandate and the gateway
/// configuration, so an identical replay yields the same hash.
pub fn intent(input: &IntentInput<'_>) -> Value {
    json!({
        "v": INTENT_VERSION,
        "tool": input.tool,
        "operation": input.operation,
        "resource": input.resource,
        "arguments_hash": input.arguments_hash,
        "mandate_hash": input.mandate_hash,
        "agent_id": input.agent_id,
        "agent_key": input.agent_key,
        "audience": input.audience,
    })
}

/// `sha256:` + hex(SHA-256(JCS(intent))).
pub fn intent_hash(intent: &Value) -> Result<String> {
    Ok(format!("sha256:{}", sha256_hex(&canonicalize(intent)?)))
}

/// Refuse an intent this build does not know: other version, other fields, wrong types.
pub fn check_intent(intent: &Value) -> Result<()> {
    let Value::Object(map) = intent else {
        return Err(Error::value("intent: expected an object"));
    };
    if map.get("v") != Some(&json!(INTENT_VERSION)) {
        return Err(Error::value("intent: unknown version"));
    }
    if map.len() != INTENT_FIELDS.len() || INTENT_FIELDS.iter().any(|f| !map.contains_key(*f)) {
        return Err(Error::value("intent: unexpected fields"));
    }
    for field in [
        "tool",
        "operation",
        "arguments_hash",
        "mandate_hash",
        "agent_key",
        "audience",
    ] {
        if !map[field].is_string() {
            return Err(Error::value(format!("intent: {field} must be a string")));
        }
    }
    for field in ["resource", "agent_id"] {
        if !(map[field].is_string() || map[field].is_null()) {
            return Err(Error::value(format!(
                "intent: {field} must be a string or null"
            )));
        }
    }
    Ok(())
}

/// A random identifier: `prefix` + 128 bits in hex.
pub fn new_id(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("{prefix}{}", hex::encode(bytes))
}

fn is_request_id(id: &str) -> bool {
    id.len() == 36
        && id.starts_with("apr_")
        && id[4..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn rfc3339(value: &DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}

// --------------------------------------------------------------------------- //
// HOLD and approval records
// --------------------------------------------------------------------------- //

/// A call held for approval: what the gateway answers and records.
#[derive(Debug, Clone, PartialEq)]
pub struct Hold {
    /// Informative: links the HOLD entry, the receipt and the ALLOW entry.
    pub request_id: String,
    pub intent: Value,
    pub intent_hash: String,
    /// The call's arguments, which the intent's `arguments_hash` summarizes.
    pub arguments: Value,
    pub approvers: Vec<String>,
    /// Informative: the answer time plus the tool's `receipt_ttl`.
    pub expires_at: String,
}

impl Hold {
    /// `{"approval_required": {...}}`, the object the client and `approve` read.
    pub fn to_json(&self) -> Value {
        json!({"approval_required": {
            "request_id": self.request_id,
            "intent": self.intent,
            "intent_hash": self.intent_hash,
            "arguments": self.arguments,
            "approvers": self.approvers,
            "expires_at": self.expires_at,
        }})
    }

    pub fn audit_detail(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "intent_hash": self.intent_hash,
            "approvers": self.approvers,
        })
    }
}

/// The receipt an allowed call consumed, for the audit entry and the outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approved {
    pub receipt_id: String,
    pub request_id: String,
    pub approver_id: String,
    pub key: String,
    pub intent_hash: String,
}

impl Approved {
    pub fn audit_detail(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "request_id": self.request_id,
            "approver_id": self.approver_id,
            "key": self.key,
            "intent_hash": self.intent_hash,
        })
    }
}

/// The `tools/call` answer to a held call: a tool result with `isError: true`, as a
/// denial, whose first block names the request and whose second carries the object.
/// `structuredContent` repeats it: the gateway keeps no upstream `outputSchema` it could
/// contradict.
pub fn hold_result(id: Value, correlation_id: &str, hold: &Hold) -> Value {
    let object = hold.to_json();
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": format!(
                        "APPROVAL REQUIRED — request {} · correlation_id: {correlation_id}",
                        hold.request_id
                    ),
                },
                {"type": "text", "text": dumps(&object)},
            ],
            "structuredContent": object,
            "isError": true,
        },
    })
}

/// The `approval_required` object of a `tools/call` response, if it is one.
pub fn approval_required(response: &Value) -> Option<Value> {
    let result = response.get("result")?;
    if let Some(found) = result
        .get("structuredContent")
        .and_then(|s| s.get("approval_required"))
    {
        return Some(found.clone());
    }
    result
        .get("content")?
        .as_array()?
        .iter()
        .filter_map(|block| block.get("text").and_then(Value::as_str))
        .filter_map(|text| strict_json(text.as_bytes()).ok())
        .find_map(|v| v.get("approval_required").cloned())
}

// --------------------------------------------------------------------------- //
// receipt
// --------------------------------------------------------------------------- //

const RECEIPT_FIELDS: &[&str] = &[
    "v",
    "receipt_id",
    "request_id",
    "intent_hash",
    "decision",
    "approver",
    "issued_at",
    "expires_at",
    "max_uses",
    "sig",
];

/// A decoded receipt, not yet trusted.
#[derive(Debug, Clone, PartialEq)]
pub struct Receipt {
    pub receipt_id: String,
    pub request_id: String,
    pub intent_hash: String,
    pub approver_id: String,
    pub approver_key: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// The receipt without `sig`, as signed.
    unsigned: Value,
    sig: Vec<u8>,
}

fn malformed() -> Error {
    Error::value(reason::MALFORMED)
}

fn is_hash(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn date(value: Option<&Value>) -> Result<DateTime<Utc>> {
    let text = value.and_then(Value::as_str).ok_or_else(malformed)?;
    if text.len() > 40 {
        return Err(malformed());
    }
    DateTime::parse_from_rfc3339(text)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|_| malformed())
}

impl Receipt {
    /// Decode the `approval-receipt` header: bounded base64url of a strict JSON object.
    pub fn from_header(header: &str) -> Result<Self> {
        if header.len() > MAX_RECEIPT_HEADER {
            return Err(malformed());
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(header.trim().trim_end_matches('='))
            .map_err(|_| malformed())?;
        Self::from_json(&strict_json(&bytes).map_err(|_| malformed())?)
    }

    /// Every field present, typed and bounded; nothing else. Lot 1 knows `v: 1`,
    /// `decision: approve` and `max_uses: 1` only.
    pub fn from_json(value: &Value) -> Result<Self> {
        let Value::Object(map) = value else {
            return Err(malformed());
        };
        if map.len() != RECEIPT_FIELDS.len() || RECEIPT_FIELDS.iter().any(|f| !map.contains_key(*f))
        {
            return Err(malformed());
        }
        if map["v"] != json!(RECEIPT_VERSION)
            || map["decision"] != json!("approve")
            || map["max_uses"] != json!(1)
        {
            return Err(malformed());
        }
        let text = |name: &str, max: usize| -> Result<String> {
            map[name]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= max)
                .map(str::to_owned)
                .ok_or_else(malformed)
        };
        let receipt_id = text("receipt_id", 128)?;
        // At least 128 bits of randomness, printable ASCII only.
        if receipt_id.len() < 20 || !receipt_id.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(malformed());
        }
        let request_id = text("request_id", 128)?;
        let intent_hash = text("intent_hash", 71)?;
        if !is_hash(&intent_hash) {
            return Err(malformed());
        }
        let Value::Object(approver) = &map["approver"] else {
            return Err(malformed());
        };
        if approver.len() != 2 {
            return Err(malformed());
        }
        let approver_id = approver
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| is_member_id(id))
            .ok_or_else(malformed)?
            .to_owned();
        let approver_key = approver
            .get("key")
            .and_then(Value::as_str)
            .and_then(|k| public_key(k).ok())
            .ok_or_else(malformed)?;
        let issued_at = date(map.get("issued_at"))?;
        let expires_at = date(map.get("expires_at"))?;
        if expires_at <= issued_at {
            return Err(malformed());
        }
        let sig = map["sig"]
            .as_str()
            .filter(|s| s.len() <= 128)
            .and_then(|s| URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok())
            .filter(|s| s.len() == 64)
            .ok_or_else(malformed)?;
        let mut unsigned = map.clone();
        unsigned.remove("sig");
        Ok(Self {
            receipt_id,
            request_id,
            intent_hash,
            approver_id,
            approver_key,
            issued_at,
            expires_at,
            unsigned: Value::Object(unsigned),
            sig,
        })
    }

    /// Ed25519 over JCS(receipt without `sig`), by the key the receipt names.
    pub fn signature_valid(&self) -> bool {
        canonicalize(&self.unsigned)
            .and_then(|payload| keys::verify(&self.approver_key, &self.sig, &payload))
            .is_ok()
    }

    pub fn to_json(&self) -> Value {
        let mut map = self.unsigned.as_object().cloned().unwrap_or_default();
        map.insert("sig".into(), json!(URL_SAFE_NO_PAD.encode(&self.sig)));
        Value::Object(map)
    }
}

/// Sign a receipt for `intent_hash` (approver side).
pub fn sign_receipt(
    approver_private: &str,
    approver_id: &str,
    request_id: &str,
    intent_hash: &str,
    issued_at: DateTime<Utc>,
    ttl_seconds: i128,
) -> Result<Value> {
    if !is_member_id(approver_id) {
        return Err(Error::value("invalid approver id"));
    }
    if !is_hash(intent_hash) {
        return Err(Error::value("invalid intent hash"));
    }
    let ttl = integer(ttl_seconds, "--ttl", MIN_RECEIPT_TTL, MAX_RECEIPT_TTL)?;
    let expires_at = issued_at + chrono::TimeDelta::seconds(ttl as i64);
    let mut receipt: Map<String, Value> = Map::new();
    receipt.insert("v".into(), json!(RECEIPT_VERSION));
    receipt.insert("receipt_id".into(), json!(new_id("rcp_")));
    receipt.insert("request_id".into(), json!(request_id));
    receipt.insert("intent_hash".into(), json!(intent_hash));
    receipt.insert("decision".into(), json!("approve"));
    receipt.insert(
        "approver".into(),
        json!({"id": approver_id, "key": keys::public_from_private(approver_private)?}),
    );
    receipt.insert("issued_at".into(), json!(rfc3339(&issued_at)));
    receipt.insert("expires_at".into(), json!(rfc3339(&expires_at)));
    receipt.insert("max_uses".into(), json!(1));
    let sig = keys::sign(
        approver_private,
        &canonicalize(&Value::Object(receipt.clone()))?,
    )?;
    receipt.insert("sig".into(), json!(URL_SAFE_NO_PAD.encode(sig)));
    Ok(Value::Object(receipt))
}

/// The `approval-receipt` header value for a receipt.
pub fn encode_receipt(receipt: &Value) -> String {
    URL_SAFE_NO_PAD.encode(dumps(receipt).as_bytes())
}

/// The receipt `expires_at` for a hold answered at `now`.
pub fn hold_expiry(now: DateTime<Utc>, ttl_seconds: i128) -> String {
    rfc3339(&(now + chrono::TimeDelta::seconds(ttl_seconds as i64)))
}

// --------------------------------------------------------------------------- //
// approver side: validate a request before showing it
// --------------------------------------------------------------------------- //

/// A request as `approve` checked it: the intent and the hash recomputed from what is
/// displayed, never taken from the file alone.
pub struct CheckedRequest {
    pub request_id: String,
    pub intent: Value,
    pub intent_hash: String,
    pub arguments: Value,
    pub approvers: Vec<String>,
}

/// Accept `{"approval_required": {...}}` or the inner object; recompute the arguments
/// hash and the intent hash, and refuse any disagreement or unknown intent version.
pub fn check_request(document: &Value) -> Result<CheckedRequest> {
    let inner = document.get("approval_required").unwrap_or(document);
    let Value::Object(map) = inner else {
        return Err(Error::value(
            "request: expected an approval_required object",
        ));
    };
    let request_id = map
        .get("request_id")
        .and_then(Value::as_str)
        .filter(|id| is_request_id(id))
        .ok_or_else(|| Error::value("request: invalid request_id"))?
        .to_owned();
    let intent = map
        .get("intent")
        .cloned()
        .ok_or_else(|| Error::value("request: no intent"))?;
    check_intent(&intent)?;
    let arguments = map
        .get("arguments")
        .cloned()
        .ok_or_else(|| Error::value("request: no arguments"))?;
    if arguments_hash(&arguments)? != intent["arguments_hash"].as_str().unwrap_or_default() {
        return Err(Error::value(
            "request: the arguments do not match the intent's arguments_hash",
        ));
    }
    let recomputed = intent_hash(&intent)?;
    if map.get("intent_hash").and_then(Value::as_str) != Some(recomputed.as_str()) {
        return Err(Error::value(
            "request: intent_hash does not match the displayed intent",
        ));
    }
    let approvers = map
        .get("approvers")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Ok(CheckedRequest {
        request_id,
        intent,
        intent_hash: recomputed,
        arguments,
        approvers,
    })
}

/// Render untrusted text for a terminal without letting it act on the terminal:
/// control characters (ANSI/OSC escapes included) are shown escaped, and invisible or
/// direction-changing characters are shown escaped and reported (`true`).
pub fn neutralize(text: &str) -> (String, bool) {
    let mut out = String::with_capacity(text.len());
    let mut flagged = false;
    for c in text.chars() {
        let code = c as u32;
        let invisible = matches!(
            code,
            0x200B..=0x200F | 0x202A..=0x202E | 0x2066..=0x2069 | 0x2060 | 0xFEFF | 0x061C
        );
        if invisible {
            flagged = true;
            out.push_str(&format!("\\u{{{code:04X}}}"));
        } else if c.is_control() {
            flagged = true;
            match c {
                '\n' => out.push_str("\\n"),
                '\t' => out.push_str("\\t"),
                '\r' => out.push_str("\\r"),
                _ => out.push_str(&format!("\\u{{{code:04X}}}")),
            }
        } else {
            out.push(c);
        }
    }
    (out, flagged)
}

// --------------------------------------------------------------------------- //
// client side: the approval directory of `client-wrap --approval-dir`
// --------------------------------------------------------------------------- //

/// `<dir>/requests`, `<dir>/receipts` and `<dir>/used`.
pub struct ApprovalDir {
    pub root: PathBuf,
}

impl ApprovalDir {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        for sub in ["requests", "receipts", "used"] {
            std::fs::create_dir_all(root.join(sub))?;
        }
        Ok(Self { root })
    }

    /// Write a held call's request to `requests/<request_id>.json`.
    pub fn save_request(&self, approval_required: &Value) -> Result<PathBuf> {
        let request_id = approval_required
            .get("request_id")
            .and_then(Value::as_str)
            .filter(|id| is_request_id(id))
            .ok_or_else(|| Error::value("invalid request_id"))?;
        let path = self
            .root
            .join("requests")
            .join(format!("{request_id}.json"));
        let document = json!({"approval_required": approval_required});
        std::fs::write(&path, crate::json::dumps_indent(&document, 2))?;
        Ok(path)
    }

    /// The receipt for this outgoing call, if one was deposited: its request must name
    /// the same tool, arguments hash and mandate hash, and the receipt the same intent
    /// hash. The wrapper cannot recompute the intent (operation, canonical resource and
    /// audience come from the gateway policy), so it never sends an unmatched receipt.
    pub fn find_receipt(
        &self,
        tool: &str,
        arguments_hash: &str,
        mandate_hash: &str,
    ) -> Option<(PathBuf, String)> {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(self.root.join("receipts"))
            .ok()?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_file())
            .collect();
        entries.sort();
        entries.into_iter().find_map(|path| {
            let raw = std::fs::read(&path).ok().filter(|r| r.len() <= 16 * 1024)?;
            let receipt = Receipt::from_json(&strict_json(&raw).ok()?).ok()?;
            if !is_request_id(&receipt.request_id) {
                return None;
            }
            let request_path = self
                .root
                .join("requests")
                .join(format!("{}.json", receipt.request_id));
            let request = strict_json(std::fs::read(request_path).ok()?).ok()?;
            let request = request.get("approval_required").unwrap_or(&request);
            let intent = request.get("intent")?;
            let matches = intent.get("tool") == Some(&json!(tool))
                && intent.get("arguments_hash") == Some(&json!(arguments_hash))
                && intent.get("mandate_hash") == Some(&json!(mandate_hash))
                && request.get("intent_hash") == Some(&json!(receipt.intent_hash));
            matches.then(|| (path, encode_receipt(&receipt.to_json())))
        })
    }

    /// Move a sent receipt to `used/`: once presented it is consumed or refused.
    pub fn retire(&self, receipt: &Path) -> Result<()> {
        let name = receipt
            .file_name()
            .ok_or_else(|| Error::value("invalid receipt path"))?;
        std::fs::rename(receipt, self.root.join("used").join(name))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neutralize_escapes_controls_and_flags_bidi() {
        let (shown, flagged) = neutralize("a\u{1b}]8;;x\u{7}b");
        assert!(flagged);
        assert!(!shown.contains('\u{1b}') && !shown.contains('\u{7}'));
        assert!(shown.contains("\\u{001B}"));
        let (shown, flagged) = neutralize("txt\u{202E}fdp.exe");
        assert!(flagged && shown.contains("\\u{202E}"));
        assert_eq!(neutralize("plain é"), ("plain é".to_owned(), false));
    }

    #[test]
    fn a_signed_receipt_round_trips_and_detects_tampering() {
        let kp = keys::generate_keypair();
        let hash = format!("sha256:{}", "ab".repeat(32));
        let now = Utc::now();
        let receipt = sign_receipt(&kp.private_str, "a.dupont", "apr_x", &hash, now, 300).unwrap();
        let decoded = Receipt::from_header(&encode_receipt(&receipt)).unwrap();
        assert!(decoded.signature_valid());
        assert_eq!(decoded.approver_key, kp.public_str);
        let mut tampered = receipt.clone();
        tampered["request_id"] = json!("apr_y");
        assert!(!Receipt::from_json(&tampered).unwrap().signature_valid());
        let mut unknown = receipt.clone();
        unknown["max_uses"] = json!(2);
        assert!(Receipt::from_json(&unknown).is_err());
    }
}
