//! The TokenCrumb - MCP Proxy verification pipeline — fail-closed, ordered.
//!
//! Guiding principle: **crypto in code, policy in Datalog.** Cryptographic facts
//! (signature chain, attestation signature, nonce freshness, argument/token binding)
//! are established in code; only AFTER they hold are the corresponding proof facts
//! injected into the Datalog authorizer, which renders the final ALLOW/DENY. A proof
//! fact is never injected without the real check having passed, so profile-1 tokens
//! (no proofs) fail any `check if <proof>(true)` by closed-world semantics.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use biscuit_auth::builder::Term as BiscuitTerm;
use biscuit_auth::{AuthorizerBuilder, AuthorizerLimits, Biscuit};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

use crate::attestation::{self, AttestationResult, Expected, biscuit_hash};
use crate::biscuit_ops::{self, verified_block_sources};
use crate::budget::{BudgetStore, BudgetTx};
use crate::canonical::{arguments_hash, canonicalize_arg, canonicalize_resource_value};
use crate::error::{Error, Result, py_repr};
use crate::isotime::timestamp;
use crate::keys::biscuit_public;
use crate::nonce_cache::{NonceCache, NonceStore};
use crate::policy::{Limits, Policy, ToolPolicy, extract_resource, mapped_args};
use crate::profiles;
use crate::revocation::RevocationSource;
use crate::token_contract::{Term, block_facts, metadata};
use crate::validation::{integer, py_isspace, py_strip, string};

/// Upper bound on the number of mapped-argument combinations authorized per call. A
/// multi-object request must have EVERY combination allowed, so this is also a DoS
/// bound on how much Datalog one call can trigger.
pub const MAX_ARG_COMBINATIONS: usize = 64;

/// Request headers, looked up case-insensitively; the first occurrence wins.
#[derive(Debug, Clone, Default)]
pub struct Headers(pub Vec<(String, String)>);

impl Headers {
    pub fn new<K: AsRef<str>, V: AsRef<str>>(pairs: impl IntoIterator<Item = (K, V)>) -> Self {
        Self(
            pairs
                .into_iter()
                .map(|(k, v)| (k.as_ref().to_ascii_lowercase(), v.as_ref().to_owned()))
                .collect(),
        )
    }

    pub fn from_http(map: &http::HeaderMap) -> Self {
        Self(
            map.iter()
                .map(|(k, v)| {
                    // Header bytes are latin-1, as the former ASGI stack decoded them.
                    let value = v.as_bytes().iter().map(|&b| b as char).collect();
                    (k.as_str().to_owned(), value)
                })
                .collect(),
        )
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.0
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// The mandate carried as `Authorization: Biscuit <token>`.
pub fn bearer_biscuit(headers: &Headers) -> Option<String> {
    let auth = headers.get("authorization")?;
    let auth = auth.trim_start_matches(py_isspace);
    let split = auth.find(py_isspace)?;
    let (scheme, rest) = (&auth[..split], auth[split..].trim_start_matches(py_isspace));
    if rest.is_empty() || !scheme.eq_ignore_ascii_case("biscuit") {
        return None;
    }
    Some(py_strip(rest).to_owned())
}

pub fn attestation_header(headers: &Headers) -> Option<String> {
    headers
        .get("agent-attestation")
        .or_else(|| headers.get("aip-token"))
        .map(str::to_owned)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub allow: bool,
    pub reason: String,
    pub profile: String,
    pub tool: String,
    pub agent_id: Option<String>,
    pub resource: Option<String>,
    pub arguments_hash: Option<String>,
    pub remaining_budget: Option<i128>,
    pub mandate_id: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub agent_key: Option<String>,
}

impl Decision {
    /// The identity recorded in the audit entry.
    pub fn identity(&self) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("mandate_id".into(), json!(self.mandate_id));
        map.insert("subject".into(), json!(self.subject));
        map.insert("issuer".into(), json!(self.issuer));
        map.insert("agent_key".into(), json!(self.agent_key));
        map
    }
}

#[derive(Default, Clone)]
struct Identity {
    mandate_id: Option<String>,
    subject: Option<String>,
    issuer: Option<String>,
    agent_key: Option<String>,
}

type PolicySource = Box<dyn Fn() -> Arc<Policy> + Send + Sync>;
pub type AgentKeyResolver = Box<dyn Fn(&str) -> Option<String> + Send + Sync>;
pub type Clock = Box<dyn Fn() -> DateTime<Utc> + Send + Sync>;

/// Everything a verifier can be built with; `Verifier::new` validates it.
pub struct VerifierOptions {
    pub audience: String,
    pub upstream_name: Option<String>,
    /// Hot reload: the policy in force is read through this on every call.
    pub policy_source: Option<PolicySource>,
    pub nonce_cache: Option<Arc<dyn NonceStore>>,
    pub budget_store: Option<Arc<BudgetStore>>,
    pub revocation: Option<Arc<dyn RevocationSource>>,
    /// Registry lookup (profile 3a).
    pub resolve_agent_pubkey: Option<AgentKeyResolver>,
    pub freshness_seconds: i128,
    pub now_fn: Option<Clock>,
    pub previous_authority_keys: Vec<String>,
}

impl VerifierOptions {
    pub fn new(audience: impl Into<String>) -> Self {
        Self {
            audience: audience.into(),
            upstream_name: None,
            policy_source: None,
            nonce_cache: None,
            budget_store: None,
            revocation: None,
            resolve_agent_pubkey: None,
            freshness_seconds: 60,
            now_fn: None,
            previous_authority_keys: Vec::new(),
        }
    }
}

pub struct Verifier {
    pub audience: String,
    pub upstream_name: Option<String>,
    pub authority_public_str: String,
    pub authority_keys: Vec<String>,
    policy: RwLock<Arc<Policy>>,
    policy_source: Option<PolicySource>,
    pub nonce_cache: Arc<dyn NonceStore>,
    pub budget_store: Arc<BudgetStore>,
    pub revocation: Option<Arc<dyn RevocationSource>>,
    resolve_agent_pubkey: Option<AgentKeyResolver>,
    pub freshness_seconds: i128,
    now_fn: Clock,
}

fn limits(limits: &Limits) -> AuthorizerLimits {
    AuthorizerLimits {
        max_facts: u64::try_from(limits.max_facts).unwrap_or(u64::MAX),
        max_iterations: u64::try_from(limits.max_iterations).unwrap_or(u64::MAX),
        max_time: Duration::from_millis(u64::try_from(limits.max_time_ms).unwrap_or(u64::MAX)),
    }
}

/// Mapped call arguments -> every combination of `(fact_name, canonical_value)`.
///
/// A scalar argument yields one value; a list argument yields one per element. The
/// caller must authorize EVERY returned combination, which is how "all identifiers must
/// be in scope, not just the first" is enforced. Returns a single empty combination
/// when the tool maps no arguments.
fn arg_combinations(tool: &ToolPolicy, arguments: &Value) -> Result<Vec<Vec<(String, String)>>> {
    let mut per_arg: Vec<Vec<(String, String)>> = Vec::new();
    for (name, raw) in mapped_args(tool, arguments) {
        let values: Vec<&Value> = match raw {
            Value::Array(items) => items.iter().collect(),
            other => vec![other],
        };
        if values.is_empty() {
            return Err(Error::new(
                crate::ErrorKind::Argument,
                format!("{name}: empty argument list"),
            ));
        }
        per_arg.push(
            values
                .into_iter()
                .map(|v| Ok((name.to_owned(), canonicalize_arg(v)?)))
                .collect::<Result<_>>()?,
        );
    }
    if per_arg.is_empty() {
        return Ok(vec![Vec::new()]);
    }
    let total = per_arg
        .iter()
        .try_fold(1usize, |acc, group| acc.checked_mul(group.len()))
        .unwrap_or(usize::MAX);
    if total > MAX_ARG_COMBINATIONS {
        return Err(Error::new(
            crate::ErrorKind::Argument,
            format!("too many argument combinations ({total} > {MAX_ARG_COMBINATIONS})"),
        ));
    }
    let mut combinations: Vec<Vec<(String, String)>> = vec![Vec::new()];
    for group in per_arg {
        combinations = combinations
            .into_iter()
            .flat_map(|prefix| {
                group.iter().map(move |item| {
                    let mut next = prefix.clone();
                    next.push(item.clone());
                    next
                })
            })
            .collect();
    }
    Ok(combinations)
}

fn describe(combination: &[(String, String)]) -> String {
    combination
        .iter()
        .map(|(k, v)| format!("{k}={}", py_repr(v)))
        .collect::<Vec<_>>()
        .join(", ")
}

struct Proofs {
    call_signature_valid: bool,
    nonce_fresh: bool,
    arguments_bound: bool,
    capability_bound: bool,
}

impl Proofs {
    fn from(result: &AttestationResult) -> Self {
        Self {
            call_signature_valid: result.call_signature_valid,
            nonce_fresh: result.nonce_fresh,
            arguments_bound: result.arguments_bound,
            capability_bound: result.capability_bound,
        }
    }

    fn facts(&self) -> [(&'static str, bool); 4] {
        [
            ("call_signature_valid", self.call_signature_valid),
            ("nonce_fresh", self.nonce_fresh),
            ("arguments_bound", self.arguments_bound),
            ("capability_bound", self.capability_bound),
        ]
    }
}

/// Why one Datalog evaluation did not allow the call.
enum AuthorizeError {
    /// The authorizer ran and refused (checks, policies, run limits).
    Denied(String),
    /// The authorizer could not be built.
    Broken(String),
}

impl Verifier {
    pub fn new(
        authority_public_str: &str,
        policy: Policy,
        options: VerifierOptions,
    ) -> Result<Self> {
        // An unnamed deployment cannot reject a mandate minted for another one, so there
        // is no safe default here (ADR-0007).
        let audience = py_strip(&options.audience).to_owned();
        if audience.is_empty() {
            return Err(Error::value(
                "an audience is required: this proxy must be nameable to reject \
                 mandates minted for another deployment",
            ));
        }
        if options.previous_authority_keys.len() > 7 {
            return Err(Error::value("at most eight trusted authority epochs"));
        }
        let mut authority_keys: Vec<String> = Vec::new();
        for key in
            std::iter::once(authority_public_str.to_owned()).chain(options.previous_authority_keys)
        {
            if !authority_keys.contains(&key) {
                authority_keys.push(key);
            }
        }
        for trusted in &authority_keys {
            biscuit_public(trusted)?;
        }
        let freshness_seconds = integer(options.freshness_seconds, "freshness_seconds", 1, 3600)?;
        Ok(Self {
            audience,
            upstream_name: options.upstream_name,
            authority_public_str: authority_public_str.to_owned(),
            authority_keys,
            policy: RwLock::new(Arc::new(policy)),
            policy_source: options.policy_source,
            nonce_cache: options
                .nonce_cache
                .unwrap_or_else(|| Arc::new(NonceCache::in_memory())),
            budget_store: options
                .budget_store
                .unwrap_or_else(|| Arc::new(BudgetStore::in_memory())),
            revocation: options.revocation,
            resolve_agent_pubkey: options.resolve_agent_pubkey,
            freshness_seconds,
            now_fn: options.now_fn.unwrap_or_else(|| Box::new(Utc::now)),
        })
    }

    /// The policy in force right now. Read through the reloader on every call, so a
    /// hot reload reaches every caller.
    pub fn policy(&self) -> Arc<Policy> {
        match &self.policy_source {
            Some(source) => source(),
            None => self.policy.read().expect("policy lock").clone(),
        }
    }

    pub fn set_policy(&self, policy: Policy) {
        *self.policy.write().expect("policy lock") = Arc::new(policy);
    }

    pub fn now(&self) -> DateTime<Utc> {
        (self.now_fn)()
    }

    fn verify_token(&self, token_b64: &str) -> Option<Biscuit> {
        self.authority_keys.iter().find_map(|trusted| {
            let key = biscuit_public(trusted).ok()?;
            Biscuit::from_base64(token_b64, key).ok()
        })
    }

    fn revoked(&self, token: &Biscuit, facts: &crate::token_contract::Metadata) -> Result<bool> {
        let Some(revocation) = &self.revocation else {
            return Ok(false);
        };
        let mut identifiers = biscuit_ops::revocation_ids(token.revocation_identifiers());
        for name in ["jti", "key_id"] {
            if let Some(value) = facts.get(name) {
                identifiers.push(format!("{name}:{value}"));
            }
        }
        Ok(revocation.any_revoked(&identifiers)?.is_some())
    }

    /// Verify the bearer identity used for session control; tools get all checks.
    fn session_metadata(
        &self,
        headers: &Headers,
    ) -> Result<(String, crate::token_contract::Metadata)> {
        let raw = bearer_biscuit(headers).filter(|r| !r.is_empty());
        let Some(raw) = raw.filter(|r| r.len() as i128 <= self.policy().limits.max_token_size)
        else {
            return Err(Error::value("session requires a bounded mandate"));
        };
        let token = self
            .verify_token(&raw)
            .ok_or_else(|| Error::value("invalid session mandate"))?;
        let facts = metadata(&verified_block_sources(&token)?)?;
        let expired = facts
            .expires_at
            .iter()
            .min()
            .is_none_or(|expiry| *expiry <= self.now());
        if facts.get("audience") != Some(self.audience.as_str()) || expired {
            return Err(Error::value("invalid session audience/expiry"));
        }
        if self.revoked(&token, &facts)? {
            return Err(Error::value("revoked session mandate"));
        }
        Ok((raw, facts))
    }

    pub fn session_owner(&self, headers: &Headers) -> Result<String> {
        Ok(biscuit_hash(&self.session_metadata(headers)?.0))
    }

    /// `(issuer, subject)` of the session's verified mandate.
    pub fn session_principal(&self, headers: &Headers) -> Result<(Option<String>, Option<String>)> {
        let (_, facts) = self.session_metadata(headers)?;
        Ok((
            facts.get("issuer").map(str::to_owned),
            facts.get("user").map(str::to_owned),
        ))
    }

    /// Verify one `tools/call`. `endpoint` is the upstream name the call arrived on
    /// (ADR-0006): one process serves several endpoints, so the upstream is per call.
    ///
    /// All caps are checked and consumed under one budget transaction. An `Err` means
    /// the verification could not be completed (state or revocation unavailable): the
    /// caller must refuse the call.
    pub fn verify_call(
        &self,
        tool: &str,
        arguments: &Value,
        headers: &Headers,
        endpoint: Option<&str>,
        policy: Option<Arc<Policy>>,
    ) -> Result<Decision> {
        let mut tx = self.budget_store.transaction()?;
        self.verify_in(&mut tx, tool, arguments, headers, endpoint, policy)
    }

    fn verify_in(
        &self,
        tx: &mut BudgetTx<'_>,
        tool: &str,
        arguments: &Value,
        headers: &Headers,
        endpoint: Option<&str>,
        policy: Option<Arc<Policy>>,
    ) -> Result<Decision> {
        let upstream_name = endpoint
            .map(str::to_owned)
            .or_else(|| self.upstream_name.clone());
        // Snapshot once: a hot reload mid-call would judge one call under two rule sets.
        let policy = policy.unwrap_or_else(|| self.policy());
        let now = self.now();
        let mut args_hash: Option<String> = None;
        let mut identity = Identity::default();

        let deny = |reason: String,
                    profile: &str,
                    agent_id: Option<String>,
                    resource: Option<String>,
                    remaining: Option<i128>,
                    args_hash: &Option<String>,
                    identity: &Identity| {
            Ok(Decision {
                allow: false,
                reason,
                profile: profile.to_owned(),
                tool: tool.to_owned(),
                agent_id,
                resource,
                arguments_hash: args_hash.clone(),
                remaining_budget: remaining,
                mandate_id: identity.mandate_id.clone(),
                subject: identity.subject.clone(),
                issuer: identity.issuer.clone(),
                agent_key: identity.agent_key.clone(),
            })
        };
        macro_rules! refuse {
            ($reason:expr) => {
                return deny(
                    $reason.into(),
                    profiles::NATIVE,
                    None,
                    None,
                    None,
                    &args_hash,
                    &identity,
                )
            };
            ($reason:expr, $profile:expr) => {
                return deny(
                    $reason.into(),
                    $profile,
                    None,
                    None,
                    None,
                    &args_hash,
                    &identity,
                )
            };
            ($reason:expr, $profile:expr, $agent:expr) => {
                return deny(
                    $reason.into(),
                    $profile,
                    $agent,
                    None,
                    None,
                    &args_hash,
                    &identity,
                )
            };
            ($reason:expr, $profile:expr, $agent:expr, $resource:expr, $remaining:expr) => {
                return deny(
                    $reason.into(),
                    $profile,
                    $agent,
                    $resource,
                    $remaining,
                    &args_hash,
                    &identity,
                )
            };
        }

        // -- extract the Biscuit ----------------------------------------------------
        let Some(token_b64) = bearer_biscuit(headers).filter(|t| !t.is_empty()) else {
            refuse!("missing Authorization: Biscuit token");
        };
        if token_b64.len() as i128 > policy.limits.max_token_size {
            refuse!("token exceeds max size (Datalog/DoS limit)");
        }
        let checked = (|| -> Result<String> {
            if !arguments.is_object() {
                return Err(Error::value("arguments must be an object"));
            }
            string(tool, "tool", 256)?;
            arguments_hash(arguments)
        })();
        match checked {
            Ok(hash) => args_hash = Some(hash),
            Err(e) => refuse!(format!("invalid arguments: {}", e.message)),
        }

        // -- 1. signature chain + revocation -----------------------------------------
        let Some(token) = self.verify_token(&token_b64) else {
            refuse!("biscuit verification failed: no trusted authority signature");
        };
        // Parse the token ONCE (provenance-safe reads from the AUTHORITY block only).
        let parsed = biscuit_ops::check_unambiguous(&token)
            .and_then(|()| biscuit_ops::inspect(&token_b64))
            .and_then(|insp| Ok((metadata(&insp.blocks)?, insp)));
        let (facts, insp) = match parsed {
            Ok(parts) => parts,
            Err(e) => refuse!(format!("invalid mandate schema: {}", e.message)),
        };
        identity = Identity {
            mandate_id: facts
                .get("jti")
                .map(str::to_owned)
                .or_else(|| insp.revocation_ids.first().cloned()),
            subject: facts.get("user").map(str::to_owned),
            issuer: facts.get("issuer").map(str::to_owned),
            agent_key: facts.get("agent_pubkey").map(str::to_owned),
        };
        if self.revoked(&token, &facts)? {
            refuse!("biscuit revoked");
        }
        let token_agent_id = facts.get("agent_id").map(str::to_owned);
        let anchored_pubkey = facts.get("agent_pubkey").map(str::to_owned); // 3b key, block 0
        let Some(required_profile) = facts.get("required_profile").map(str::to_owned) else {
            refuse!("required_profile missing in authority block");
        };
        if anchored_pubkey.is_some() && required_profile != profiles::HARDENED {
            refuse!("anchored key requires hardened profile");
        }

        // -- 1b. audience -------------------------------------------------------------
        // Read from the authority block only, like agent_pubkey: reading the union would
        // let a bearer widen its own audience by appending a block. Absent is a DENY,
        // not a wildcard (ADR-0007).
        match facts.get("audience") {
            None => refuse!(
                "no audience in authority block (fail-closed)",
                profiles::NATIVE,
                token_agent_id.clone()
            ),
            Some(aud) if aud != self.audience => refuse!(
                format!(
                    "audience mismatch: token {} != gateway {}",
                    py_repr(aud),
                    py_repr(&self.audience)
                ),
                profiles::NATIVE,
                token_agent_id.clone()
            ),
            Some(_) => {}
        }

        // -- 2. profile detection + anti-downgrade -----------------------------------
        let header_att = attestation_header(headers);
        let presented = profiles::detect_presented(
            header_att.is_some(),
            anchored_pubkey.as_deref(),
            self.resolve_agent_pubkey.is_some(),
        );
        if header_att.is_some() && presented == profiles::NATIVE {
            refuse!(
                "attestation has no trusted key source",
                profiles::NATIVE,
                token_agent_id.clone()
            );
        }
        if !profiles::at_least(presented, &required_profile)? {
            refuse!(
                format!(
                    "profile downgrade: presented {} < required {}",
                    py_repr(presented),
                    py_repr(&required_profile)
                ),
                presented,
                token_agent_id.clone()
            );
        }
        if !profiles::at_least(presented, &policy.min_profile)? {
            refuse!(
                format!(
                    "profile below policy min: {} < {}",
                    py_repr(presented),
                    py_repr(&policy.min_profile)
                ),
                presented,
                token_agent_id.clone()
            );
        }

        // -- 3–7. attestation (3a / 3b) ---------------------------------------------
        let mut proofs: Option<Proofs> = None;
        let mut attested: Option<AttestationResult> = None;
        if presented == profiles::HARDENED || presented == profiles::REGISTRY {
            // 3. agent_pubkey provenance
            let agent_pubkey = if presented == profiles::HARDENED {
                anchored_pubkey.clone() // from the authority block
            } else {
                let Some(agent_id) = &token_agent_id else {
                    refuse!(
                        "registry profile: no agent_id in authority block",
                        presented
                    );
                };
                let resolved = self
                    .resolve_agent_pubkey
                    .as_ref()
                    .and_then(|resolve| resolve(agent_id));
                if resolved.as_deref().is_none_or(str::is_empty) {
                    refuse!(
                        format!(
                            "registry: agent {} not found (fail-closed)",
                            py_repr(agent_id)
                        ),
                        presented,
                        token_agent_id.clone()
                    );
                }
                resolved
            };
            let Some(agent_pubkey) = agent_pubkey.filter(|k| !k.is_empty()) else {
                refuse!(
                    "no agent public key available",
                    presented,
                    token_agent_id.clone()
                );
            };

            // 4–7. verify the signed attestation against the real call
            let hash = args_hash.clone().expect("hash computed");
            let result = attestation::verify_attestation(
                header_att.as_deref().unwrap_or(""),
                &Expected {
                    agent_pubkey: &agent_pubkey,
                    tool,
                    arguments_hash: &hash,
                    token_b64: &token_b64,
                    now,
                    freshness_seconds: self.freshness_seconds,
                    clock_skew_seconds: policy.clock_skew_seconds,
                },
                self.nonce_cache.as_ref(),
                false,
            );
            if !result.ok {
                refuse!(
                    result
                        .reason
                        .clone()
                        .unwrap_or_else(|| "attestation invalid".into()),
                    presented,
                    result.agent_id.clone().or_else(|| token_agent_id.clone())
                );
            }
            // Cross-consistency: an attestation must not claim an identity the mandate
            // binds to someone else. In 3b the key IS the identity; a mandate without
            // `agent_id` (Keycloak) binds no name, so there is nothing to contradict.
            if token_agent_id.is_some() && result.agent_id != token_agent_id {
                refuse!(
                    "agent_id mismatch between attestation and Biscuit",
                    presented,
                    result.agent_id.clone()
                );
            }
            proofs = Some(Proofs::from(&result));
            attested = Some(result);
        }

        // -- 8. tool mapping + resource canonicalization -----------------------------
        let Some(tp) = policy.tool(tool) else {
            refuse!(
                format!(
                    "unknown tool {}: a mapping is required (deny_unknown_tools)",
                    py_repr(tool)
                ),
                presented,
                token_agent_id.clone()
            );
        };
        // An endpoint serves its own upstream's tools and nothing else (ADR-0006).
        if let (Some(endpoint), Some(served_by)) = (&upstream_name, &tp.upstream) {
            if served_by != endpoint {
                refuse!(
                    format!(
                        "tool {} is served by upstream {}, not {}",
                        py_repr(tool),
                        py_repr(served_by),
                        py_repr(endpoint)
                    ),
                    presented,
                    token_agent_id.clone()
                );
            }
        }
        let mut canonical_resource: Option<String> = None;
        if let Some(raw) = extract_resource(tp, arguments) {
            let canonical = canonicalize_resource_value(raw).and_then(|c| {
                if Some(c.as_str()) != raw.as_str() {
                    Err(Error::new(
                        crate::ErrorKind::Resource,
                        "resource must already use its canonical representation",
                    ))
                } else {
                    Ok(c)
                }
            });
            match canonical {
                Ok(c) => canonical_resource = Some(c),
                Err(e) => refuse!(
                    format!("resource rejected: {}", e.message),
                    presented,
                    token_agent_id.clone()
                ),
            }
        }

        // -- 8b. mapped call arguments -> arg(name, value) facts -----------------------
        let combinations = match arg_combinations(tp, arguments) {
            Ok(c) => c,
            Err(e) => refuse!(
                format!("argument rejected: {}", e.message),
                presented,
                token_agent_id.clone(),
                canonical_resource.clone(),
                None
            ),
        };

        // -- budgets: one counter for the mandate, one per (mandate, tool) ------------
        // The two ceilings answer different questions — "how many calls in total" and
        // "how many of THIS tool" — so they cannot share a counter (ADR-0008).
        let mandate_key = insp.revocation_ids.first().cloned().unwrap_or_default();
        tx.prepare(now.timestamp() as i128)?;
        let tool_key = format!("{mandate_key}|{tool}");
        let total_caps: Vec<i128> = policy
            .budget_total
            .into_iter()
            .chain(facts.budget_cap.iter().map(|c| i128::from(*c)))
            .collect();
        let mut counters: Vec<(String, i128)> = Vec::new();
        if let Some(min) = total_caps.iter().min() {
            counters.push((mandate_key.clone(), *min));
        }
        if let Some(budget) = tp.budget {
            counters.push((tool_key.clone(), budget));
        }
        let mut remaining = counters.iter().map(|(k, c)| tx.remaining(k, *c)).min();
        if remaining.is_some_and(|r| r <= 0) {
            refuse!(
                "policy denied: budget exhausted",
                presented,
                token_agent_id.clone(),
                None,
                remaining
            );
        }
        if let Some(depth) = facts.max_delegation_depth.iter().min() {
            if insp.block_count as i64 - 1 > *depth {
                refuse!("maximum delegation depth exceeded", presented);
            }
        }
        let root = block_facts(&insp.blocks[0], true, false)?;
        let Some(expires_at) = facts
            .expires_at
            .iter()
            .min()
            .copied()
            .filter(|_| root.contains("expires_at"))
        else {
            refuse!(
                "mandate is not bounded within max_ttl: expires_at required",
                presented
            );
        };
        if expires_at <= now {
            refuse!("policy denied: mandate expired", presented);
        }
        let ceiling = biscuit_ops::add_seconds(now, policy.max_ttl_seconds)?;
        if expires_at > ceiling {
            refuse!("mandate is not bounded within max_ttl", presented);
        }

        // A child budget narrows the external ceiling but must not change the contextual
        // witness seen by checks in its parent (nonmonotonic comparisons).
        let root_caps: Vec<i128> = root
            .get("budget_cap")
            .map(|facts| {
                facts
                    .iter()
                    .filter_map(|f| match f.first() {
                        Some(Term::Int(i)) => Some(i128::from(*i)),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut datalog_counters: Vec<(&str, i128)> = Vec::new();
        if let Some(min) = policy.budget_total.into_iter().chain(root_caps).min() {
            datalog_counters.push((&mandate_key, min));
        }
        if let Some(budget) = tp.budget {
            datalog_counters.push((&tool_key, budget));
        }
        let datalog_remaining = datalog_counters
            .iter()
            .map(|(k, c)| tx.remaining(k, *c))
            .min();

        // -- 9–10. Datalog evaluation ------------------------------------------------
        // One authorization per combination of mapped argument values, and EVERY one must
        // pass. Biscuit checks are existential ("some fact matches"), so the "all ids must
        // be in scope" semantics is carried here, around the same signed check.
        for combination in &combinations {
            let outcome = self.authorize(
                &token,
                tp,
                now,
                canonical_resource.as_deref(),
                datalog_remaining,
                proofs.as_ref(),
                combination,
                upstream_name.as_deref(),
                &policy,
            );
            match outcome {
                Ok(()) => {}
                Err(AuthorizeError::Denied(message)) => {
                    let scope = if combination.is_empty() {
                        String::new()
                    } else {
                        format!(" for {}", describe(combination))
                    };
                    refuse!(
                        format!("policy denied{scope}: {message}"),
                        presented,
                        token_agent_id.clone(),
                        canonical_resource.clone(),
                        remaining
                    );
                }
                Err(AuthorizeError::Broken(message)) => refuse!(
                    format!("authorizer error: {message}"),
                    presented,
                    token_agent_id.clone(),
                    canonical_resource.clone(),
                    remaining
                ),
            }
        }

        // The signed, typed expiry has already been checked above.
        if let Some(result) = &attested {
            let fresh = self.nonce_cache.check_and_add(
                result.nonce_key.as_deref().unwrap_or_default(),
                timestamp(&now),
                result.nonce_expires_at,
            )?;
            if !fresh {
                refuse!(
                    "nonce replay or cache full",
                    presented,
                    token_agent_id.clone()
                );
            }
        }

        // -- 11. effects (consume budget) --------------------------------------------
        if !counters.is_empty() {
            let keys: Vec<&str> = counters.iter().map(|(k, _)| k.as_str()).collect();
            let first_expiry = facts
                .expires_at
                .first()
                .map(DateTime::timestamp)
                .map(i128::from);
            tx.consume(&keys, first_expiry)?;
            remaining = counters.iter().map(|(k, c)| tx.remaining(k, *c)).min();
        }

        Ok(Decision {
            allow: true,
            reason: "allow".into(),
            profile: presented.to_owned(),
            tool: tool.to_owned(),
            agent_id: token_agent_id,
            resource: canonical_resource,
            arguments_hash: args_hash,
            remaining_budget: remaining,
            mandate_id: Some(mandate_key),
            subject: facts.get("user").map(str::to_owned),
            issuer: facts.get("issuer").map(str::to_owned),
            agent_key: anchored_pubkey,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn authorize(
        &self,
        token: &Biscuit,
        tp: &ToolPolicy,
        now: DateTime<Utc>,
        resource: Option<&str>,
        remaining: Option<i128>,
        proofs: Option<&Proofs>,
        arg_facts: &[(String, String)],
        upstream_name: Option<&str>,
        policy: &Policy,
    ) -> std::result::Result<(), AuthorizeError> {
        // `tool` names the called tool (its public name) so an attenuation block can keep
        // a subset of the granted tools: `check if tool($t), {tools}.contains($t)`.
        let mut lines: Vec<String> = vec![
            "time({t});".into(),
            "operation({o});".into(),
            "tool({tool});".into(),
        ];
        let mut params: HashMap<String, BiscuitTerm> = HashMap::from([
            (
                "t".into(),
                BiscuitTerm::Date(u64::try_from(now.timestamp()).unwrap_or(0)),
            ),
            ("o".into(), BiscuitTerm::Str(tp.operation.clone())),
            ("tool".into(), BiscuitTerm::Str(tp.name.clone())),
        ]);
        // Which upstream this endpoint fronts. A mandate narrows to one upstream with
        // `check if upstream("catalog")` — a check, not a fact, so appending it can only
        // restrict. An unnamed gateway injects nothing: such a token is denied.
        if let Some(name) = upstream_name {
            lines.push("upstream({u});".into());
            params.insert("u".into(), BiscuitTerm::Str(name.to_owned()));
        }
        if let Some(resource) = resource {
            lines.push("resource({r});".into());
            params.insert("r".into(), BiscuitTerm::Str(resource.to_owned()));
        }
        if let Some(remaining) = remaining {
            lines.push("budget({b});".into());
            params.insert("b".into(), BiscuitTerm::Integer(remaining as i64));
        }
        for (i, (key, value)) in arg_facts.iter().enumerate() {
            lines.push(format!("arg({{ak{i}}}, {{av{i}}});"));
            params.insert(format!("ak{i}"), BiscuitTerm::Str(key.clone()));
            params.insert(format!("av{i}"), BiscuitTerm::Str(value.clone()));
        }
        if let Some(proofs) = proofs {
            for (name, value) in proofs.facts() {
                if value {
                    lines.push(format!("{name}(true);"));
                }
            }
        }
        // base checks derived from the tool mapping, in their historical order
        lines.push("check if right({tool}, {o});".into());
        if let Some(exact) = &tp.resource_exact {
            lines.push("check if resource({rx});".into());
            params.insert("rx".into(), BiscuitTerm::Str(exact.clone()));
        }
        if let Some(prefix) = &tp.resource_prefix {
            lines.push("check if resource($r), $r.starts_with({p});".into());
            params.insert("p".into(), BiscuitTerm::Str(prefix.clone()));
        }
        if remaining.is_some() {
            lines.push("check if budget($b), $b > 0;".into());
        }
        for name in &tp.require {
            lines.push(format!("check if {name}(true);"));
        }
        lines.push("allow if operation($o);".into());

        let mut authorizer = AuthorizerBuilder::new()
            .code_with_params(lines.join("\n"), params, HashMap::new())
            .map(|b| b.set_limits(limits(&policy.limits)))
            .and_then(|b| b.build(token))
            .map_err(|e| AuthorizeError::Broken(e.to_string()))?;
        authorizer
            .authorize()
            .map(|_| ())
            .map_err(|e| AuthorizeError::Denied(e.to_string()))
    }
}
