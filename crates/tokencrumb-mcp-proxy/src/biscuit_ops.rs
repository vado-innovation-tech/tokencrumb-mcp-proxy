//! Biscuit control-plane operations: forge, attenuate, inspect.
//!
//! Authority block (signed by the authority private key) carries facts:
//!     agent_id("..."), required_profile("..."), [agent_pubkey("ed25519/..")],
//!     right("<tool>", "<operation>"), budget_cap(<int>), audience(".."),
//!     and checks: TTL (`check if time($t), $t < <exp>`), optional resource prefix,
//!     and an optional upstream restriction (`check if upstream("..")`).
//!
//! `audience` is mandatory: the proxy refuses a mandate that does not name the
//! deployment it was minted for (ADR-0007). `upstream` is a *check* rather than a
//! fact, so an offline attenuation can narrow a mandate to one upstream but never
//! widen it.
//!
//! Attenuation blocks (appended offline, signed by an ephemeral key) can only add
//! restrictive checks / lower budget caps — monotonic narrowing, enforced by Biscuit.

use std::collections::HashMap;
use std::sync::LazyLock;

use biscuit_auth::builder::Term as BiscuitTerm;
use biscuit_auth::{Biscuit, BiscuitBuilder, BlockBuilder, UnverifiedBiscuit};
use chrono::{DateTime, Utc};
use regex::Regex;

use crate::canonical::canonicalize_prefix;
use crate::error::{Error, ErrorKind, Result, py_repr};
use crate::keys::{biscuit_keypair, biscuit_public};
use crate::profiles;
use crate::token_contract::{BlockFacts, Term, block_facts, is_context, is_governed, metadata};
use crate::validation::{MAX_INTEGER, integer, public_key, py_strip, string};

pub const DEFAULT_PROFILE: &str = profiles::NATIVE;

static PREDICATE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9_]{0,63}\z").expect("regex"));
static FACT_SPEC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)^\s*([a-z][a-z0-9_]{0,63})\s*\((.*)\)\s*;?\s*\z").expect("regex")
});
static FACT_ARG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^\s*(?:"((?:[^"\\]|\\.)*)"|(-?\d+))\s*\z"#).expect("regex"));

fn fact_spec_error(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::FactSpec, message)
}

/// A value from a `--fact` specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactArg {
    Str(String),
    Int(i64),
}

impl FactArg {
    fn term(&self) -> BiscuitTerm {
        match self {
            FactArg::Str(s) => BiscuitTerm::Str(s.clone()),
            FactArg::Int(i) => BiscuitTerm::Integer(*i),
        }
    }
}

/// `'assigned_incident("INC-123")'` -> `("assigned_incident", ["INC-123"])`.
///
/// The result is re-emitted as a *parameterized* Datalog fact by [`forge`], so no
/// caller-supplied text ever reaches the block source. That makes Datalog injection
/// through `--fact` impossible by construction.
pub fn parse_fact_spec(text: &str) -> Result<(String, Vec<FactArg>)> {
    let Some(captures) = FACT_SPEC_RE.captures(text) else {
        return Err(fact_spec_error(format!(
            "cannot parse fact {} (expected: name(\"value\", ...))",
            py_repr(text)
        )));
    };
    let predicate = captures[1].to_owned();
    let raw_args = py_strip(&captures[2]).to_owned();
    if is_context(&predicate) || is_governed(&predicate) {
        return Err(fact_spec_error(format!("reserved predicate: {predicate}")));
    }
    if raw_args.is_empty() {
        return Err(fact_spec_error(format!(
            "fact {} needs at least one argument",
            py_repr(&predicate)
        )));
    }
    let mut args = Vec::new();
    for piece in split_fact_args(&raw_args)? {
        let Some(arg) = FACT_ARG_RE.captures(&piece) else {
            return Err(fact_spec_error(format!(
                "fact {}: argument {} must be a quoted string or an integer",
                py_repr(&predicate),
                py_repr(py_strip(&piece))
            )));
        };
        if let Some(s) = arg.get(1) {
            args.push(FactArg::Str(
                s.as_str().replace("\\\"", "\"").replace("\\\\", "\\"),
            ));
        } else {
            let digits = &arg[2];
            let value = digits.parse::<i64>().map_err(|_| {
                fact_spec_error(format!(
                    "fact {}: integer {digits} does not fit a Datalog integer",
                    py_repr(&predicate)
                ))
            })?;
            args.push(FactArg::Int(value));
        }
    }
    Ok((predicate, args))
}

/// Split on commas that are not inside a quoted string.
fn split_fact_args(raw: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut buffer = String::new();
    let mut in_string = false;
    let mut escaped = false;
    for c in raw.chars() {
        if escaped {
            buffer.push(c);
            escaped = false;
            continue;
        }
        if c == '\\' && in_string {
            buffer.push(c);
            escaped = true;
        } else if c == '"' {
            in_string = !in_string;
            buffer.push(c);
        } else if c == ',' && !in_string {
            out.push(std::mem::take(&mut buffer));
        } else {
            buffer.push(c);
        }
    }
    if in_string {
        return Err(fact_spec_error("unterminated string in fact specification"));
    }
    out.push(buffer);
    Ok(out)
}

/// `'incident_id=assigned_incident'` -> `("incident_id", "assigned_incident")`.
///
/// Emits `check if arg("incident_id", $x), assigned_incident($x);` — the rule that
/// binds a call argument to a fact signed into the token.
pub fn parse_scope_arg(text: &str) -> Result<(String, String)> {
    let (arg_name, predicate, separated) = match text.split_once('=') {
        Some((a, p)) => (py_strip(a), py_strip(p), true),
        None => (py_strip(text), "", false),
    };
    if !separated || arg_name.is_empty() || predicate.is_empty() {
        return Err(fact_spec_error(format!(
            "cannot parse scope arg {} (expected: arg_name=fact_predicate)",
            py_repr(text)
        )));
    }
    if !PREDICATE_RE.is_match(predicate) {
        return Err(fact_spec_error(format!(
            "invalid fact predicate {}",
            py_repr(predicate)
        )));
    }
    Ok((arg_name.to_owned(), predicate.to_owned()))
}

/// `now + timedelta(seconds=n)`, refusing what a date cannot represent.
pub fn add_seconds(now: DateTime<Utc>, seconds: i128) -> Result<DateTime<Utc>> {
    i64::try_from(seconds)
        .ok()
        .and_then(chrono::TimeDelta::try_seconds)
        .and_then(|delta| now.checked_add_signed(delta))
        .ok_or_else(|| Error::value("date value out of range"))
}

fn date_term(value: DateTime<Utc>) -> BiscuitTerm {
    BiscuitTerm::Date(u64::try_from(value.timestamp()).unwrap_or(0))
}

/// Everything `forge` needs besides the authority key.
#[derive(Debug, Clone)]
pub struct ForgeRequest {
    pub agent_id: String,
    pub tool: String,
    pub operation: String,
    pub ttl_seconds: i128,
    pub budget: i128,
    pub audience: String,
    pub resource_prefix: Option<String>,
    pub agent_pubkey: Option<String>,
    pub required_profile: String,
    pub upstream: Option<String>,
    pub max_delegation_depth: Option<i128>,
    pub facts: Vec<String>,
    pub scope_args: Vec<String>,
}

impl Default for ForgeRequest {
    fn default() -> Self {
        Self {
            agent_id: "agent-01".into(),
            tool: String::new(),
            operation: "read".into(),
            ttl_seconds: 900,
            budget: 200,
            audience: String::new(),
            resource_prefix: None,
            agent_pubkey: None,
            required_profile: DEFAULT_PROFILE.into(),
            upstream: None,
            max_delegation_depth: None,
            facts: Vec::new(),
            scope_args: Vec::new(),
        }
    }
}

fn nonempty(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|v| !v.is_empty())
}

/// Forge a capability Biscuit; returns the base64url token string.
///
/// `facts` are authority-block facts such as `assigned_incident("INC-123")`;
/// `scope_args` are `arg_name=fact_predicate` pairs that bind a call argument to one of
/// those facts. Both are parsed and re-emitted parameterized (see [`parse_fact_spec`]),
/// never concatenated into the block source.
pub fn forge(authority_private_str: &str, request: &ForgeRequest) -> Result<String> {
    forge_at(authority_private_str, request, Utc::now())
}

pub fn forge_at(
    authority_private_str: &str,
    request: &ForgeRequest,
    now: DateTime<Utc>,
) -> Result<String> {
    // A mandate with no audience is refused by every proxy, so forging one is a silent
    // dead end — fail here instead (ADR-0007).
    if py_strip(&request.audience).is_empty() {
        return Err(Error::value(
            "forge requires an audience: the deployment this mandate is for",
        ));
    }
    integer(request.ttl_seconds, "ttl_seconds", 1, MAX_INTEGER)?;
    integer(request.budget, "budget", 0, MAX_INTEGER)?;
    profiles::rank(&request.required_profile)?;
    string(&request.agent_id, "agent_id", 256)?;
    string(&request.audience, "audience", 256)?;
    let mut required_profile = request.required_profile.clone();
    let agent_pubkey = match nonempty(&request.agent_pubkey) {
        Some(key) => {
            required_profile = profiles::HARDENED.into();
            Some(public_key(key)?)
        }
        None => None,
    };
    if let Some(depth) = request.max_delegation_depth {
        integer(depth, "max_delegation_depth", 0, MAX_INTEGER)?;
    }
    let expiry = add_seconds(now, request.ttl_seconds)?;
    let mut lines = vec![
        "agent_id({agent_id});".to_owned(),
        "required_profile({profile});".to_owned(),
        "right({tool}, {operation});".to_owned(),
        "budget_cap({budget});".to_owned(),
        "audience({aud});".to_owned(),
        "expires_at({exp});".to_owned(),
        "check if time($t), $t < {exp};".to_owned(),
    ];
    let mut params: HashMap<String, BiscuitTerm> = HashMap::from([
        (
            "agent_id".into(),
            BiscuitTerm::Str(request.agent_id.clone()),
        ),
        ("profile".into(), BiscuitTerm::Str(required_profile)),
        ("tool".into(), BiscuitTerm::Str(request.tool.clone())),
        (
            "operation".into(),
            BiscuitTerm::Str(request.operation.clone()),
        ),
        ("budget".into(), BiscuitTerm::Integer(request.budget as i64)),
        (
            "aud".into(),
            BiscuitTerm::Str(py_strip(&request.audience).to_owned()),
        ),
        ("exp".into(), date_term(expiry)),
    ]);
    if let Some(key) = agent_pubkey {
        lines.push("agent_pubkey({agent_pub});".into());
        params.insert("agent_pub".into(), BiscuitTerm::Str(key));
    }
    if let Some(upstream) = nonempty(&request.upstream) {
        // A check, not a fact: it can only narrow, and the proxy injects the matching
        // `upstream(...)` fact for the endpoint that receives the call.
        lines.push("check if upstream({ups});".into());
        params.insert("ups".into(), BiscuitTerm::Str(upstream.to_owned()));
    }
    if let Some(depth) = request.max_delegation_depth {
        lines.push("max_delegation_depth({mdd});".into());
        params.insert("mdd".into(), BiscuitTerm::Integer(depth as i64));
    }
    if let Some(prefix) = nonempty(&request.resource_prefix) {
        lines.push("check if resource($r), $r.starts_with({prefix});".into());
        params.insert(
            "prefix".into(),
            BiscuitTerm::Str(canonicalize_prefix(prefix)?),
        );
    }
    for (i, spec) in request.facts.iter().enumerate() {
        let (predicate, values) = parse_fact_spec(spec)?;
        let keys: Vec<String> = (0..values.len()).map(|j| format!("fact{i}_{j}")).collect();
        let placeholders: Vec<String> = keys.iter().map(|k| format!("{{{k}}}")).collect();
        lines.push(format!("{predicate}({});", placeholders.join(", ")));
        for (key, value) in keys.into_iter().zip(values) {
            params.insert(key, value.term());
        }
    }
    for (i, spec) in request.scope_args.iter().enumerate() {
        let (arg_name, predicate) = parse_scope_arg(spec)?;
        let key = format!("scope{i}");
        lines.push(format!("check if arg({{{key}}}, $x), {predicate}($x);"));
        params.insert(key, BiscuitTerm::Str(arg_name));
    }
    let builder =
        BiscuitBuilder::new().code_with_params(lines.join("\n"), params, HashMap::new())?;
    let token = builder.build(&biscuit_keypair(authority_private_str)?)?;
    check_unambiguous(&token)?;
    Ok(token.to_base64()?)
}

/// Restrictions an offline attenuation may add.
#[derive(Debug, Clone, Default)]
pub struct Attenuation {
    pub resource: Option<String>,
    pub budget: Option<i128>,
    pub ttl_seconds: Option<i128>,
    pub upstream: Option<String>,
    pub max_delegation_depth: Option<i128>,
    /// Keep only these tools (public names). Never grants one: the issuer's right
    /// is still required.
    pub tools: Vec<String>,
}

/// Append a restrictive block. Requires the authority *public* key (the trust anchor,
/// not a secret): only a verified token is re-serialized. Narrowing is monotonic and
/// cryptographically enforced.
pub fn attenuate(
    token_b64: &str,
    authority_public_str: &str,
    request: &Attenuation,
) -> Result<String> {
    attenuate_at(token_b64, authority_public_str, request, Utc::now())
}

pub fn attenuate_at(
    token_b64: &str,
    authority_public_str: &str,
    request: &Attenuation,
    now: DateTime<Utc>,
) -> Result<String> {
    if let Some(budget) = request.budget {
        integer(budget, "budget", 0, MAX_INTEGER)?;
    }
    if let Some(ttl) = request.ttl_seconds {
        integer(ttl, "ttl_seconds", 1, MAX_INTEGER)?;
    }
    if let Some(depth) = request.max_delegation_depth {
        integer(depth, "max_delegation_depth", 1, MAX_INTEGER)?;
    }
    let token = Biscuit::from_base64(token_b64, biscuit_public(authority_public_str)?)?;
    let mut lines: Vec<String> = Vec::new();
    let mut params: HashMap<String, BiscuitTerm> = HashMap::new();
    if let Some(resource) = nonempty(&request.resource) {
        lines.push("check if resource($r), $r.starts_with({prefix});".into());
        params.insert(
            "prefix".into(),
            BiscuitTerm::Str(canonicalize_prefix(resource)?),
        );
    }
    if let Some(budget) = request.budget {
        // Lower the ceiling; the proxy takes the min across all budget_cap facts.
        lines.push("budget_cap({budget});".into());
        params.insert("budget".into(), BiscuitTerm::Integer(budget as i64));
    }
    if let Some(ttl) = request.ttl_seconds {
        let expiry = add_seconds(now, ttl)?;
        lines.push("expires_at({exp});".into());
        lines.push("check if time($t), $t < {exp};".into());
        params.insert("exp".into(), date_term(expiry));
    }
    if let Some(upstream) = nonempty(&request.upstream) {
        // Narrow to one upstream without enumerating its tools. Monotonic: the check
        // only ever removes reachable endpoints.
        lines.push("check if upstream({ups});".into());
        params.insert("ups".into(), BiscuitTerm::Str(upstream.to_owned()));
    }
    if let Some(depth) = request.max_delegation_depth {
        lines.push("max_delegation_depth({mdd});".into());
        params.insert("mdd".into(), BiscuitTerm::Integer(depth as i64));
    }
    if !request.tools.is_empty() {
        let mut kept = std::collections::BTreeSet::new();
        for tool in &request.tools {
            let tool = string(tool, "tool", 128)?;
            kept.insert(BiscuitTerm::Str(tool.to_owned()));
        }
        if kept.len() > 64 {
            return Err(Error::value("at most 64 tools may be kept"));
        }
        lines.push("check if tool($t), {tools}.contains($t);".into());
        params.insert("tools".into(), BiscuitTerm::Set(kept));
    }
    if lines.is_empty() {
        return Err(Error::value(
            "attenuate needs at least one of: resource, budget, ttl, upstream, max-depth",
        ));
    }
    let block = BlockBuilder::new().code_with_params(lines.join("\n"), params, HashMap::new())?;
    let attenuated = token.append(block)?;
    check_unambiguous(&attenuated)?;
    Ok(attenuated.to_base64()?)
}

/// What `inspect` shows — no key required.
#[derive(Debug, Clone)]
pub struct InspectResult {
    pub block_count: usize,
    pub revocation_ids: Vec<String>,
    pub root_key_id: Option<u32>,
    pub blocks: Vec<String>,
    /// Authority-block facts, values flattened per name.
    pub facts: Vec<(String, Vec<Term>)>,
}

impl InspectResult {
    pub fn fact(&self, name: &str) -> Option<&Vec<Term>> {
        self.facts.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    pub fn first_str(&self, name: &str) -> Option<&str> {
        self.fact(name)
            .and_then(|v| v.first())
            .and_then(Term::as_str)
    }
}

fn parse_authority_facts(block0_source: &str) -> Result<Vec<(String, Vec<Term>)>> {
    // Human inspection accepts context facts too, but never infers identity by regex.
    let parsed: BlockFacts = block_facts(block0_source, false, true)?;
    Ok(parsed
        .0
        .into_iter()
        .map(|(name, facts)| (name, facts.into_iter().flatten().collect()))
        .collect())
}

pub fn block_sources(token: &UnverifiedBiscuit) -> Result<Vec<String>> {
    (0..token.block_count())
        .map(|i| token.print_block_source(i).map_err(Error::from))
        .collect()
}

/// Refuse a mandate whose rendered block source would be ambiguous.
///
/// Biscuit prints string terms between quotes without escaping them, and the typed
/// metadata is read back from that rendering: a string such as
/// `a"); user("alice"); x("` would print as three facts and fabricate an identity the
/// issuer never signed. No legitimate mandate string needs a quote or a backslash, so
/// any block symbol holding one makes the whole mandate refused, fail-closed.
pub fn check_unambiguous(token: &Biscuit) -> Result<()> {
    for index in 0..token.block_count() {
        if token
            .block_symbols(index)?
            .iter()
            .any(|s| s.contains(['"', '\\']))
        {
            return Err(Error::value(format!(
                "block {index} holds a string with a quote or backslash: its source would be ambiguous"
            )));
        }
    }
    Ok(())
}

pub fn verified_block_sources(token: &Biscuit) -> Result<Vec<String>> {
    check_unambiguous(token)?;
    (0..token.block_count())
        .map(|i| token.print_block_source(i).map_err(Error::from))
        .collect()
}

pub fn revocation_ids(identifiers: Vec<Vec<u8>>) -> Vec<String> {
    identifiers.into_iter().map(hex::encode).collect()
}

pub fn inspect(token_b64: &str) -> Result<InspectResult> {
    let token = UnverifiedBiscuit::from_base64(token_b64)?;
    let blocks = block_sources(&token)?;
    let facts = match blocks.first() {
        Some(source) => parse_authority_facts(source)?,
        None => Vec::new(),
    };
    Ok(InspectResult {
        block_count: token.block_count(),
        revocation_ids: revocation_ids(token.revocation_identifiers()),
        root_key_id: token.root_key_id(),
        blocks,
        facts,
    })
}

fn authority_value(token_b64: &str, name: &str) -> Result<Option<Term>> {
    let token = UnverifiedBiscuit::from_base64(token_b64)?;
    if token.block_count() == 0 {
        return Ok(None);
    }
    let facts = parse_authority_facts(&token.print_block_source(0)?)?;
    Ok(facts
        .into_iter()
        .find(|(n, _)| n == name)
        .and_then(|(_, v)| v.into_iter().next()))
}

/// Provenance-safe read of `agent_pubkey` from the authority block (3b).
pub fn authority_pubkey(token_b64: &str) -> Result<Option<Term>> {
    authority_value(token_b64, "agent_pubkey")
}

pub fn authority_required_profile(token_b64: &str) -> Result<Option<Term>> {
    authority_value(token_b64, "required_profile")
}

pub fn authority_agent_id(token_b64: &str) -> Result<Option<Term>> {
    authority_value(token_b64, "agent_id")
}

pub fn budget_caps_from_blocks<S: AsRef<str>>(blocks: &[S]) -> Result<Vec<i64>> {
    Ok(metadata(blocks)?.budget_cap)
}

/// Effective budget ceiling = min of all `budget_cap` facts across blocks.
pub fn min_budget_cap(token_b64: &str) -> Result<Option<i64>> {
    let token = UnverifiedBiscuit::from_base64(token_b64)?;
    Ok(budget_caps_from_blocks(&block_sources(&token)?)?
        .into_iter()
        .min())
}

/// Stable identifier for a forged capability (authority block revocation id).
pub fn capability_key(token_b64: &str) -> Result<String> {
    let token = UnverifiedBiscuit::from_base64(token_b64)?;
    revocation_ids(token.revocation_identifiers())
        .into_iter()
        .next()
        .ok_or_else(|| Error::value("mandate has no authority revocation identifier"))
}
