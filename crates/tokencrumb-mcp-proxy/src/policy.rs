//! `policy.yaml` — the proxy's *base* policy (tool -> Datalog mapping).
//!
//! Fine-grained authorization travels signed inside the Biscuit; `policy.yaml` only
//! declares how an MCP `tools/call` is projected into Datalog facts and which base
//! constraints/proofs the proxy enforces. Each tool mapping is, per the doctrine,
//! "a security hypothesis about the real semantics of the upstream tool".

use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::canonical::{canonicalize_prefix, sha256_hex};
use crate::duration::parse_duration;
use crate::error::{Error, Result, py_repr};
use crate::json::{as_integer, dumps};
use crate::profiles;
use crate::validation::{MAX_INTEGER, choice_value, integer, integer_value, mapping, string_value};

/// Proof facts, injected by the verifier only after real crypto checks.
pub const PROOF_FACTS: &[&str] = &[
    "call_signature_valid",
    "nonce_fresh",
    "arguments_bound",
    "capability_bound",
];

/// MCP methods the gateway relays without a mandate. `tools/call` (enforced) and
/// `tools/list` (filtered) are handled separately and are never listed here.
pub const DEFAULT_ALLOW_METHODS: &[&str] = &[
    "initialize",
    "ping",
    "notifications/initialized",
    "notifications/cancelled",
];

/// The MCP revision this gateway is pinned to. 2025-06-18 removed JSON-RPC batching,
/// which is why a batch body is refused rather than unpacked.
pub const DEFAULT_SPEC_VERSION: &str = "2025-06-18";

/// Projects one MCP call argument into a Datalog `arg(name, value)` fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgMapping {
    /// Key inside `arguments`, e.g. `incident_id`.
    pub source_key: String,
    /// Datalog fact name, e.g. `incident_id`.
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpPolicy {
    pub spec_version: String,
    pub allow_methods: Vec<String>,
}

impl Default for McpPolicy {
    fn default() -> Self {
        Self {
            spec_version: DEFAULT_SPEC_VERSION.into(),
            allow_methods: DEFAULT_ALLOW_METHODS
                .iter()
                .map(|m| (*m).to_owned())
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ToolPolicy {
    pub name: String,
    pub operation: String,
    /// Which upstream serves this tool (ADR-0006). `upstream_tool` renames it on the
    /// way out; the attestation and the argument binding always cover the PUBLIC name.
    pub upstream: Option<String>,
    pub upstream_tool: Option<String>,
    /// e.g. `arguments.path`
    pub resource_from: Option<String>,
    /// canonicalized allow-prefix
    pub resource_prefix: Option<String>,
    pub resource_exact: Option<String>,
    pub budget: Option<i128>,
    pub require: Vec<String>,
    pub args: Vec<ArgMapping>,
}

/// Runtime bounds on one Datalog evaluation (anti-DoS). Defaults mirror biscuit-auth's
/// own, so an absent `limits:` block changes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_facts: i128,
    pub max_iterations: i128,
    /// Wall-clock ceiling per authorization.
    pub max_time_ms: i128,
    /// Bytes of base64 token.
    pub max_token_size: i128,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_facts: 1000,
            max_iterations: 100,
            max_time_ms: 50,
            max_token_size: 16384,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    pub deny_unknown_tools: bool,
    /// `enforce` | `warn-only`
    pub mode: String,
    /// `native` | `registry_backed` | `hardened_biscuit_anchored`
    pub min_profile: String,
    /// Ceiling on the TOTAL number of calls one mandate may make, all tools and all
    /// upstreams together. A mandate's own budget_cap can lower it, never raise it.
    pub budget_total: Option<i128>,
    /// Longest life a mandate may have, in seconds (ADR-0002).
    pub max_ttl_seconds: i128,
    pub revocation_path: Option<String>,
    pub clock_skew_seconds: i128,
    pub limits: Limits,
    /// name -> upstream spec (URL or stdio command), in declaration order. Empty means
    /// the single unnamed upstream passed on the command line (ADR-0006).
    pub upstreams: Vec<(String, String)>,
    /// Tool mappings, in declaration order.
    pub tools: Vec<ToolPolicy>,
    pub mcp: McpPolicy,
    /// SHA-256 of the raw policy bytes, recorded on every audit entry.
    pub policy_digest: String,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            deny_unknown_tools: true,
            mode: "enforce".into(),
            min_profile: profiles::NATIVE.into(),
            budget_total: None,
            max_ttl_seconds: 28800,
            revocation_path: None,
            clock_skew_seconds: 30,
            limits: Limits::default(),
            upstreams: Vec::new(),
            tools: Vec::new(),
            mcp: McpPolicy::default(),
            policy_digest: String::new(),
        }
    }
}

impl Policy {
    pub fn tool(&self, name: &str) -> Option<&ToolPolicy> {
        self.tools.iter().find(|t| t.name == name)
    }

    /// Tool names served by one endpoint — the catalog `tools/list` may show.
    pub fn tools_for(&self, upstream: Option<&str>) -> Vec<&str> {
        self.tools
            .iter()
            .filter(|t| upstream.is_none() || t.upstream.as_deref() == upstream)
            .map(|t| t.name.as_str())
            .collect()
    }

    /// True for methods relayed as-is (never `tools/call` or `tools/list`).
    pub fn method_allowed(&self, method: &str) -> bool {
        self.mcp.allow_methods.iter().any(|m| m == method)
    }

    pub fn upstream(&self, name: &str) -> Option<&str> {
        self.upstreams
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, spec)| spec.as_str())
    }

    /// The upstream set compared as a mapping (order does not matter).
    pub fn same_upstreams(&self, other: &Policy) -> bool {
        let mut a = self.upstreams.clone();
        let mut b = other.upstreams.clone();
        a.sort();
        b.sort();
        a == b
    }
}

/// `arguments.path` -> `path`.
pub fn resource_key(resource_from: &str) -> &str {
    resource_from
        .strip_prefix("arguments.")
        .unwrap_or(resource_from)
}

/// The raw resource value out of the MCP call arguments per the mapping.
pub fn extract_resource<'a>(tool: &ToolPolicy, arguments: &'a Value) -> Option<&'a Value> {
    let key = resource_key(tool.resource_from.as_deref().filter(|s| !s.is_empty())?);
    arguments.get(key).filter(|v| !v.is_null())
}

/// The mapped call arguments present in the call, as `(fact_name, raw_value)` pairs.
/// A value may be a list — the verifier then requires *every* element to authorize.
pub fn mapped_args<'t, 'a>(
    tool: &'t ToolPolicy,
    arguments: &'a Value,
) -> Vec<(&'t str, &'a Value)> {
    tool.args
        .iter()
        .filter_map(|m| arguments.get(&m.source_key).map(|v| (m.name.as_str(), v)))
        .collect()
}

fn list<'a>(value: &'a Value, place: &str) -> Result<&'a Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| Error::value(format!("{place}: expected a list")))
}

/// Python's `repr()` of a policy value, for messages that quote it.
fn value_repr(value: &Value) -> String {
    match value {
        Value::String(s) => py_repr(s),
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        other => dumps(other),
    }
}

fn resolve_upstream(
    tool: &str,
    declared: Option<&Value>,
    upstreams: &[(String, String)],
) -> Result<Option<String>> {
    if let Some(declared) = declared.filter(|v| !v.is_null()) {
        return match declared {
            Value::String(name) if upstreams.iter().any(|(n, _)| n == name) => {
                Ok(Some(name.clone()))
            }
            other => Err(Error::value(format!(
                "tool {}: upstream {} is not declared in `upstreams:`",
                py_repr(tool),
                value_repr(other)
            ))),
        };
    }
    match upstreams.len() {
        0 => Ok(None),
        1 => Ok(Some(upstreams[0].0.clone())),
        n => {
            let mut names: Vec<&str> = upstreams.iter().map(|(n, _)| n.as_str()).collect();
            names.sort_unstable();
            Err(Error::value(format!(
                "tool {}: no `upstream:` while {n} are declared ({})",
                py_repr(tool),
                names.join(", ")
            )))
        }
    }
}

fn is_upstream_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn get_or<'a>(map: &'a serde_json::Map<String, Value>, key: &str, default: &'a Value) -> &'a Value {
    map.get(key).unwrap_or(default)
}

/// Validate a raw (YAML-decoded) policy document.
pub fn parse_policy(raw: &Value) -> Result<Policy> {
    let empty_map = Value::Object(Default::default());
    let empty_list = Value::Array(Vec::new());
    let raw = mapping(
        raw,
        &[
            "limits",
            "upstreams",
            "tools",
            "mcp",
            "deny_unknown_tools",
            "mode",
            "min_profile",
            "budget_total",
            "max_ttl",
            "revocation",
            "clock_skew_seconds",
        ],
        "policy",
    )?;
    let lim = mapping(
        get_or(raw, "limits", &empty_map),
        &[
            "max_facts",
            "max_iterations",
            "max_time_ms",
            "max_token_size",
        ],
        "limits",
    )?;
    let mut limits = Limits::default();
    for (key, value) in lim {
        let n = integer_value(value, &format!("limits.{key}"), 1, MAX_INTEGER)?;
        match key.as_str() {
            "max_facts" => limits.max_facts = n,
            "max_iterations" => limits.max_iterations = n,
            "max_time_ms" => limits.max_time_ms = n,
            _ => limits.max_token_size = n,
        }
    }

    let Value::Object(up) = get_or(raw, "upstreams", &empty_map) else {
        return Err(Error::value("upstreams: expected an object"));
    };
    let mut upstreams = Vec::new();
    for (name, spec) in up {
        if !is_upstream_name(name) {
            return Err(Error::value(
                "invalid upstream name (literal URL segment required)",
            ));
        }
        upstreams.push((
            name.clone(),
            string_value(Some(spec), "upstream", 2048)?.to_owned(),
        ));
    }

    let mut tools: Vec<ToolPolicy> = Vec::new();
    for entry in list(get_or(raw, "tools", &empty_list), "tools")? {
        let entry = mapping(
            entry,
            &[
                "name",
                "operation",
                "upstream",
                "upstream_tool",
                "resource",
                "allow",
                "require",
                "args",
            ],
            "tool",
        )?;
        let name = string_value(entry.get("name"), "tool.name", 256)?.to_owned();
        let operation = string_value(entry.get("operation"), "tool.operation", 256)?.to_owned();
        if tools.iter().any(|t| t.name == name) {
            return Err(Error::value(format!(
                "tool {} is mapped twice",
                py_repr(&name)
            )));
        }
        let allow = mapping(
            get_or(entry, "allow", &empty_map),
            &["resource_prefix", "resource_exact", "budget"],
            &format!("{name}.allow"),
        )?;
        let resource = mapping(
            get_or(entry, "resource", &empty_map),
            &["from"],
            &format!("{name}.resource"),
        )?;
        let source = match resource.get("from") {
            Some(v) => Some(string_value(Some(v), "resource.from", 256)?.to_owned()),
            None => None,
        };
        let prefix = match allow.get("resource_prefix") {
            Some(v) => Some(canonicalize_prefix(string_value(
                Some(v),
                "resource_prefix",
                4096,
            )?)?),
            None => None,
        };
        let exact = match allow.get("resource_exact") {
            Some(v) => Some(string_value(Some(v), "resource_exact", 4096)?.to_owned()),
            None => None,
        };
        if prefix.is_some() && exact.is_some() {
            return Err(Error::value("choose resource_prefix or resource_exact"));
        }
        if (prefix.is_some() || exact.is_some()) && source.is_none() {
            return Err(Error::value(
                "a resource restriction requires resource.from",
            ));
        }
        let mut require = Vec::new();
        for fact in list(get_or(entry, "require", &empty_list), "require")? {
            require.push(choice_value(fact, PROOF_FACTS, "require fact")?.to_owned());
        }
        let mut args = Vec::new();
        for arg in list(get_or(entry, "args", &empty_list), "args")? {
            let arg = mapping(arg, &["from", "as"], "arg mapping")?;
            let key = resource_key(string_value(arg.get("from"), "arg.from", 256)?).to_owned();
            let alias = match arg.get("as") {
                Some(v) => string_value(Some(v), "arg.as", 256)?.to_owned(),
                None => string_value(Some(&Value::String(key.clone())), "arg.as", 256)?.to_owned(),
            };
            args.push(ArgMapping {
                source_key: key,
                name: alias,
            });
        }
        let upstream = resolve_upstream(&name, entry.get("upstream"), &upstreams)?;
        let upstream_tool = match entry.get("upstream_tool") {
            Some(v) => Some(string_value(Some(v), "upstream_tool", 256)?.to_owned()),
            None => None,
        };
        let budget = match allow.get("budget") {
            Some(v) => Some(integer_value(v, "allow.budget", 0, MAX_INTEGER)?),
            None => None,
        };
        tools.push(ToolPolicy {
            name,
            operation,
            upstream,
            upstream_tool,
            resource_from: source,
            resource_prefix: prefix,
            resource_exact: exact,
            budget,
            require,
            args,
        });
    }

    let m = mapping(
        get_or(raw, "mcp", &empty_map),
        &["spec_version", "allow_methods"],
        "mcp",
    )?;
    let default_methods = Value::Array(
        DEFAULT_ALLOW_METHODS
            .iter()
            .map(|m| Value::String((*m).into()))
            .collect(),
    );
    let mut methods = Vec::new();
    for method in list(
        get_or(m, "allow_methods", &default_methods),
        "mcp.allow_methods",
    )? {
        if matches!(method.as_str(), Some("tools/call" | "tools/list")) {
            return Err(Error::value(format!(
                "mcp.allow_methods must not contain {} (handled separately)",
                value_repr(method)
            )));
        }
        methods.push(choice_value(method, DEFAULT_ALLOW_METHODS, "mcp.allow_methods")?.to_owned());
    }
    let default_spec = Value::String(DEFAULT_SPEC_VERSION.into());
    let spec = choice_value(
        get_or(m, "spec_version", &default_spec),
        &[DEFAULT_SPEC_VERSION],
        "spec_version",
    )?;

    let default_ttl = Value::String("8h".into());
    let ttl = match get_or(raw, "max_ttl", &default_ttl) {
        Value::String(s) => parse_duration(s)?,
        v @ Value::Number(_) if crate::validation::is_int(v) => {
            let n = as_integer(v).expect("integer");
            parse_duration(&n.to_string()).map_err(|_| {
                Error::new(
                    crate::error::ErrorKind::Duration,
                    format!("invalid duration: {n} (use e.g. 300s, 15m, 8h, 1d)"),
                )
            })?
        }
        _ => return Err(Error::value("max_ttl: expected positive duration")),
    };
    let max_ttl_seconds = integer(ttl, "max_ttl", 1, MAX_INTEGER)?;
    let budget_total = match raw.get("budget_total") {
        Some(v) => Some(integer_value(v, "budget_total", 0, MAX_INTEGER)?),
        None => None,
    };
    let revocation_path = match raw.get("revocation") {
        Some(v) => Some(string_value(Some(v), "revocation", 4096)?.to_owned()),
        None => None,
    };

    // Field checks, in the order the former dataclass ran them.
    let default_mode = Value::String("enforce".into());
    let mode = choice_value(
        get_or(raw, "mode", &default_mode),
        &["enforce", "warn-only"],
        "mode",
    )?
    .to_owned();
    let default_profile = Value::String(profiles::NATIVE.into());
    let min_profile = match get_or(raw, "min_profile", &default_profile) {
        Value::String(p) => {
            profiles::rank(p)?;
            p.clone()
        }
        other => {
            return Err(Error::value(format!(
                "unknown security profile: {}",
                value_repr(other)
            )));
        }
    };
    let deny_unknown_tools = match get_or(raw, "deny_unknown_tools", &Value::Bool(true)) {
        Value::Bool(b) => *b,
        _ => return Err(Error::value("deny_unknown_tools: expected boolean")),
    };
    let default_skew = crate::json::int(30);
    let clock_skew_seconds = integer_value(
        get_or(raw, "clock_skew_seconds", &default_skew),
        "clock_skew_seconds",
        0,
        3600,
    )?;

    Ok(Policy {
        deny_unknown_tools,
        mode,
        min_profile,
        budget_total,
        max_ttl_seconds,
        revocation_path,
        clock_skew_seconds,
        limits,
        upstreams,
        tools,
        mcp: McpPolicy {
            spec_version: spec.to_owned(),
            allow_methods: methods,
        },
        policy_digest: String::new(),
    })
}

/// Parse policy text (PyYAML semantics, duplicate keys refused).
pub fn parse_policy_text(text: &str) -> Result<Policy> {
    parse_policy(&crate::yaml11::load(text, true)?)
}

pub fn load_policy(path: impl AsRef<Path>) -> Result<Policy> {
    let raw = std::fs::read(path)?;
    let text = String::from_utf8(raw.clone()).map_err(|e| Error::value(e.to_string()))?;
    let mut policy = parse_policy_text(&text)?;
    policy.policy_digest = sha256_hex(&raw);
    Ok(policy)
}

/// Receives `(level, message)` for every reload decision.
pub type PolicyEventSink = Box<dyn Fn(&str, &str) + Send + Sync>;

/// (device, inode, sha256) of a consistent read of the policy file.
type Snapshot = (u64, u64, String);

/// Serve the current policy, picking up edits to the file without a restart.
///
/// Three rules make this safe enough to run in front of a live gateway:
///
/// * **A policy that does not load does not take effect.** Any error keeps the
///   policy already in force; the proxy never falls back to a permissive default.
/// * **The upstream set is frozen at startup.** Endpoints are routes built when the
///   app was created, so a reload that adds or removes an upstream is refused whole.
/// * **The digest travels into the audit.** Every entry records `policy_digest`.
pub struct PolicyReloader {
    path: PathBuf,
    min_interval: Duration,
    on_event: PolicyEventSink,
    frozen: Policy,
    state: Mutex<ReloadState>,
}

struct ReloadState {
    policy: Arc<Policy>,
    snapshot: Option<Snapshot>,
    checked_at: Instant,
}

fn snapshot(path: &Path) -> Result<(Snapshot, Vec<u8>)> {
    let mut file = std::fs::File::open(path)?;
    let before = file.metadata()?;
    let mut raw = Vec::new();
    (&mut file).take(1024 * 1024 + 1).read_to_end(&mut raw)?;
    let after = file.metadata()?;
    let changed = (before.size(), before.mtime(), before.mtime_nsec())
        != (after.size(), after.mtime(), after.mtime_nsec());
    if raw.len() > 1024 * 1024 || changed {
        return Err(Error::value(
            "policy changed while reading or exceeds size limit",
        ));
    }
    Ok(((after.dev(), after.ino(), sha256_hex(&raw)), raw))
}

impl PolicyReloader {
    pub fn new(
        path: impl Into<PathBuf>,
        current: Policy,
        min_interval: Duration,
        on_event: PolicyEventSink,
    ) -> Self {
        let path = path.into();
        let initial = snapshot(&path).ok().map(|(s, _)| s);
        Self {
            path,
            min_interval,
            on_event,
            frozen: current.clone(),
            state: Mutex::new(ReloadState {
                policy: Arc::new(current),
                snapshot: initial,
                checked_at: Instant::now(),
            }),
        }
    }

    /// The policy in force now (re-reading the file at most every `min_interval`).
    pub fn current(&self) -> Arc<Policy> {
        let mut state = self.state.lock().expect("policy lock");
        if state.checked_at.elapsed() < self.min_interval {
            return state.policy.clone();
        }
        state.checked_at = Instant::now();
        let candidate = (|| -> Result<Option<(Snapshot, Policy)>> {
            let (snap, raw) = snapshot(&self.path)?;
            if state.snapshot.as_ref() == Some(&snap) {
                return Ok(None);
            }
            if let Some(previous) = &state.snapshot {
                if (previous.0, previous.1) == (snap.0, snap.1) {
                    return Err(Error::value(
                        "publish policy by atomic replacement; in-place writes are refused",
                    ));
                }
            }
            let text = String::from_utf8(raw).map_err(|e| Error::value(e.to_string()))?;
            let mut policy = parse_policy_text(&text)?;
            policy.policy_digest = snap.2.clone();
            Ok(Some((snap, policy)))
        })();
        match candidate {
            Ok(None) => state.policy.clone(),
            Err(e) => {
                (self.on_event)(
                    "error",
                    &format!("policy reload refused ({e}); keeping the policy in force"),
                );
                state.policy.clone()
            }
            Ok(Some((snap, policy))) => {
                if !policy.same_upstreams(&self.frozen)
                    || policy.revocation_path != self.frozen.revocation_path
                {
                    (self.on_event)(
                        "error",
                        "policy reload refused: the upstream set is fixed at startup \
                         (endpoints are routes); revocation path is fixed too; restart to change it",
                    );
                    return state.policy.clone();
                }
                (self.on_event)(
                    "info",
                    &format!("policy reloaded, digest={}", &policy.policy_digest[..12]),
                );
                state.snapshot = Some(snap);
                state.policy = Arc::new(policy);
                state.policy.clone()
            }
        }
    }
}
