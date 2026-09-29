//! Wire and run the proxy from `serve` parameters (shared by the CLI and tests).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use crate::audit::{AuditLog, trusted_from};
use crate::budget::BudgetStore;
use crate::canonical::{canonicalize, sha256_hex};
use crate::error::{Error, Result};
use crate::json::strict_json;
use crate::keys;
use crate::nonce_cache::NonceCache;
use crate::policy::{Policy, PolicyReloader, load_policy};
use crate::profiles;
use crate::proxy::app::{ProxyConfig, close_upstreams, create_app};
use crate::proxy::upstream::{SharedUpstream, Upstream, build_upstream};
use crate::revocation::{RevocationList, RevocationSource};
use crate::validation::{choice, mapping, string_value};
use crate::verifier::{Verifier, VerifierOptions};

/// Every `tokencrumb serve` option, already parsed. Field names follow the CLI flags.
#[derive(Debug, Clone, Default)]
pub struct ServeOptions {
    pub upstream: Option<String>,
    pub authority_pub: PathBuf,
    pub policy: PathBuf,
    pub audience: String,
    pub upstream_name: Option<String>,
    /// `[upstream:]Header=ENV_VARIABLE`, repeatable.
    pub upstream_header: Vec<String>,
    pub upstream_user_credentials: Option<PathBuf>,
    pub previous_audit_pub: Vec<PathBuf>,
    pub allowed_origin: Vec<String>,
    pub previous_authority: Vec<PathBuf>,
    pub revocation_pub: Option<PathBuf>,
    /// `[host]:port`, default `:9443`.
    pub listen: String,
    pub mode: Option<String>,
    pub min_profile: Option<String>,
    pub registry: Option<String>,
    pub registry_pub: Option<PathBuf>,
    pub audit: PathBuf,
    pub audit_key: Option<PathBuf>,
    pub ephemeral_audit_key: bool,
    pub budget_state: Option<PathBuf>,
    pub gateway_id: Option<String>,
    pub freshness: i128,
    pub reload_policy: bool,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub insecure_http: bool,
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut raw = path.as_os_str().to_owned();
    raw.push(suffix);
    PathBuf::from(raw)
}

fn is_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn is_header_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// `--mode` / `--min-profile` override the policy file; the digest then names both, so
/// the audit never attributes an overridden decision to the unmodified file.
fn effective(policy: &Policy, mode: &Option<String>, min_profile: &Option<String>) -> Policy {
    if mode.is_none() && min_profile.is_none() {
        return policy.clone();
    }
    let mut overridden = policy.clone();
    let mut digest_source = serde_json::Map::new();
    digest_source.insert("source".into(), json!(policy.policy_digest));
    if let Some(mode) = mode {
        overridden.mode = mode.clone();
        digest_source.insert("mode".into(), json!(mode));
    }
    if let Some(profile) = min_profile {
        overridden.min_profile = profile.clone();
        digest_source.insert("min_profile".into(), json!(profile));
    }
    overridden.policy_digest =
        sha256_hex(&canonicalize(&Value::Object(digest_source)).expect("canonical digest source"));
    overridden
}

/// `[upstream:]Header=ENV_VARIABLE` -> upstream -> header -> secret.
fn credential_headers(specs: &[String]) -> Result<BTreeMap<Option<String>, Vec<(String, String)>>> {
    let mut out: BTreeMap<Option<String>, Vec<(String, String)>> = BTreeMap::new();
    for spec in specs {
        let (destination, env_name) = spec.split_once('=').unwrap_or((spec.as_str(), ""));
        if !spec.contains('=') || !is_env_name(env_name) {
            return Err(Error::value(
                "upstream header requires [upstream:]Header=ENV_VARIABLE",
            ));
        }
        let (target, header) = match destination.split_once(':') {
            Some((target, header)) => (Some(target.to_owned()), header),
            None => (None, destination),
        };
        if !is_header_name(header) {
            return Err(Error::value("invalid upstream header name"));
        }
        let value = std::env::var(env_name).ok().filter(|v| !v.is_empty());
        let Some(value) = value else {
            return Err(Error::value(format!(
                "missing credential environment variable: {env_name}"
            )));
        };
        let header = header.to_ascii_lowercase();
        let entry = out.entry(target).or_default();
        if entry.iter().any(|(h, _)| *h == header) {
            return Err(Error::value("duplicate upstream credential header"));
        }
        entry.push((header, value));
    }
    Ok(out)
}

const FORBIDDEN_USER_HEADERS: &[&str] = &[
    "cookie",
    "host",
    "content-length",
    "transfer-encoding",
    "mcp-session-id",
    "mcp-protocol-version",
    "last-event-id",
];

fn apply_user_credentials(
    path: &Path,
    upstreams: &mut [(Option<String>, Box<dyn Upstream>)],
) -> Result<()> {
    let records = strict_json(std::fs::read(path)?)?;
    let records = records
        .as_array()
        .filter(|r| !r.is_empty())
        .ok_or_else(|| Error::value("user credentials must be an array"))?;
    for record in records {
        let record = mapping(
            record,
            &["upstream", "issuer", "subject", "header", "env"],
            "user credential",
        )?;
        let target_name: Option<String> = match record.get("upstream") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => {
                return Err(Error::value(
                    "user credentials require a configured HTTP upstream",
                ));
            }
        };
        let target = upstreams
            .iter_mut()
            .find(|(name, _)| *name == target_name)
            .and_then(|(_, upstream)| upstream.as_http())
            .ok_or_else(|| Error::value("user credentials require a configured HTTP upstream"))?;
        let issuer = string_value(record.get("issuer"), "issuer", 4096)?;
        let subject = string_value(record.get("subject"), "subject", 256)?;
        let header = string_value(record.get("header"), "header", 256)?;
        let variable = string_value(record.get("env"), "env", 256)?;
        let secret = std::env::var(variable).ok().filter(|v| !v.is_empty());
        let Some(secret) = secret else {
            return Err(Error::value(format!(
                "missing user credential environment variable: {variable}"
            )));
        };
        if target.has_principal(issuer, subject) {
            return Err(Error::value("duplicate upstream user credential"));
        }
        if !is_header_name(header)
            || FORBIDDEN_USER_HEADERS.contains(&header.to_ascii_lowercase().as_str())
            || secret.contains(['\r', '\n'])
        {
            return Err(Error::value("invalid upstream user credential header"));
        }
        target.add_user_credential(issuer, subject, header, &secret)?;
    }
    Ok(())
}

/// Everything `serve` runs: the app configuration plus what the banner shows.
pub struct Runtime {
    pub config: ProxyConfig,
    /// The upstream specs, in endpoint order (for the banner).
    pub upstream_specs: Vec<String>,
}

/// Build the proxy configuration from `serve` options (no socket is opened).
pub fn build_config(options: &ServeOptions) -> Result<Runtime> {
    let budget_state = options
        .budget_state
        .clone()
        .unwrap_or_else(|| with_suffix(&options.audit, ".budget.json"));
    let source_policy = load_policy(&options.policy)?;
    if let Some(mode) = &options.mode {
        choice(mode, &["enforce", "warn-only"], "mode")?;
    }
    if let Some(profile) = &options.min_profile {
        profiles::rank(profile)?;
    }
    let policy = effective(&source_policy, &options.mode, &options.min_profile);

    let credentials = credential_headers(&options.upstream_header)?;
    // Where the upstreams come from is an either/or: taking both would leave one of the
    // two descriptions silently unused, and no reader could tell which.
    if !policy.upstreams.is_empty() && options.upstream.is_some() {
        return Err(Error::value(
            "--upstream and the `upstreams:` block of policy.yaml are mutually exclusive",
        ));
    }
    let mut upstreams: Vec<(Option<String>, Box<dyn Upstream>)> = Vec::new();
    let mut upstream_specs = Vec::new();
    if !policy.upstreams.is_empty() {
        for (name, spec) in &policy.upstreams {
            let headers = credentials.get(&Some(name.clone())).cloned();
            upstreams.push((Some(name.clone()), build_upstream(spec, headers)?));
            upstream_specs.push(name.clone());
        }
    } else if let Some(spec) = &options.upstream {
        upstreams.push((None, build_upstream(spec, credentials.get(&None).cloned())?));
        upstream_specs.push(spec.clone());
    } else {
        return Err(Error::value(
            "no upstream: pass --upstream, or declare an `upstreams:` block in policy.yaml",
        ));
    }
    if credentials
        .keys()
        .any(|target| !upstreams.iter().any(|(name, _)| name == target))
    {
        return Err(Error::value(
            "credential configured for an unknown upstream",
        ));
    }
    if let Some(path) = &options.upstream_user_credentials {
        apply_user_credentials(path, &mut upstreams)?;
    }
    let authority_pub = keys::load_public_key(&options.authority_pub)?;

    let revocation: Option<Arc<dyn RevocationSource>> = match &policy.revocation_path {
        Some(path) => {
            // The revocation list is signed by the authority key unless told otherwise.
            let signer = match &options.revocation_pub {
                Some(p) => keys::load_public_key(p)?,
                None => authority_pub.clone(),
            };
            Some(Arc::new(RevocationList::new(path, &signer, None, None)?))
        }
        None => None,
    };

    let resolver = match &options.registry {
        Some(url) => {
            let Some(registry_pub) = &options.registry_pub else {
                return Err(Error::value(
                    "--registry-pub is required to authenticate registry records",
                ));
            };
            Some(crate::registry::registry_resolver(
                url,
                &keys::load_public_key(registry_pub)?,
                4096,
            )?)
        }
        None => None,
    };

    // Opt-in: rules changing under a running gateway is not something to discover. The
    // reloader refuses a policy that fails to load and one that changes the upstream
    // set, so neither can silently take effect.
    let policy_source: Option<Box<dyn Fn() -> Arc<Policy> + Send + Sync>> = if options.reload_policy
    {
        let reloader = PolicyReloader::new(
            options.policy.clone(),
            source_policy.clone(),
            Duration::from_secs(2),
            Box::new(|_level, message| eprintln!("[tokencrumb] {message}")),
        );
        let (mode, min_profile) = (options.mode.clone(), options.min_profile.clone());
        Some(Box::new(move || {
            Arc::new(effective(&reloader.current(), &mode, &min_profile))
        }))
    } else {
        None
    };

    let mut verifier_options = VerifierOptions::new(options.audience.clone());
    verifier_options.upstream_name = options.upstream_name.clone();
    verifier_options.policy_source = policy_source;
    verifier_options.nonce_cache = Some(Arc::new(NonceCache::new(
        100_000,
        (options.freshness * 2).max(120),
        Some(&with_suffix(&budget_state, ".nonces.db")),
    )?));
    verifier_options.budget_store = Some(Arc::new(BudgetStore::open(&budget_state)?));
    verifier_options.revocation = revocation;
    verifier_options.resolve_agent_pubkey = resolver;
    verifier_options.freshness_seconds = options.freshness;
    verifier_options.previous_authority_keys = options
        .previous_authority
        .iter()
        .map(keys::load_public_key)
        .collect::<Result<_>>()?;
    let verifier = Verifier::new(&authority_pub, policy.clone(), verifier_options)?;

    // Audit signing key. An ephemeral key makes the chain unverifiable after a restart,
    // so it must be asked for explicitly rather than happen by default.
    let audit_private = if let Some(path) = &options.audit_key {
        keys::load_private_key(path, None)?
    } else if options.ephemeral_audit_key {
        let kp = keys::generate_keypair();
        eprintln!(
            "[tokencrumb] ephemeral audit signing pubkey: {}",
            kp.public_str
        );
        eprintln!("[tokencrumb] WARNING: this chain cannot be verified after a restart");
        kp.private_str
    } else {
        return Err(Error::value(
            "an audit signing key is required: pass --audit-key <file>, \
             or --ephemeral-audit-key to accept a chain that dies with this process",
        ));
    };
    let previous_audit: Vec<String> = options
        .previous_audit_pub
        .iter()
        .map(keys::load_public_key)
        .collect::<Result<_>>()?;
    let gateway_id = options
        .gateway_id
        .clone()
        .unwrap_or_else(|| format!("gw-{}", hostname()));
    let audit = AuditLog::new(
        &options.audit,
        &audit_private,
        &gateway_id,
        &policy.policy_digest,
        trusted_from(&previous_audit)?,
    )?;

    let upstreams: Vec<(Option<String>, SharedUpstream)> = upstreams
        .into_iter()
        .map(|(name, up)| (name, SharedUpstream::from(up)))
        .collect();
    let mut config = ProxyConfig::new(Arc::new(verifier), upstreams, Some(Arc::new(audit)));
    config.allowed_origins = options.allowed_origin.clone();
    Ok(Runtime {
        config,
        upstream_specs,
    })
}

pub fn hostname() -> String {
    let mut buffer = [0u8; 256];
    // SAFETY: gethostname writes at most `len` bytes into the buffer we own.
    let rc = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
    if rc != 0 {
        return "localhost".into();
    }
    let end = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
    String::from_utf8_lossy(&buffer[..end]).into_owned()
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

/// Run `tokencrumb serve` until interrupted. The CLI runs the listen/TLS guards itself
/// (with their own messages) and prints any error returned here as
/// `error: cannot start proxy: <message>`, as before.
pub async fn serve(options: ServeOptions) -> anyhow::Result<()> {
    let listen = if options.listen.is_empty() {
        ":9443"
    } else {
        options.listen.as_str()
    };
    let (host, port) = crate::net::parse_listen(listen).map_err(|e| anyhow::anyhow!("{e}"))?;
    let tls = crate::net::tls_pair(
        options.tls_cert.as_deref(),
        options.tls_key.as_deref(),
        "serve",
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    crate::net::guard_cleartext_bind(&host, tls.is_some(), options.insecure_http, "serve")
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let runtime = build_config(&options).map_err(|e| anyhow::anyhow!("{e}"))?;

    let scheme = if tls.is_some() { "https" } else { "http" };
    let endpoints: Vec<String> = runtime
        .config
        .upstreams
        .iter()
        .map(|(name, _)| match name {
            None => format!("{scheme}://{host}:{port}/mcp"),
            Some(n) => format!("{scheme}://{host}:{port}/mcp/{n}"),
        })
        .collect();
    let policy = runtime.config.verifier.policy();
    let budget_path = options
        .budget_state
        .clone()
        .unwrap_or_else(|| with_suffix(&options.audit, ".budget.json"));
    eprintln!(
        "TokenCrumb - MCP Proxy proxy listening on {}\n  upstream : {}{}\n  audience : {}\n  mode     : {}\n  \
         policy   : {}  (min_profile={}, digest={})\n  mcp spec : {}  (batch refused · server->client channel closed)\n  \
         registry : {}\n  audit    : {}\n  reload   : {}\n  tls      : {}\n  budgets  : {} (persistent local state)\n  \
         state    : budget, nonce and audit stores must share the same persistent volume across local workers.\n             \
         Cross-host distributed storage is not provided.",
        endpoints.join(", "),
        runtime.upstream_specs.join(", "),
        options
            .upstream_name
            .as_ref()
            .map(|n| format!(" (name: {n})"))
            .unwrap_or_default(),
        options.audience,
        policy.mode,
        options.policy.display(),
        policy.min_profile,
        &policy.policy_digest[..policy.policy_digest.len().min(12)],
        policy.mcp.spec_version,
        options.registry.as_deref().unwrap_or("-"),
        options.audit.display(),
        if options.reload_policy {
            "policy.yaml watched (upstreams fixed)"
        } else {
            "off"
        },
        if tls.is_some() {
            "on (renew = restart, no ACME)"
        } else {
            "off"
        },
        budget_path.display(),
    );

    let upstreams = runtime.config.upstreams.clone();
    let app = create_app(runtime.config).map_err(|e| anyhow::anyhow!("{e}"))?;
    let address: SocketAddr =
        crate::net::socket_addr(&host, port).map_err(|e| anyhow::anyhow!("{e}"))?;
    let handle = axum_server::Handle::new();
    let shutdown = handle.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        shutdown.graceful_shutdown(Some(Duration::from_secs(10)));
    });
    let service = app.into_make_service_with_connect_info::<SocketAddr>();
    let served = match tls {
        Some((cert, key)) => {
            let tls_config = crate::net::rustls_config(cert, key)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            axum_server::bind_rustls(address, tls_config)
                .handle(handle)
                .serve(service)
                .await
        }
        None => {
            axum_server::bind(address)
                .handle(handle)
                .serve(service)
                .await
        }
    };
    close_upstreams(&upstreams).await;
    served.map_err(|e| anyhow::anyhow!("{e}"))
}
