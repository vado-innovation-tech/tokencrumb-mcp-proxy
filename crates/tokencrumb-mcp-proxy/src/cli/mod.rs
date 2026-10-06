//! `tokencrumb` command-line interface (control plane + proxy launcher).
//!
//! Standalone air-gapped lifecycle needs only: keygen -> forge -> attenuate -> serve
//! (zero IAM, zero registry). `inspect` is the auditor's window into a token.
//!
//! Contract kept from the former implementation: command and option names, defaults,
//! repeatable options, `file:`/`literal:` secrets, a token argument that is either a
//! file or the token itself, forged tokens on stdout with status on stderr, refusals
//! as `error: <message>` on stderr with exit code 1, usage errors with exit code 2.

mod render;
mod wrap;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use tokencrumb_mcp_proxy::biscuit_ops::{self as ops, Attenuation, ForgeRequest};
use tokencrumb_mcp_proxy::error::py_repr;
use tokencrumb_mcp_proxy::json::{dumps, dumps_indent, sort_keys, strict_json};
use tokencrumb_mcp_proxy::proxy::runtime::ServeOptions;
use tokencrumb_mcp_proxy::validation::py_strip;
use tokencrumb_mcp_proxy::{ErrorKind, audit, keys, net, registry, revocation, storage};
use clap::{CommandFactory as _, Parser, Subcommand};
use serde_json::{Map, Value, json};

use render::{Stream, grid, paint, panel};

#[derive(Parser, Debug)]
#[command(
    name = "tokencrumb-mcp-proxy",
    about = "TokenCrumb - MCP Proxy — MCP authorization proxy & Biscuit capability toolkit.",
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Generate an Ed25519 keypair (authority root, agent identity, or audit signer).
    Keygen {
        /// Base name; writes <out>.key and <out>.pub
        #[arg(long)]
        out: String,
        /// authority | agent | audit
        #[arg(long = "type", default_value = "authority")]
        key_type: String,
        /// Encrypt the private key (scrypt+AES-GCM)
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Forge a capability Biscuit (authority block, signed by the root key).
    ///
    /// Scoping a right to specific objects takes a fact plus the rule that binds it to
    /// the call argument:
    ///
    ///     --fact 'assigned_incident("INC-123")' --scope-arg incident_id=assigned_incident
    ///
    /// The gateway then compares the call's `incident_id` against a fact signed into
    /// the token, with no upstream lookup on the decision path.
    Forge {
        /// Authority private key file
        #[arg(long)]
        key: String,
        /// Granted MCP tool name
        #[arg(long)]
        tool: String,
        /// Datalog operation (read/write/...)
        #[arg(long, default_value = "read")]
        operation: String,
        #[arg(long, default_value = "agent-01")]
        agent_id: String,
        /// Time to live, e.g. 15m, 8h
        #[arg(long, default_value = "15m")]
        ttl: String,
        /// Max calls (integer)
        #[arg(long, default_value_t = 200, allow_negative_numbers = true)]
        budget: i128,
        #[arg(long)]
        resource_prefix: Option<String>,
        /// ed25519/... for profile 3b/3a
        #[arg(long)]
        agent_pubkey: Option<String>,
        #[arg(long, default_value = "native")]
        required_profile: String,
        /// Deployment this mandate is for; must match the proxy's --audience
        #[arg(long)]
        audience: String,
        /// Restrict the mandate to one upstream by name
        #[arg(long)]
        upstream: Option<String>,
        #[arg(long = "max-depth", allow_negative_numbers = true)]
        max_delegation_depth: Option<i128>,
        /// Authority-block fact, repeatable, e.g. 'assigned_incident("INC-123")'
        #[arg(long)]
        fact: Vec<String>,
        /// Bind a call argument to a fact, repeatable: incident_id=assigned_incident
        #[arg(long)]
        scope_arg: Vec<String>,
        #[arg(long)]
        passphrase: Option<String>,
        /// Write token here (default: stdout)
        #[arg(long)]
        out: Option<String>,
    },
    /// Append a restrictive block (offline, monotonic narrowing).
    Attenuate {
        /// Token file or base64 string
        #[arg(long)]
        token: String,
        /// Authority public key file
        #[arg(long)]
        authority_pub: String,
        /// Restrict to a resource prefix
        #[arg(long)]
        resource: Option<String>,
        /// Lower the budget ceiling
        #[arg(long, allow_negative_numbers = true)]
        budget: Option<i128>,
        /// Shorten TTL
        #[arg(long)]
        ttl: Option<String>,
        /// Restrict to one upstream by name (no tool enumeration)
        #[arg(long)]
        upstream: Option<String>,
        #[arg(long = "max-depth", allow_negative_numbers = true)]
        max_delegation_depth: Option<i128>,
        /// Keep only this tool (repeatable); the others become unusable
        #[arg(long = "tool")]
        tools: Vec<String>,
        #[arg(long)]
        out: Option<String>,
    },
    /// Show a token's blocks, facts and Datalog checks (no key required).
    Inspect {
        /// Token file or base64 string
        token: String,
    },
    /// Launch the TokenCrumb - MCP Proxy proxy in front of an unmodified MCP server.
    Serve(ServeArgs),
    /// Verify an audit log offline: entry hashes, signatures and chain continuity.
    AuditVerify {
        /// Audit log path
        #[arg(long, default_value = "audit.log")]
        log: String,
        /// Audit signing public key (file or ed25519/...)
        #[arg(long = "pub")]
        public: String,
        /// Additional trusted audit public key file
        #[arg(long)]
        previous_pub: Vec<String>,
    },
    /// Emit a signed `{seq, head_hash}` attestation, for publication to a witness.
    ///
    /// The chain detects tampering by anyone WITHOUT the audit key — but a compromised
    /// proxy holds that key and can rewrite and re-sign its whole log. Publishing this
    /// attestation at intervals to somewhere the proxy cannot reach bounds any rewrite
    /// to the time since the last anchor. Run it on a timer; keep the output off this
    /// host.
    AuditHead {
        /// Audit log path
        #[arg(long, default_value = "audit.log")]
        log: String,
        /// Audit signing private key file
        #[arg(long)]
        key: String,
        #[arg(long)]
        gateway_id: Option<String>,
        /// Additional trusted audit public key file
        #[arg(long)]
        previous_pub: Vec<String>,
        #[arg(long)]
        passphrase: Option<String>,
        /// Write the attestation here (default: stdout)
        #[arg(long)]
        out: Option<String>,
    },
    /// Run the agent public-key registry (profile 3a).
    RegistryServe {
        /// Persistent registry signing private key file
        #[arg(long)]
        signing_key: String,
        /// [host]:port
        #[arg(long, default_value = ":8081")]
        listen: String,
        /// JSON store path
        #[arg(long, default_value = "agents.json")]
        store: String,
        /// Registry write secret: literal value or file:/absolute/path
        #[arg(long)]
        write_token: String,
        /// PEM certificate chain
        #[arg(long)]
        tls_cert: Option<PathBuf>,
        /// PEM private key (no ACME: renew = restart)
        #[arg(long)]
        tls_key: Option<PathBuf>,
        /// Serve a non-loopback address in cleartext (agent keys travel unprotected)
        #[arg(long)]
        insecure_http: bool,
    },
    /// Register an agent's public key (via HTTP or directly into a store file).
    RegistryAdd {
        #[arg(long)]
        agent_id: String,
        /// ed25519/... agent public key
        #[arg(long)]
        pubkey: String,
        /// Registry base URL (HTTP register)
        #[arg(long)]
        registry: Option<String>,
        /// Registry write secret: literal value or file:/absolute/path
        #[arg(long)]
        token: Option<String>,
        /// Write directly to a JSON store instead
        #[arg(long)]
        store: Option<String>,
        #[arg(long)]
        owner_ref: Option<String>,
    },
    /// Add an entry to the signed, hot-reloadable revocation list.
    Revoke {
        /// Signing private key (authority) for the list
        #[arg(long)]
        key: String,
        #[arg(long, default_value = "revoked.list")]
        out: String,
        /// A revocation_id to add
        #[arg(long)]
        add: Option<String>,
        /// Token issuer public key when distinct from the revocation signer
        #[arg(long)]
        authority_pub: Option<String>,
        /// Revoke a token by its authority id
        #[arg(long)]
        from_token: Option<String>,
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Wrap a stdio MCP client: hold the token & agent key, sign each tools/call
    /// attestation, and forward to the HTTP proxy. Point your MCP client's command
    /// at this. stdout carries the MCP channel; do not print anything else to it.
    ClientWrap {
        /// Proxy MCP endpoint, e.g. http://host:9443/mcp
        #[arg(long)]
        proxy: String,
        /// Biscuit token file or base64
        #[arg(long)]
        token: String,
        /// Agent private key (enables 3b/3a signing)
        #[arg(long)]
        agent_key: Option<String>,
        /// Override agent id (default: from token)
        #[arg(long)]
        agent_id: Option<String>,
        #[arg(long)]
        passphrase: Option<String>,
        /// CA bundle (PEM) trusted for the proxy's TLS cert
        #[arg(long)]
        ca: Option<String>,
    },
    /// Validate a policy and publish it by atomic replacement for hot reload.
    PolicyInstall { source: String, destination: String },
    /// Verify an old unversioned list and write a fresh signed list to a NEW file.
    RevocationMigrate {
        source: String,
        destination: String,
        #[arg(long)]
        old_pub: String,
        #[arg(long)]
        key: String,
    },
    /// Verify an issuer response against a separately provisioned public trust anchor.
    ///
    /// With --url, only checks that the issuer URL is safe to send credentials to.
    /// With --response, verifies the issuer's `{"biscuit": ...}` answer against
    /// --authority-pub (provisioned beforehand, never taken from the issuer) and writes
    /// the mandate to --out.
    Bootstrap {
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        authority_pub: Option<String>,
        #[arg(long)]
        response: Option<String>,
        #[arg(long)]
        out: Option<String>,
    },
    /// Print a DPoP proof (RFC 9449) signed by the agent key, for one HTTP request.
    ///
    /// An issuer in `hardened_biscuit_anchored` anchors the key of this proof in the
    /// mandate: the agent proves possession instead of declaring a key, e.g.
    /// curl -H "DPoP: $(tokencrumb dpop-proof --agent-key agent.key --url $TOKEN_URL)" …
    DpopProof {
        /// Agent private key file
        #[arg(long)]
        agent_key: String,
        /// Exact URL of the request, without query or fragment
        #[arg(long)]
        url: String,
        #[arg(long, default_value = "POST")]
        method: String,
        #[arg(long)]
        passphrase: Option<String>,
    },
}

#[derive(clap::Args, Debug)]
pub struct ServeArgs {
    /// http://host:port[/mcp] or 'npx ...'; omit when policy.yaml declares `upstreams:`
    #[arg(long)]
    upstream: Option<String>,
    /// Authority public key file
    #[arg(long)]
    authority_pub: PathBuf,
    /// policy.yaml path
    #[arg(long)]
    policy: PathBuf,
    /// This deployment's name; mandates minted for another one are refused
    #[arg(long)]
    audience: String,
    /// Name of the upstream this gateway fronts, for `check if upstream(..)`
    #[arg(long)]
    upstream_name: Option<String>,
    /// [upstream:]Header=ENV_VARIABLE; repeatable, secrets stay outside arguments
    #[arg(long)]
    upstream_header: Vec<String>,
    /// JSON map of signed issuer/subject to header/environment variable
    #[arg(long)]
    upstream_user_credentials: Option<PathBuf>,
    /// Additional trusted audit public key file; repeatable
    #[arg(long)]
    previous_audit_pub: Vec<PathBuf>,
    /// Explicitly trusted browser Origin; repeatable
    #[arg(long)]
    allowed_origin: Vec<String>,
    /// Additional explicitly trusted authority public key file; repeatable
    #[arg(long)]
    previous_authority: Vec<PathBuf>,
    /// Public key of the revocation signer
    #[arg(long)]
    revocation_pub: Option<PathBuf>,
    /// [host]:port
    #[arg(long, default_value = ":9443")]
    listen: String,
    /// enforce | warn-only (overrides policy)
    #[arg(long)]
    mode: Option<String>,
    /// native|registry_backed|hardened_biscuit_anchored
    #[arg(long)]
    min_profile: Option<String>,
    /// Registry base URL (profile 3a)
    #[arg(long)]
    registry: Option<String>,
    /// Trusted registry signing public key file
    #[arg(long)]
    registry_pub: Option<PathBuf>,
    /// Audit log path
    #[arg(long, default_value = "audit.log")]
    audit: PathBuf,
    /// Audit signing private key file
    #[arg(long)]
    audit_key: Option<PathBuf>,
    /// Sign the audit chain with a throwaway key (unverifiable after restart)
    #[arg(long)]
    ephemeral_audit_key: bool,
    /// Persist budget counters here, so a consumed one-shot survives a restart
    #[arg(long)]
    budget_state: Option<PathBuf>,
    /// Identifier recorded in the audit
    #[arg(long)]
    gateway_id: Option<String>,
    /// Attestation freshness window (s)
    #[arg(long, default_value_t = 60, allow_negative_numbers = true)]
    freshness: i128,
    /// Pick up policy.yaml edits without a restart (upstreams stay fixed)
    #[arg(long)]
    reload_policy: bool,
    /// PEM certificate chain
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    /// PEM private key (no ACME: renew = restart)
    #[arg(long)]
    tls_key: Option<PathBuf>,
    /// Serve a non-loopback address in cleartext (mandates travel unprotected)
    #[arg(long)]
    insecure_http: bool,
}

impl ServeArgs {
    /// The runtime's view of the flags (field names follow the CLI flags).
    pub fn options(&self) -> ServeOptions {
        ServeOptions {
            upstream: self.upstream.clone(),
            authority_pub: self.authority_pub.clone(),
            policy: self.policy.clone(),
            audience: self.audience.clone(),
            upstream_name: self.upstream_name.clone(),
            upstream_header: self.upstream_header.clone(),
            upstream_user_credentials: self.upstream_user_credentials.clone(),
            previous_audit_pub: self.previous_audit_pub.clone(),
            allowed_origin: self.allowed_origin.clone(),
            previous_authority: self.previous_authority.clone(),
            revocation_pub: self.revocation_pub.clone(),
            listen: self.listen.clone(),
            mode: self.mode.clone(),
            min_profile: self.min_profile.clone(),
            registry: self.registry.clone(),
            registry_pub: self.registry_pub.clone(),
            audit: self.audit.clone(),
            audit_key: self.audit_key.clone(),
            ephemeral_audit_key: self.ephemeral_audit_key,
            budget_state: self.budget_state.clone(),
            gateway_id: self.gateway_id.clone(),
            freshness: self.freshness,
            reload_policy: self.reload_policy,
            tls_cert: self.tls_cert.clone(),
            tls_key: self.tls_key.clone(),
            insecure_http: self.insecure_http,
        }
    }
}

// --------------------------------------------------------------------------- //
// Outcomes
// --------------------------------------------------------------------------- //

/// How a command ends when it does not succeed.
pub enum Exit {
    /// A refusal: `error: <message>` on stderr, exit code 1.
    Fail(String),
    /// An exit code whose message, if any, was already written.
    Code(u8),
}

type Outcome = Result<(), Exit>;

fn fail<T>(message: impl Into<String>) -> Result<T, Exit> {
    Err(Exit::Fail(message.into()))
}

/// Library errors become refusals with their message.
impl From<tokencrumb_mcp_proxy::Error> for Exit {
    fn from(error: tokencrumb_mcp_proxy::Error) -> Self {
        Exit::Fail(error.message)
    }
}

/// A usage error (exit code 2) reported the way clap reports its own.
fn usage_error(subcommand: &str, message: impl std::fmt::Display) -> Exit {
    let mut command = Cli::command();
    let command = command
        .find_subcommand_mut(subcommand)
        .expect("known subcommand")
        .clone()
        .bin_name(format!("tokencrumb {subcommand}"));
    let mut command = command;
    let _ = command
        .error(clap::error::ErrorKind::ValueValidation, message)
        .print();
    Exit::Code(2)
}

fn status(message: &str) {
    eprintln!("{message}");
}

fn say(message: &str) {
    println!("{message}");
}

pub fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Exit::Fail(message)) => {
            eprintln!("{} {message}", paint("error:", "1;31", Stream::Stderr));
            ExitCode::from(1)
        }
        Err(Exit::Code(code)) => ExitCode::from(code),
    }
}

fn run(command: Command) -> Outcome {
    match command {
        Command::Keygen {
            out,
            key_type,
            passphrase,
        } => keygen(&out, &key_type, passphrase.as_deref()),
        Command::Forge {
            key,
            tool,
            operation,
            agent_id,
            ttl,
            budget,
            resource_prefix,
            agent_pubkey,
            required_profile,
            audience,
            upstream,
            max_delegation_depth,
            fact,
            scope_arg,
            passphrase,
            out,
        } => {
            let private = load_private(&key, passphrase.as_deref())
                .or_else(|e| fail(format!("cannot load private key: {e}")))?;
            let ttl_seconds = tokencrumb_mcp_proxy::duration::parse_duration(&ttl)
                .map_err(|e| usage_error("forge", format!("Invalid value: {}", e.message)))?;
            let request = ForgeRequest {
                agent_id,
                tool,
                operation,
                ttl_seconds,
                budget,
                audience,
                resource_prefix,
                agent_pubkey,
                required_profile,
                upstream,
                max_delegation_depth,
                facts: fact,
                scope_args: scope_arg,
            };
            let token = ops::forge(&private, &request)?;
            emit_token(&token, out.as_deref(), "forged")
        }
        Command::Attenuate {
            token,
            authority_pub,
            resource,
            budget,
            ttl,
            upstream,
            max_delegation_depth,
            tools,
            out,
        } => {
            let token_b64 = read_token_arg(&token);
            let public = load_public(&authority_pub).map_err(Exit::Fail)?;
            let attenuated = (|| -> tokencrumb_mcp_proxy::Result<String> {
                let ttl_seconds = match ttl.as_deref().filter(|t| !t.is_empty()) {
                    Some(ttl) => Some(tokencrumb_mcp_proxy::duration::parse_duration(ttl)?),
                    None => None,
                };
                ops::attenuate(
                    &token_b64,
                    &public,
                    &Attenuation {
                        resource,
                        budget,
                        ttl_seconds,
                        upstream,
                        max_delegation_depth,
                        tools,
                    },
                )
            })()
            .or_else(|e| fail(format!("attenuation failed: {}", e.message)))?;
            emit_token(&attenuated, out.as_deref(), "attenuated")
        }
        Command::Inspect { token } => inspect(&token),
        Command::Serve(args) => serve(&args),
        Command::AuditVerify {
            log,
            public,
            previous_pub,
        } => audit_verify(&log, &public, &previous_pub),
        Command::AuditHead {
            log,
            key,
            gateway_id,
            previous_pub,
            passphrase,
            out,
        } => audit_head(
            &log,
            &key,
            gateway_id.as_deref(),
            &previous_pub,
            passphrase.as_deref(),
            out.as_deref(),
        ),
        Command::RegistryServe {
            signing_key,
            listen,
            store,
            write_token,
            tls_cert,
            tls_key,
            insecure_http,
        } => registry_serve(
            &signing_key,
            &listen,
            &store,
            &write_token,
            tls_cert.as_deref(),
            tls_key.as_deref(),
            insecure_http,
        ),
        Command::RegistryAdd {
            agent_id,
            pubkey,
            registry,
            token,
            store,
            owner_ref,
        } => registry_add(
            &agent_id,
            &pubkey,
            registry.as_deref(),
            token.as_deref(),
            store.as_deref(),
            owner_ref.as_deref(),
        ),
        Command::Revoke {
            key,
            out,
            add,
            authority_pub,
            from_token,
            passphrase,
        } => revoke(
            &key,
            &out,
            add.as_deref(),
            authority_pub.as_deref(),
            from_token.as_deref(),
            passphrase.as_deref(),
        ),
        Command::ClientWrap {
            proxy,
            token,
            agent_key,
            agent_id,
            passphrase,
            ca,
        } => wrap::client_wrap(
            &proxy,
            &token,
            agent_key.as_deref(),
            agent_id.as_deref(),
            passphrase.as_deref(),
            ca.as_deref(),
        ),
        Command::PolicyInstall {
            source,
            destination,
        } => policy_install(&source, &destination),
        Command::RevocationMigrate {
            source,
            destination,
            old_pub,
            key,
        } => revocation_migrate(&source, &destination, &old_pub, &key),
        Command::Bootstrap {
            url,
            authority_pub,
            response,
            out,
        } => bootstrap(
            url.as_deref(),
            authority_pub.as_deref(),
            response.as_deref(),
            out.as_deref(),
        ),
        Command::DpopProof {
            agent_key,
            url,
            method,
            passphrase,
        } => {
            let private = load_private(&agent_key, passphrase.as_deref()).map_err(Exit::Fail)?;
            let proof = tokencrumb_mcp_proxy::dpop::proof(&private, &method, &url, chrono::Utc::now())?;
            say(&proof);
            Ok(())
        }
    }
}

// --------------------------------------------------------------------------- //
// helpers
// --------------------------------------------------------------------------- //

/// Python's rendering of an `OSError`: `[Errno 2] No such file or directory: 'x'`.
pub fn os_error(error: &std::io::Error, path: &str) -> String {
    match error.raw_os_error() {
        Some(code) => {
            let text = error.to_string();
            let description = text.split(" (os error").next().unwrap_or(&text);
            format!("[Errno {code}] {description}: {}", py_repr(path))
        }
        None => error.to_string(),
    }
}

/// Open the file first so a missing or unreadable one is reported with its errno.
fn readable(path: &str) -> Result<(), String> {
    std::fs::File::open(path)
        .map(drop)
        .map_err(|e| os_error(&e, path))
}

pub fn load_private(path: &str, passphrase: Option<&str>) -> Result<String, String> {
    readable(path)?;
    keys::load_private_key(path, passphrase).map_err(|e| e.message)
}

pub fn load_public(path: &str) -> Result<String, String> {
    readable(path)?;
    keys::load_public_key(path).map_err(|e| e.message)
}

/// Accept either a path to a token file or the raw base64 token.
///
/// A raw token can exceed the filesystem's component-length limit, so a path that
/// cannot be inspected or read is simply taken as the token itself.
pub fn read_token_arg(value: &str) -> String {
    let path = Path::new(value);
    if path.is_file() {
        if let Ok(text) = std::fs::read_to_string(path) {
            return py_strip(&text).to_owned();
        }
    }
    py_strip(value).to_owned()
}

/// `file:/absolute/path` for a secret file, `literal:value` (or a plain value) inline.
pub fn read_secret(value: Option<&str>) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    if let Some(path) = value.strip_prefix("file:") {
        let text = std::fs::read_to_string(path).map_err(|e| os_error(&e, path))?;
        return Ok(Some(py_strip(&text).to_owned()));
    }
    Ok(Some(
        py_strip(value.strip_prefix("literal:").unwrap_or(value)).to_owned(),
    ))
}

/// Token to stdout (pipeable), status to stderr — or the token to a private file.
fn emit_token(token: &str, out: Option<&str>, verb: &str) -> Outcome {
    let verb = paint(verb, "32", Stream::Stderr);
    match out.filter(|o| !o.is_empty()) {
        Some(out) => {
            storage::write_secure(out, format!("{token}\n").as_bytes())?;
            status(&format!("{verb} token -> {out}"));
        }
        None => {
            status(&format!("{verb} token:"));
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "{token}");
            let _ = stdout.flush();
        }
    }
    Ok(())
}

/// Host, port and the validated (certificate, key) pair of a listening socket.
type Listening = (String, u16, Option<(PathBuf, PathBuf)>);

/// `[host]:port` and the validated TLS pair, with the cleartext guard applied.
fn listening(
    listen: &str,
    tls_cert: Option<&Path>,
    tls_key: Option<&Path>,
    insecure_http: bool,
    what: &str,
) -> Result<Listening, Exit> {
    let (host, port) = net::parse_listen(listen)?;
    let tls = net::tls_pair(tls_cert, tls_key, what)?
        .map(|(cert, key)| (cert.to_path_buf(), key.to_path_buf()));
    net::guard_cleartext_bind(&host, tls.is_some(), insecure_http, what)?;
    Ok((host, port, tls))
}

fn runtime() -> Result<tokio::runtime::Runtime, Exit> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .or_else(|e| fail(format!("cannot start runtime: {e}")))
}

// --------------------------------------------------------------------------- //
// commands
// --------------------------------------------------------------------------- //

fn keygen(out: &str, key_type: &str, passphrase: Option<&str>) -> Outcome {
    if !["authority", "agent", "audit"].contains(&key_type) {
        return fail("--type must be 'authority', 'agent' or 'audit'");
    }
    let kp = keys::generate_keypair();
    let (key_path, pub_path) = (format!("{out}.key"), format!("{out}.pub"));
    if Path::new(&key_path).exists() || Path::new(&pub_path).exists() {
        return fail("key files already exist; choose another --out for an explicit rotation");
    }
    keys::save_private_key(&key_path, &kp.private_str, passphrase)?;
    keys::save_public_key(&pub_path, &kp.public_str)?;
    let encrypted = if passphrase.is_some_and(|p| !p.is_empty()) {
        ", encrypted"
    } else {
        ""
    };
    print!(
        "{}",
        panel(
            "keygen",
            &[
                format!("{key_type} keypair generated"),
                format!("private : {key_path} (0600{encrypted})"),
                format!("public  : {pub_path}"),
                format!("pubkey  : {}", kp.public_str),
            ],
        )
    );
    Ok(())
}

fn inspect(token: &str) -> Outcome {
    let token_b64 = read_token_arg(token);
    let result = ops::inspect(&token_b64)
        .or_else(|e| fail(format!("cannot inspect token: {}", e.message)))?;
    let joined = |name: &str, missing: &str| -> String {
        match result.fact(name) {
            Some(values) => values
                .iter()
                .map(|t| t.display())
                .collect::<Vec<_>>()
                .join(", "),
            None => missing.to_owned(),
        }
    };
    let rows = grid(&[
        ("blocks", result.block_count.to_string()),
        (
            "root_key_id",
            result
                .root_key_id
                .map_or_else(|| "None".to_owned(), |id| id.to_string()),
        ),
        ("agent_id", joined("agent_id", "-")),
        ("required_profile", joined("required_profile", "-")),
        ("agent_pubkey", joined("agent_pubkey", "-")),
        ("audience", joined("audience", "- (refused: mandatory)")),
        ("revocation_ids", result.revocation_ids.len().to_string()),
    ]);
    let mut out = panel("biscuit inspect", &rows);
    for (i, source) in result.blocks.iter().enumerate() {
        let role = if i == 0 { "authority" } else { "attenuation" };
        let source = py_strip(source);
        let lines: Vec<String> = if source.is_empty() {
            vec!["(empty)".to_owned()]
        } else {
            source.lines().map(str::to_owned).collect()
        };
        out.push_str(&panel(&format!("block {i} · {role}"), &lines));
    }
    print!("{out}");
    Ok(())
}

fn serve(args: &ServeArgs) -> Outcome {
    // The listening guards run here, before anything is loaded, with the messages the
    // former CLI printed; the runtime owns everything else.
    listening(
        &args.listen,
        args.tls_cert.as_deref(),
        args.tls_key.as_deref(),
        args.insecure_http,
        "serve",
    )?;
    let options = args.options();
    let runtime = runtime()?;
    runtime
        .block_on(tokencrumb_mcp_proxy::proxy::runtime::serve(options))
        .or_else(|e| fail(format!("cannot start proxy: {e:#}")))
}

fn audit_verify(log: &str, public: &str, previous: &[String]) -> Outcome {
    let path = Path::new(public);
    let public = if path.is_file() {
        load_public(public).map_err(Exit::Fail)?
    } else {
        public.to_owned()
    };
    let verified = (|| -> tokencrumb_mcp_proxy::Result<audit::VerifyResult> {
        let mut publics = vec![public.clone()];
        for file in previous {
            publics.push(keys::load_public_key(file)?);
        }
        let trusted = audit::trusted_from(&publics)?;
        audit::verify_log(Path::new(log), &trusted)
    })();
    let result = match verified {
        Ok(result) => result,
        Err(e) if e.is(ErrorKind::NotFound) => return fail(format!("audit log not found: {log}")),
        Err(e) => return fail(format!("cannot verify audit log: {}", e.message)),
    };
    let rows = grid(&[
        ("log", log.to_owned()),
        ("entries", result.entries.to_string()),
        ("key_id", keys::key_id(&public)?),
        ("head", result.head.clone()),
    ]);
    print!("{}", panel("audit-verify", &rows));
    if result.ok {
        say(&format!(
            "{} — hashes, signatures and links all verify",
            paint("chain intact", "1;32", Stream::Stdout)
        ));
        return Ok(());
    }
    for (line, reason) in &result.failures {
        status(&format!(
            "{} {reason}",
            paint(&format!("line {line}:"), "1;31", Stream::Stderr)
        ));
    }
    Err(Exit::Code(1))
}

fn audit_head(
    log: &str,
    key: &str,
    gateway_id: Option<&str>,
    previous: &[String],
    passphrase: Option<&str>,
    out: Option<&str>,
) -> Outcome {
    let private = load_private(key, passphrase)
        .or_else(|e| fail(format!("cannot load audit private key: {e}")))?;
    let attestation = (|| -> tokencrumb_mcp_proxy::Result<Value> {
        let mut publics = Vec::new();
        for file in previous {
            publics.push(keys::load_public_key(file)?);
        }
        audit::head_attestation(
            Path::new(log),
            &private,
            gateway_id,
            audit::trusted_from(&publics)?,
        )
    })();
    let attestation = match attestation {
        Ok(attestation) => attestation,
        Err(e) if e.is(ErrorKind::NotFound) => return fail(format!("audit log not found: {log}")),
        Err(e) => return fail(e.message),
    };
    let payload = dumps_indent(&sort_keys(&attestation), 2);
    match out.filter(|o| !o.is_empty()) {
        Some(out) => {
            std::fs::write(out, format!("{payload}\n"))
                .map_err(|e| Exit::Fail(os_error(&e, out)))?;
            say(&format!(
                "{} -> {out}  (seq {})",
                paint("head attestation", "32", Stream::Stdout),
                dumps(&attestation["seq"])
            ));
        }
        None => say(&payload),
    }
    Ok(())
}

fn registry_serve(
    signing_key: &str,
    listen: &str,
    store: &str,
    write_token: &str,
    tls_cert: Option<&Path>,
    tls_key: Option<&Path>,
    insecure_http: bool,
) -> Outcome {
    let (host, port, tls) = listening(listen, tls_cert, tls_key, insecure_http, "registry-serve")?;
    let scheme = if tls.is_some() { "https" } else { "http" };
    let token = read_secret(Some(write_token)).map_err(Exit::Fail)?;
    let private = load_private(signing_key, None).map_err(Exit::Fail)?;
    let app = registry::create_registry_app(store, token.as_deref(), Some(&private))?;
    status(&format!(
        "{} on {scheme}://{host}:{port}  (store={store})",
        paint("registry", "1;32", Stream::Stderr)
    ));
    let runtime = runtime()?;
    runtime.block_on(registry::serve_registry(app, &host, port, tls))?;
    Ok(())
}

fn registry_add(
    agent_id: &str,
    pubkey: &str,
    registry_url: Option<&str>,
    token: Option<&str>,
    store: Option<&str>,
    owner_ref: Option<&str>,
) -> Outcome {
    if let Some(url) = registry_url.filter(|u| !u.is_empty()) {
        let secret = read_secret(token).map_err(Exit::Fail)?;
        let Some(secret) = secret.filter(|s| !s.is_empty()) else {
            return fail("--token is required to write to a registry");
        };
        let mut body = Map::new();
        body.insert("agent_id".into(), json!(agent_id));
        body.insert("agent_pubkey".into(), json!(pubkey));
        if let Some(owner) = owner_ref {
            body.insert("owner_ref".into(), json!(owner));
        }
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(10))
            .redirects(0)
            .build();
        let response = agent
            .post(&format!("{}/agents", url.trim_end_matches('/')))
            .set("authorization", &format!("Bearer {secret}"))
            .set("content-type", "application/json")
            .send_bytes(&serde_json::to_vec(&Value::Object(body)).unwrap_or_default());
        let (code, text) = match response {
            Ok(r) => (r.status(), r.into_string().unwrap_or_default()),
            Err(ureq::Error::Status(code, r)) => (code, r.into_string().unwrap_or_default()),
            Err(e) => return fail(e.to_string()),
        };
        if code >= 300 {
            return fail(format!("registry rejected: {code} {text}"));
        }
        say(&format!(
            "{} {agent_id} -> {url}",
            paint("registered", "32", Stream::Stdout)
        ));
        return Ok(());
    }
    if let Some(store) = store.filter(|s| !s.is_empty()) {
        let mut record = Map::new();
        record.insert("agent_pubkey".into(), json!(pubkey));
        if let Some(owner) = owner_ref {
            record.insert("owner_ref".into(), json!(owner));
        }
        registry::Store::new(store).put(agent_id, record, false)?;
        say(&format!(
            "{} {agent_id} -> {store}",
            paint("registered", "32", Stream::Stdout)
        ));
        return Ok(());
    }
    fail("provide --registry URL or --store path")
}

fn revoke(
    key: &str,
    out: &str,
    add: Option<&str>,
    authority_pub: Option<&str>,
    from_token: Option<&str>,
    passphrase: Option<&str>,
) -> Outcome {
    let private = load_private(key, passphrase).map_err(Exit::Fail)?;
    let mut additions = Vec::new();
    if let Some(from_token) = from_token.filter(|t| !t.is_empty()) {
        let raw = read_token_arg(from_token);
        let public = match authority_pub.filter(|p| !p.is_empty()) {
            Some(path) => load_public(path).map_err(Exit::Fail)?,
            None => keys::public_from_private(&private)?,
        };
        // Only a mandate this authority really signed is revoked by its family id.
        biscuit_auth::Biscuit::from_base64(&raw, keys::biscuit_public(&public)?)
            .map_err(tokencrumb_mcp_proxy::Error::from)?;
        additions.push(ops::capability_key(&raw)?);
    }
    if let Some(add) = add.filter(|a| !a.is_empty()) {
        additions.push(add.to_owned());
    }
    let doc = revocation::update_revocation_list(out, &private, &additions)?;
    let count = doc["revoked"].as_array().map_or(0, Vec::len);
    say(&format!(
        "{} {out} now has {count} id(s)",
        paint("revocation list", "32", Stream::Stdout)
    ));
    Ok(())
}

fn policy_install(source: &str, destination: &str) -> Outcome {
    let raw = std::fs::read(source).map_err(|e| Exit::Fail(os_error(&e, source)))?;
    let text = String::from_utf8(raw.clone()).or_else(|e| fail(e.to_string()))?;
    tokencrumb_mcp_proxy::policy::parse_policy_text(&text)?;
    storage::write_secure(destination, &raw)?;
    say(&format!(
        "{} {destination}",
        paint("policy published", "32", Stream::Stdout)
    ));
    Ok(())
}

fn revocation_migrate(source: &str, destination: &str, old_pub: &str, key: &str) -> Outcome {
    if Path::new(destination).exists()
        || storage::absolute(Path::new(source)) == storage::absolute(Path::new(destination))
    {
        return fail("migration destination must be a new path");
    }
    let migrated = (|| -> Result<(), String> {
        let raw = std::fs::read(source).map_err(|e| os_error(&e, source))?;
        let document = strict_json(raw).map_err(|e| e.message)?;
        let old_public = load_public(old_pub)?;
        let private = load_private(key, None)?;
        let fresh = revocation::migrate_legacy_list(&document, &old_public, &private)
            .map_err(|e| e.message)?;
        storage::atomic_json(destination, &fresh).map_err(|e| e.message)
    })();
    // Never publish an unauthenticated list.
    migrated.or_else(|e| fail(format!("revocation migration refused: {e}")))?;
    say(&format!(
        "{} {destination}",
        paint("revocations migrated", "32", Stream::Stdout)
    ));
    Ok(())
}

fn bootstrap(
    url: Option<&str>,
    authority_pub: Option<&str>,
    response: Option<&str>,
    out: Option<&str>,
) -> Outcome {
    if let Some(url) = url.filter(|u| !u.is_empty()) {
        tokencrumb_mcp_proxy::bootstrap::validate_issuer_url(url)?;
    }
    if let Some(response) = response.filter(|r| !r.is_empty()) {
        let Some(authority_pub) = authority_pub else {
            return fail("--authority-pub is required with --response");
        };
        let Some(out) = out else {
            return fail("--out is required with --response");
        };
        let raw = std::fs::read(response).map_err(|e| Exit::Fail(os_error(&e, response)))?;
        let public = load_public(authority_pub).map_err(Exit::Fail)?;
        let token = tokencrumb_mcp_proxy::bootstrap::accept_exchange(&raw, &public)?;
        storage::write_secure(out, format!("{token}\n").as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Port of `test_cli_wires_security_options_into_runtime`: every security option
    /// reaches the runtime configuration unchanged.
    #[test]
    fn cli_wires_security_options_into_runtime() {
        let cli = Cli::try_parse_from([
            "tokencrumb",
            "serve",
            "--policy",
            "policy.yaml",
            "--authority-pub",
            "authority.pub",
            "--audience",
            "gw",
            "--upstream",
            "https://up/mcp",
            "--listen",
            "[::1]:9443",
            "--previous-authority",
            "old.pub",
            "--previous-audit-pub",
            "audit-old.pub",
            "--upstream-user-credentials",
            "users.json",
            "--registry",
            "https://registry",
            "--registry-pub",
            "registry.pub",
            "--allowed-origin",
            "https://console",
        ])
        .unwrap();
        let Command::Serve(args) = cli.command else {
            panic!("serve expected");
        };
        let options = args.options();
        assert_eq!(options.previous_authority, [PathBuf::from("old.pub")]);
        assert_eq!(options.previous_audit_pub, [PathBuf::from("audit-old.pub")]);
        assert_eq!(
            options.upstream_user_credentials,
            Some(PathBuf::from("users.json"))
        );
        assert_eq!(options.registry_pub, Some(PathBuf::from("registry.pub")));
        assert_eq!(options.registry.as_deref(), Some("https://registry"));
        assert_eq!(options.allowed_origin, ["https://console"]);
        assert_eq!(options.listen, "[::1]:9443");
        assert_eq!(options.audit, PathBuf::from("audit.log"));
        assert_eq!(options.freshness, 60);
        assert!(!options.insecure_http && !options.reload_policy);
    }

    #[test]
    fn serve_defaults_match_the_former_cli() {
        let cli = Cli::try_parse_from([
            "tokencrumb",
            "serve",
            "--policy",
            "p",
            "--authority-pub",
            "a",
            "--audience",
            "gw",
        ])
        .unwrap();
        let Command::Serve(args) = cli.command else {
            panic!("serve expected");
        };
        let options = args.options();
        assert_eq!(options.listen, ":9443");
        assert!(options.upstream.is_none() && options.upstream_header.is_empty());
    }

    #[test]
    fn secrets_and_token_arguments() {
        assert_eq!(
            read_secret(Some("literal: x ")).unwrap().as_deref(),
            Some("x")
        );
        assert_eq!(
            read_secret(Some(" plain ")).unwrap().as_deref(),
            Some("plain")
        );
        assert!(read_secret(Some("file:/nonexistent/secret")).is_err());
        let long = "E".repeat(400);
        assert_eq!(read_token_arg(&format!(" {long}\n")), long);
    }

    #[test]
    fn os_errors_read_like_python() {
        let error = std::fs::File::open("/nonexistent/x").unwrap_err();
        assert_eq!(
            os_error(&error, "/nonexistent/x"),
            "[Errno 2] No such file or directory: '/nonexistent/x'"
        );
    }
}
