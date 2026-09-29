//! Wire and run the proxy from `serve` parameters (shared by the CLI and tests).

use std::path::PathBuf;

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

/// Run `tokencrumb serve` until interrupted. Refusals to start are returned as errors
/// whose message the CLI prints after `error: cannot start proxy: `.
pub async fn serve(options: ServeOptions) -> anyhow::Result<()> {
    let _ = options;
    anyhow::bail!("proxy runtime not wired yet")
}
