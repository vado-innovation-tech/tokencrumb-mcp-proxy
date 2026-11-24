//! `code-mode`: one stdio MCP entry for every gateway service (ADR 0007, client side).
//!
//! stdout carries the MCP channel and nothing else; every status line goes to stderr.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use serde_json::{Value, json};
use tokencrumb_mcp_proxy::approval::ApprovalDir;
use tokencrumb_mcp_proxy::biscuit_ops as ops;
use tokencrumb_mcp_proxy::client_transport::{ClientTransport, http_agent};
use tokencrumb_mcp_proxy::codemode::sandbox::Limits;
use tokencrumb_mcp_proxy::codemode::{Server, Service};
use tokencrumb_mcp_proxy::json::dumps;
use tokencrumb_mcp_proxy::validation::py_strip;

use super::render::{Stream, paint};
use super::wrap::{Line, TokenFile, read_line};
use super::{Exit, Outcome, fail, load_private, read_token_arg, status};

pub struct Options<'a> {
    pub services: &'a [String],
    pub token: &'a str,
    pub agent_key: Option<&'a str>,
    pub agent_id: Option<&'a str>,
    pub passphrase: Option<&'a str>,
    pub ca: Option<&'a str>,
    pub approval_dir: Option<&'a str>,
    pub max_calls: usize,
    pub timeout_seconds: u64,
    pub max_output: usize,
}

/// `name=url` pairs; names must be distinct identifiers.
fn parse_services(specs: &[String]) -> Result<Vec<(String, String)>, Exit> {
    let mut out: Vec<(String, String)> = Vec::new();
    for spec in specs {
        let Some((name, url)) = spec.split_once('=') else {
            return fail(format!("--service must be name=url, got {spec:?}"));
        };
        let valid = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if !valid {
            return fail(format!("invalid service name {name:?}"));
        }
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return fail(format!("service {name}: the URL must be http(s)"));
        }
        if out.iter().any(|(n, _)| n == name) {
            return fail(format!("service {name} given twice"));
        }
        out.push((name.to_owned(), url.to_owned()));
    }
    if out.is_empty() {
        return fail("at least one --service is required");
    }
    Ok(out)
}

pub fn code_mode(options: Options<'_>) -> Outcome {
    let services = parse_services(options.services)?;
    if options.max_calls == 0 || options.timeout_seconds == 0 || options.max_output < 200 {
        return fail("limits must be positive (and --max-output at least 200)");
    }
    let token_b64 = read_token_arg(options.token);
    let private = match options.agent_key.filter(|k| !k.is_empty()) {
        Some(path) => Some(load_private(path, options.passphrase).map_err(Exit::Fail)?),
        None => None,
    };
    let agent_id_given = options.agent_id.is_some_and(|a| !a.is_empty());
    let agent_id = match options.agent_id.filter(|a| !a.is_empty()) {
        Some(id) => id.to_owned(),
        None => ops::authority_agent_id(&token_b64)?
            .map(|term| term.display())
            .filter(|id| !id.is_empty())
            .unwrap_or_else(|| "agent".to_owned()),
    };
    let ca_path = options.ca.filter(|c| !c.is_empty()).map(Path::new);
    if let Some(path) = ca_path
        && !path.is_file()
    {
        status(&format!(
            "{} CA bundle not found: {}",
            paint("code-mode:", "31", Stream::Stderr),
            path.display()
        ));
        return Err(Exit::Code(2));
    }
    let agent = match http_agent(ca_path) {
        Ok(agent) => agent,
        Err(e) => return fail(e.message),
    };
    let approvals = options.approval_dir.filter(|d| !d.is_empty());
    let mut list = Vec::new();
    for (name, url) in &services {
        let mut bridge = ClientTransport::new(
            agent.clone(),
            url.clone(),
            token_b64.clone(),
            agent_id.clone(),
            private.clone(),
        );
        if let Some(dir) = approvals {
            match ApprovalDir::open(dir) {
                Ok(dir) => bridge.approvals = Some(dir),
                Err(e) => return fail(format!("cannot open approval directory: {}", e.message)),
            }
        }
        list.push(Service::new(name.clone(), bridge));
    }
    let limits = Limits {
        max_calls: options.max_calls,
        timeout: Duration::from_secs(options.timeout_seconds),
        max_output: options.max_output,
        ..Limits::default()
    };
    status(&format!(
        "{} {} service(s): {}  (agent={agent_id}, signing={}, limits={} calls/{} s)",
        paint("code-mode", "32", Stream::Stderr),
        services.len(),
        services
            .iter()
            .map(|(n, _)| n.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        if private.is_some() { "on" } else { "off" },
        limits.max_calls,
        limits.timeout.as_secs(),
    ));
    let mut server = Server::new(list, limits);
    let mut watched = TokenFile::watch(options.token);
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let stdout = std::io::stdout();
    loop {
        let line = read_line(&mut input).or_else(|e| fail(e.to_string()))?;
        let reply: Option<Value> = match line {
            Line::Eof => break,
            Line::TooLarge => Some(json!({"jsonrpc": "2.0", "id": null,
                "error": {"code": -32600, "message": "request too large"}})),
            Line::Undecodable => Some(json!({"jsonrpc": "2.0", "id": null,
                "error": {"code": -32700, "message": "parse error"}})),
            Line::Text(text) if py_strip(&text).is_empty() => continue,
            Line::Text(text) => {
                if let Some(token_b64) = watched.as_mut().and_then(TokenFile::changed) {
                    let id = (!agent_id_given)
                        .then(|| ops::authority_agent_id(&token_b64).ok().flatten())
                        .flatten()
                        .map(|t| t.display());
                    if server.rotate_token(&token_b64, id.as_deref()) {
                        status(&format!(
                            "{} mandate reloaded from {}",
                            paint("code-mode", "32", Stream::Stderr),
                            options.token
                        ));
                    }
                }
                server.handle(&text)
            }
        };
        if let Some(reply) = reply {
            let mut out = stdout.lock();
            if writeln!(out, "{}", dumps(&reply))
                .and_then(|_| out.flush())
                .is_err()
            {
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn specs(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn services_are_name_url_pairs() {
        let parsed = parse_services(&specs(&[
            "kdrive=https://gw/mcp/kdrive",
            "github=http://127.0.0.1:9/mcp/github",
        ]))
        .ok()
        .unwrap();
        assert_eq!(parsed[0], ("kdrive".into(), "https://gw/mcp/kdrive".into()));
        for bad in [
            &["nourl"][..],
            &["a b=https://x"],
            &["a=ftp://x"],
            &["a=https://x", "a=https://y"],
            &[],
        ] {
            assert!(parse_services(&specs(bad)).is_err(), "{bad:?}");
        }
    }
}
