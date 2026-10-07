//! `client-wrap`: the per-call attestation shim between a stdio MCP client and the
//! HTTP proxy (profiles 3a/3b).
//!
//! stdout carries the MCP channel and nothing else; every status line goes to stderr.

use std::io::{BufRead, Write};
use std::path::Path;

use serde_json::{Value, json};
use tokencrumb_mcp_proxy::biscuit_ops as ops;
use tokencrumb_mcp_proxy::client_transport::{ClientTransport, MAX_REQUEST, http_agent};
use tokencrumb_mcp_proxy::json::dumps;
use tokencrumb_mcp_proxy::validation::py_strip;

use super::render::{Stream, paint};
use super::{Exit, Outcome, fail, load_private, read_token_arg, status};

/// One line read from the client.
enum Line {
    Eof,
    /// Longer than [`MAX_REQUEST`] characters; drained without being buffered.
    TooLarge,
    /// Not UTF-8: it cannot be a JSON-RPC message.
    Undecodable,
    Text(String),
}

/// Read one line, never buffering more than a bounded prefix of it.
///
/// The limit counts characters, newline included, as the former implementation did;
/// four bytes per character bound the prefix that has to be held to decide.
fn read_line(input: &mut impl BufRead) -> std::io::Result<Line> {
    let cap = 4 * (MAX_REQUEST + 2);
    let mut buffer: Vec<u8> = Vec::new();
    let mut overflow = false;
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            break;
        }
        let (taken, done) = match available.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (available.len(), false),
        };
        if !overflow {
            if buffer.len() + taken > cap {
                overflow = true;
                buffer.clear();
            } else {
                buffer.extend_from_slice(&available[..taken]);
            }
        }
        input.consume(taken);
        if done {
            break;
        }
    }
    if overflow {
        return Ok(Line::TooLarge);
    }
    if buffer.is_empty() {
        return Ok(Line::Eof);
    }
    match String::from_utf8(buffer) {
        Ok(text) if text.chars().count() > MAX_REQUEST => Ok(Line::TooLarge),
        Ok(text) => Ok(Line::Text(text)),
        Err(_) => Ok(Line::Undecodable),
    }
}

/// The mandate file, watched so a renewed mandate is picked up by a running client
/// (Claude Desktop launches `client-wrap` once and keeps it for the whole session).
struct TokenFile {
    path: std::path::PathBuf,
    stamp: Option<std::time::SystemTime>,
}

impl TokenFile {
    fn watch(token: &str) -> Option<Self> {
        let path = Path::new(token);
        path.is_file().then(|| Self {
            path: path.to_path_buf(),
            stamp: Self::stamp(path),
        })
    }

    fn stamp(path: &Path) -> Option<std::time::SystemTime> {
        std::fs::metadata(path).and_then(|m| m.modified()).ok()
    }

    /// The new mandate when the file changed since the last look.
    fn changed(&mut self) -> Option<String> {
        let stamp = Self::stamp(&self.path);
        if stamp.is_none() || stamp == self.stamp {
            return None;
        }
        self.stamp = stamp;
        let text = std::fs::read_to_string(&self.path).ok()?;
        Some(py_strip(&text).to_owned()).filter(|t| !t.is_empty())
    }
}

pub fn client_wrap(
    proxy: &str,
    token: &str,
    agent_key: Option<&str>,
    agent_id: Option<&str>,
    passphrase: Option<&str>,
    ca: Option<&str>,
) -> Outcome {
    let token_b64 = read_token_arg(token);
    let private = match agent_key.filter(|k| !k.is_empty()) {
        Some(path) => Some(load_private(path, passphrase).map_err(Exit::Fail)?),
        None => None,
    };
    let agent_id_given = agent_id.is_some_and(|a| !a.is_empty());
    let agent_id = match agent_id.filter(|a| !a.is_empty()) {
        Some(id) => id.to_owned(),
        None => ops::authority_agent_id(&token_b64)?
            .map(|term| term.display())
            .filter(|id| !id.is_empty())
            .unwrap_or_else(|| "agent".to_owned()),
    };

    // A proxy behind a private PKI presents a certificate no public bundle chains to.
    // `--ca` names the anchor; disabling verification is never offered.
    let ca_path = ca.filter(|c| !c.is_empty()).map(Path::new);
    if let (Some(ca), Some(path)) = (ca, ca_path)
        && !path.is_file()
    {
        status(&format!(
            "{} CA bundle not found: {ca}",
            paint("client-wrap:", "31", Stream::Stderr)
        ));
        return Err(Exit::Code(2));
    }
    let agent = match http_agent(ca_path) {
        Ok(agent) => agent,
        Err(e) => return fail(e.message),
    };
    let ca_label = ca_path
        .and_then(Path::file_name)
        .map(|name| format!(", ca={}", name.to_string_lossy()))
        .unwrap_or_default();
    status(&format!(
        "{} -> {proxy}  (agent={agent_id}, signing={}{ca_label})",
        paint("client-wrap", "32", Stream::Stderr),
        if private.is_some() { "on" } else { "off" },
    ));

    let mut watched = TokenFile::watch(token);
    let mut bridge = ClientTransport::new(agent, proxy, token_b64, agent_id, private);
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let stdout = std::io::stdout();
    loop {
        let line = read_line(&mut input).or_else(|e| fail(e.to_string()))?;
        let result: Option<Value> = match line {
            Line::Eof => break,
            Line::TooLarge => Some(json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {"code": -32600, "message": "request too large"},
            })),
            Line::Undecodable => Some(json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {"code": -32603, "message": "transport or request error"},
            })),
            Line::Text(text) if py_strip(&text).is_empty() => continue,
            Line::Text(text) => {
                if let Some(token_b64) = watched.as_mut().and_then(TokenFile::changed) {
                    if !agent_id_given && let Ok(Some(id)) = ops::authority_agent_id(&token_b64) {
                        bridge.agent_id = id.display();
                    }
                    if bridge.rotate_token(&token_b64) {
                        status(&format!(
                            "{} mandate reloaded from {token}",
                            paint("client-wrap", "32", Stream::Stderr)
                        ));
                    }
                }
                bridge.exchange(&text)
            }
        };
        if let Some(result) = result {
            let mut out = stdout.lock();
            if writeln!(out, "{}", dumps(&result))
                .and_then(|_| out.flush())
                .is_err()
            {
                // The client went away: nothing left to answer.
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(input: &[u8]) -> Vec<String> {
        let mut reader = std::io::BufReader::with_capacity(7, input);
        let mut out = Vec::new();
        loop {
            match read_line(&mut reader).unwrap() {
                Line::Eof => break,
                Line::TooLarge => out.push("<too large>".to_owned()),
                Line::Undecodable => out.push("<undecodable>".to_owned()),
                Line::Text(t) => out.push(t),
            }
        }
        out
    }

    #[test]
    fn lines_keep_their_newline_and_the_last_one_may_lack_it() {
        assert_eq!(lines(b"ab\n\ncd"), ["ab\n", "\n", "cd"]);
        assert_eq!(lines(b"\xff\n{}\n"), ["<undecodable>", "{}\n"]);
    }

    #[test]
    fn an_oversized_line_is_drained_and_the_next_one_still_read() {
        let mut input = vec![b'x'; MAX_REQUEST + 5];
        input.extend_from_slice(b"\n{\"a\":1}\n");
        assert_eq!(lines(&input), ["<too large>", "{\"a\":1}\n"]);
        // Exactly at the limit (newline included) is still accepted.
        let mut input = vec![b'x'; MAX_REQUEST - 1];
        input.push(b'\n');
        assert_eq!(lines(&input)[0].len(), MAX_REQUEST);
    }
}
