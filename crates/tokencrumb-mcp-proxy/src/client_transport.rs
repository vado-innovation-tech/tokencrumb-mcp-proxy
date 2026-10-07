//! Bounded stdio JSON-RPC to Streamable HTTP adapter (client requests only).
//!
//! `client-wrap` holds the mandate and the agent key on the agent's side: each line an
//! MCP client writes on stdin becomes one POST to the proxy, with the mandate in
//! `Authorization` and, for `tools/call`, a fresh per-call attestation. Every response
//! must be complete, bounded, uncompressed and paired with the request it answers;
//! anything else becomes a generic JSON-RPC error. There is no automatic retry: a
//! timed-out tool may already have executed.

use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use crate::attestation::build_attestation;
use crate::error::{Error, Result};
use crate::json::{as_float, as_integer, dumps, strict_json};
use crate::proxy::messages::{INTERNAL_ERROR, response_messages};

/// Largest request line accepted from the client.
pub const MAX_REQUEST: usize = 1024 * 1024;
/// Largest response body accepted from the proxy.
pub const MAX_RESPONSE: usize = 4 * 1024 * 1024;
/// The MCP revision this bridge speaks (and requires the proxy to negotiate).
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// The HTTP client for the bridge: 30 s timeouts, no redirects, no proxy taken from
/// the environment, and certificate verification always on.
///
/// A proxy behind a private PKI (an OpenShift Route reencrypted by the cluster CA, an
/// internal issuer) presents a certificate no public bundle chains to. `ca` then
/// becomes the ONLY trust anchor — the alternative, disabling verification, is not
/// offered: that would normalize "TLS, but unverified".
pub fn http_agent(ca: Option<&Path>) -> Result<ureq::Agent> {
    let mut builder = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(30))
        .timeout_read(Duration::from_secs(30))
        .timeout_write(Duration::from_secs(30))
        .redirects(0);
    if let Some(ca) = ca {
        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject as _;
        let mut roots = rustls::RootCertStore::empty();
        let certificates = CertificateDer::pem_file_iter(ca)
            .map_err(|e| Error::io(format!("cannot read CA bundle: {e}")))?;
        for certificate in certificates {
            let certificate =
                certificate.map_err(|e| Error::io(format!("cannot read CA bundle: {e}")))?;
            roots
                .add(certificate)
                .map_err(|e| Error::value(format!("invalid CA certificate: {e}")))?;
        }
        if roots.is_empty() {
            return Err(Error::value("CA bundle holds no certificate"));
        }
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::value(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        builder = builder.tls_config(Arc::new(config));
    }
    Ok(builder.build())
}

/// Python `==` between a request id (str or int) and a response id.
fn same_id(response: Option<&Value>, request: &Value) -> bool {
    let Some(response) = response else {
        return request.is_null();
    };
    match (request, response) {
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Number(a), other) => {
            let wanted = as_integer(request)
                .map(|i| i as f64)
                .or_else(|| as_float(a));
            let got = match other {
                Value::Number(n) => as_integer(other).map(|i| i as f64).or_else(|| as_float(n)),
                Value::Bool(b) => Some(f64::from(u8::from(*b))),
                _ => None,
            };
            match (as_integer(request), as_integer(other)) {
                (Some(x), Some(y)) => x == y,
                _ => wanted.is_some() && wanted == got,
            }
        }
        (a, b) => a == b,
    }
}

pub struct ClientTransport {
    agent: ureq::Agent,
    pub url: String,
    token: String,
    pub agent_id: String,
    private: Option<String>,
    /// `MCP-Session-Id` negotiated at `initialize`; dropped when the proxy answers 404.
    pub session: Option<String>,
    pub version: String,
    /// The client's own `initialize` and `notifications/initialized`, kept to reopen a
    /// session when the mandate changes under a running client.
    handshake: Vec<String>,
}

impl ClientTransport {
    pub fn new(
        agent: ureq::Agent,
        url: impl Into<String>,
        token: impl Into<String>,
        agent_id: impl Into<String>,
        private: Option<String>,
    ) -> Self {
        Self {
            agent,
            url: url.into(),
            token: token.into(),
            agent_id: agent_id.into(),
            private,
            session: None,
            version: PROTOCOL_VERSION.into(),
            handshake: Vec::new(),
        }
    }

    /// Present `token` from now on. The proxy binds a session to the mandate that opened
    /// it, so a different mandate drops the session and replays the client's handshake
    /// under the new one; the client sees nothing. Returns false when nothing changed.
    pub fn rotate_token(&mut self, token: &str) -> bool {
        if token == self.token {
            return false;
        }
        self.token = token.to_owned();
        self.session = None;
        for raw in self.handshake.clone() {
            // A failed replay leaves no session: the next request reports it, generically.
            let _ = self.relay(&raw, &mut Value::Null, &mut true);
        }
        true
    }

    /// Relay one client line; `None` for a notification (nothing to write back).
    pub fn exchange(&mut self, raw: &str) -> Option<Value> {
        let mut request_id = Value::Null;
        let mut has_id = true;
        match self.relay(raw, &mut request_id, &mut has_id) {
            Ok(result) => result,
            // Untrusted boundary: any failure refuses the operation, generically.
            Err(_) if has_id => Some(json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": INTERNAL_ERROR, "message": "transport or request error"},
            })),
            Err(_) => None,
        }
    }

    fn relay(
        &mut self,
        raw: &str,
        request_id: &mut Value,
        has_id: &mut bool,
    ) -> Result<Option<Value>> {
        if raw.len() > MAX_REQUEST {
            return Err(Error::value("request too large"));
        }
        let message = strict_json(raw.as_bytes())?;
        let method = match message.as_object() {
            Some(map) if map.get("jsonrpc").and_then(Value::as_str) == Some("2.0") => {
                match map.get("method") {
                    Some(Value::String(m)) => m.clone(),
                    _ => return Err(Error::value("invalid JSON-RPC message")),
                }
            }
            _ => return Err(Error::value("invalid JSON-RPC message")),
        };
        let map = message.as_object().expect("checked above");
        *has_id = map.contains_key("id");
        *request_id = map.get("id").cloned().unwrap_or(Value::Null);
        if *has_id && !(request_id.is_string() || crate::validation::is_int(request_id)) {
            return Err(Error::value("invalid request id"));
        }
        let empty = Value::Object(Default::default());
        let params = map.get("params").unwrap_or(&empty);
        let Value::Object(params) = params else {
            return Err(Error::value("params must be an object"));
        };

        let mut request = self
            .agent
            .post(&self.url)
            .set("Authorization", &format!("Biscuit {}", self.token))
            .set("Content-Type", "application/json")
            .set("Accept", "application/json, text/event-stream")
            .set("Accept-Encoding", "identity")
            .set("MCP-Protocol-Version", &self.version);
        if let Some(session) = &self.session {
            request = request.set("MCP-Session-Id", session);
        }
        if method == "tools/call"
            && let Some(private) = &self.private
        {
            let arguments = params.get("arguments").unwrap_or(&empty);
            let (Value::Object(_), Some(Value::String(tool))) = (arguments, params.get("name"))
            else {
                return Err(Error::value("invalid tool arguments"));
            };
            let header =
                build_attestation(&self.agent_id, tool, arguments, &self.token, private, None)?;
            request = request.set("Agent-Attestation", &header);
        }

        let response = match request.send_bytes(dumps(&message).as_bytes()) {
            Ok(response) => response,
            Err(ureq::Error::Status(status, _)) => {
                if status == 404 {
                    self.session = None;
                }
                return Err(Error::io(format!("proxy status {status}")));
            }
            Err(e) => return Err(Error::io(e.to_string())),
        };
        let status = response.status();
        if !(200..300).contains(&status) {
            return Err(Error::io(format!("proxy status {status}")));
        }
        let encoding = response.header("content-encoding").unwrap_or("identity");
        if !encoding.eq_ignore_ascii_case("identity") {
            return Err(Error::value("compressed responses are not supported"));
        }
        let content_type = response.header("content-type").map(str::to_owned);
        let session = response.header("mcp-session-id").map(str::to_owned);
        let mut content = Vec::new();
        response
            .into_reader()
            .take(MAX_RESPONSE as u64 + 1)
            .read_to_end(&mut content)?;
        if content.len() > MAX_RESPONSE {
            return Err(Error::value("response too large"));
        }
        let (messages, _) = response_messages(status, content_type.as_deref(), &content)?;
        if !*has_id {
            if !messages.is_empty() {
                return Err(Error::value("notification returned an unsolicited message"));
            }
            if method == "notifications/initialized" && self.handshake.len() == 1 {
                self.handshake.push(raw.to_owned());
            }
            return Ok(None);
        }
        if messages.len() != 1 || !same_id(messages[0].get("id"), request_id) {
            return Err(Error::value("response is not paired to request"));
        }
        let result = messages.into_iter().next().expect("one message");
        if method == "initialize"
            && let Some(outcome) = result.get("result")
        {
            let Value::Object(outcome) = outcome else {
                return Err(Error::value("malformed initialize result"));
            };
            let version = outcome
                .get("protocolVersion")
                .cloned()
                .unwrap_or_else(|| Value::String(self.version.clone()));
            if version.as_str() != Some(self.version.as_str()) {
                return Err(Error::value("unsupported negotiated MCP version"));
            }
            self.session = session;
            self.handshake = vec![raw.to_owned()];
        }
        Ok(Some(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_compare_like_python() {
        assert!(same_id(Some(&json!(1)), &json!(1)));
        assert!(same_id(Some(&strict_json("1.0").unwrap()), &json!(1)));
        assert!(same_id(Some(&json!(true)), &json!(1)));
        assert!(!same_id(Some(&json!("1")), &json!(1)));
        assert!(same_id(Some(&json!("a")), &json!("a")));
        assert!(!same_id(None, &json!("a")));
    }
}
