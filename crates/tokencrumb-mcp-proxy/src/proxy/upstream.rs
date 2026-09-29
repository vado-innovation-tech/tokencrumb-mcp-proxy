//! Bounded HTTP/stdio transports with explicit credentials and no ambient cookies.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use futures_util::future::BoxFuture;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

use crate::error::{Error, ErrorKind, Result};
use crate::json::{dumps, strict_json};
use crate::verifier::Headers;

/// Session headers relayed to the upstream as-is.
pub const PROPAGATE: &[&str] = &["mcp-protocol-version", "mcp-session-id", "last-event-id"];
pub const MAX_RESPONSE: usize = 4 * 1024 * 1024;

/// Headers a configured credential may never set.
const RESERVED: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "cookie",
    "mcp-protocol-version",
    "mcp-session-id",
    "last-event-id",
];

/// The verified principal a call runs as: `(issuer, subject)` of its mandate.
pub type Principal = (Option<String>, Option<String>);

/// What the gateway hands to an upstream: the incoming headers, and — only once a
/// mandate has been verified — its principal. Clients cannot set the principal
/// through HTTP: it is not a header.
#[derive(Debug, Clone, Default)]
pub struct ForwardHeaders {
    pub incoming: Headers,
    pub principal: Option<Principal>,
}

/// An upstream reply, fully buffered within the size bound.
#[derive(Debug, Clone)]
pub struct UpstreamResponse {
    pub status: u16,
    /// Lowercase names; `content-encoding`, `content-length` and `set-cookie` removed.
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

impl UpstreamResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

pub trait Upstream: Send + Sync {
    fn forward<'a>(
        &'a self,
        method: &'a str,
        body: Bytes,
        headers: &'a ForwardHeaders,
    ) -> BoxFuture<'a, Result<UpstreamResponse>>;
    fn close(&self) -> BoxFuture<'_, ()>;
    /// True when the upstream expects per-user credentials (so every relayed method,
    /// not only `tools/call`, needs a verified mandate).
    fn requires_user_credentials(&self) -> bool {
        false
    }
    /// The HTTP transport, for configuring per-user credentials at startup.
    fn as_http(&mut self) -> Option<&mut HttpUpstream> {
        None
    }
}

fn timeout_error() -> Error {
    Error::new(ErrorKind::Io, "TimeoutError")
}

pub struct HttpUpstream {
    pub url: String,
    pub timeout: Duration,
    pub max_response: usize,
    headers: Vec<(String, String)>,
    pub requires_user_credentials: bool,
    user_credentials: HashMap<(String, String), Vec<(String, String)>>,
    client: reqwest::Client,
}

fn check_credential(name: &str, value: &str) -> Result<()> {
    if RESERVED.contains(&name.to_ascii_lowercase().as_str()) {
        return Err(Error::value(
            "upstream credential cannot override transport/session headers",
        ));
    }
    if name.contains(['\r', '\n']) || value.contains(['\r', '\n']) {
        return Err(Error::value("invalid upstream credential header"));
    }
    Ok(())
}

impl HttpUpstream {
    pub fn new(url: &str, headers: Vec<(String, String)>) -> Result<Self> {
        let invalid = || {
            Error::value(
                "upstream requires an explicit HTTP URL without embedded credentials/fragment",
            )
        };
        let parsed = url::Url::parse(url).map_err(|_| invalid())?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none_or(str::is_empty)
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(invalid());
        }
        let headers: Vec<(String, String)> = headers
            .into_iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();
        for (name, value) in &headers {
            check_credential(name, value)?;
        }
        crate::net::install_crypto_provider();
        let timeout = Duration::from_secs(30);
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(timeout)
            .build()
            .map_err(|e| Error::io(e.to_string()))?;
        Ok(Self {
            url: url.to_owned(),
            timeout,
            max_response: MAX_RESPONSE,
            headers,
            requires_user_credentials: false,
            user_credentials: HashMap::new(),
            client,
        })
    }

    pub fn has_principal(&self, issuer: &str, subject: &str) -> bool {
        self.user_credentials
            .contains_key(&(issuer.to_owned(), subject.to_owned()))
    }

    /// Attach the credential used for one verified `(issuer, subject)`.
    pub fn add_user_credential(
        &mut self,
        issuer: &str,
        subject: &str,
        header: &str,
        secret: &str,
    ) -> Result<()> {
        check_credential(header, secret)?;
        self.requires_user_credentials = true;
        self.user_credentials.insert(
            (issuer.to_owned(), subject.to_owned()),
            vec![(header.to_ascii_lowercase(), secret.to_owned())],
        );
        Ok(())
    }

    async fn exchange(
        &self,
        method: &str,
        body: Bytes,
        headers: &ForwardHeaders,
    ) -> Result<UpstreamResponse> {
        let mut outgoing: Vec<(String, String)> = vec![
            ("content-type".into(), "application/json".into()),
            (
                "accept".into(),
                "application/json, text/event-stream".into(),
            ),
            ("accept-encoding".into(), "identity".into()),
        ];
        for name in PROPAGATE {
            if let Some(value) = headers.incoming.get(name).filter(|v| !v.is_empty()) {
                outgoing.push(((*name).into(), value.to_owned()));
            }
        }
        let mut set = |name: &str, value: &str| match outgoing.iter_mut().find(|(k, _)| k == name) {
            Some(entry) => entry.1 = value.to_owned(),
            None => outgoing.push((name.to_owned(), value.to_owned())),
        };
        for (name, value) in &self.headers {
            set(name, value);
        }
        if self.requires_user_credentials {
            let credential = headers
                .principal
                .as_ref()
                .and_then(|(issuer, subject)| Some((issuer.clone()?, subject.clone()?)))
                .and_then(|principal| self.user_credentials.get(&principal))
                .ok_or_else(|| {
                    Error::value("no upstream credential for verified issuer/subject")
                })?;
            for (name, value) in credential {
                set(name, value);
            }
        }
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| Error::value(e.to_string()))?;
        let mut request = self.client.request(method, &self.url).body(body);
        for (name, value) in &outgoing {
            request = request.header(name.as_str(), value.as_str());
        }
        let response = request
            .send()
            .await
            .map_err(|e| Error::io(format!("ConnectError: {e}")))?;
        let encoding = response
            .headers()
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("identity")
            .to_ascii_lowercase();
        if encoding != "identity" {
            return Err(Error::value(
                "compressed upstream responses are not supported by the bounded transport",
            ));
        }
        let status = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .filter(|(k, _)| {
                !matches!(
                    k.as_str(),
                    "content-encoding" | "content-length" | "set-cookie"
                )
            })
            .map(|(k, v)| {
                (
                    k.as_str().to_owned(),
                    v.as_bytes().iter().map(|&b| b as char).collect(),
                )
            })
            .collect();
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| Error::io(format!("ReadError: {e}")))?;
            if body.len() + chunk.len() > self.max_response {
                return Err(Error::value("upstream response size limit exceeded"));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(UpstreamResponse {
            status,
            headers,
            body: Bytes::from(body),
        })
    }
}

impl Upstream for HttpUpstream {
    fn forward<'a>(
        &'a self,
        method: &'a str,
        body: Bytes,
        headers: &'a ForwardHeaders,
    ) -> BoxFuture<'a, Result<UpstreamResponse>> {
        Box::pin(async move {
            tokio::time::timeout(self.timeout, self.exchange(method, body, headers))
                .await
                .map_err(|_| timeout_error())?
        })
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }

    fn requires_user_credentials(&self) -> bool {
        self.requires_user_credentials
    }

    fn as_http(&mut self) -> Option<&mut HttpUpstream> {
        Some(self)
    }
}

struct Process {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

struct StdioState {
    process: Option<Process>,
    initialize: Option<Value>,
}

/// Sequential JSON-RPC bridge to a local command; stale responses never survive
/// cancellation (any failure kills the process, the next call respawns it and
/// replays `initialize`).
pub struct StdioUpstream {
    pub command: Vec<String>,
    pub timeout: Duration,
    state: Mutex<StdioState>,
}

const ENVIRONMENT: &[&str] = &["PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT"];

impl StdioUpstream {
    pub fn new(command: Vec<String>) -> Result<Self> {
        if command.is_empty() {
            return Err(Error::value("empty stdio command"));
        }
        Ok(Self {
            command,
            timeout: Duration::from_secs(30),
            state: Mutex::new(StdioState {
                process: None,
                initialize: None,
            }),
        })
    }

    fn spawn(&self) -> Result<Process> {
        let mut command = Command::new(&self.command[0]);
        command
            .args(&self.command[1..])
            .env_clear()
            .envs(std::env::vars().filter(|(k, _)| ENVIRONMENT.contains(&k.as_str())))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = command.spawn()?;
        let stdin = child.stdin.take().ok_or_else(|| Error::io("no stdin"))?;
        let stdout = BufReader::with_capacity(
            64 * 1024,
            child.stdout.take().ok_or_else(|| Error::io("no stdout"))?,
        );
        Ok(Process {
            child,
            stdin,
            stdout,
        })
    }

    async fn exchange(process: &mut Process, message: &Value) -> Result<UpstreamResponse> {
        let mut line = dumps(message).into_bytes();
        line.push(b'\n');
        process.stdin.write_all(&line).await?;
        process.stdin.flush().await?;
        if message.get("id").is_none() {
            return Ok(UpstreamResponse {
                status: 202,
                headers: Vec::new(),
                body: Bytes::new(),
            });
        }
        let mut reply = Vec::new();
        let read = (&mut process.stdout)
            .take(MAX_RESPONSE as u64 + 1)
            .read_until(b'\n', &mut reply)
            .await?;
        if read == 0 || reply.len() > MAX_RESPONSE {
            return Err(Error::value("missing/oversize stdio response"));
        }
        let response = strict_json(&reply)?;
        let paired = response
            .as_object()
            .is_some_and(|map| map.get("id") == message.get("id") && !map.contains_key("method"));
        if !paired {
            return Err(Error::value("unpaired or server-initiated stdio response"));
        }
        Ok(UpstreamResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: Bytes::from(reply),
        })
    }

    async fn call(&self, state: &mut StdioState, message: &Value) -> Result<UpstreamResponse> {
        let alive = match &mut state.process {
            Some(process) => process.child.try_wait()?.is_none(),
            None => false,
        };
        if !alive {
            let mut process = self.spawn()?;
            if let Some(initialize) = state.initialize.clone() {
                Self::exchange(&mut process, &initialize).await?;
                Self::exchange(
                    &mut process,
                    &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                )
                .await?;
            }
            state.process = Some(process);
        }
        let process = state.process.as_mut().expect("spawned");
        let response = Self::exchange(process, message).await?;
        if message.get("method").and_then(Value::as_str) == Some("initialize") {
            state.initialize = Some(message.clone());
        }
        Ok(response)
    }

    async fn abort(state: &mut StdioState) {
        if let Some(mut process) = state.process.take() {
            let _ = process.child.kill().await;
            let _ = process.child.wait().await;
        }
    }
}

use tokio::io::AsyncReadExt as _;

impl Upstream for StdioUpstream {
    fn forward<'a>(
        &'a self,
        method: &'a str,
        body: Bytes,
        _headers: &'a ForwardHeaders,
    ) -> BoxFuture<'a, Result<UpstreamResponse>> {
        Box::pin(async move {
            if method != "POST" {
                return Err(Error::value("stdio supports POST messages only"));
            }
            let message = strict_json(&body)?;
            let mut state = self.state.lock().await;
            let outcome = tokio::time::timeout(self.timeout, self.call(&mut state, &message)).await;
            match outcome {
                Ok(Ok(response)) => Ok(response),
                Ok(Err(e)) => {
                    Self::abort(&mut state).await;
                    Err(e)
                }
                Err(_) => {
                    Self::abort(&mut state).await;
                    Err(timeout_error())
                }
            }
        })
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            Self::abort(&mut state).await;
        })
    }
}

/// An upstream from its spec: an HTTP(S) URL, or a command line run over stdio.
pub fn build_upstream(
    spec: &str,
    headers: Option<Vec<(String, String)>>,
) -> Result<Box<dyn Upstream>> {
    if spec.starts_with("http://") || spec.starts_with("https://") {
        return Ok(Box::new(HttpUpstream::new(
            spec,
            headers.unwrap_or_default(),
        )?));
    }
    if headers.is_some_and(|h| !h.is_empty()) {
        return Err(Error::value("HTTP credentials cannot be used with stdio"));
    }
    let command = shlex::split(spec).ok_or_else(|| Error::value("No closing quotation"))?;
    Ok(Box::new(StdioUpstream::new(command)?))
}

pub type SharedUpstream = Arc<dyn Upstream>;
