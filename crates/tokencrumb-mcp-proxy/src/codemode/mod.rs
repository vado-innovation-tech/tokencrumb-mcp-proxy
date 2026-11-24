//! Code Mode, client side (ADR 0007).
//!
//! One stdio MCP server exposes every configured gateway service through two tools:
//!
//! - `search`: a script filters `codemode.tools()`, the merged catalog with TypeScript
//!   declarations; it cannot call anything;
//! - `execute`: a script calls `codemode.<service>_<tool>(args)`.
//!
//! Every call a script issues is an ordinary `tools/call` to the service's gateway
//! endpoint through [`ClientTransport`]: same mandate, same per-call attestation signed
//! with the agent key, same approval receipts. The gateway's policy, budget, approval
//! and audit apply to each call exactly as they do without Code Mode. The agent key
//! never enters the sandbox.
//!
//! A call the gateway holds for approval stops the script; the model receives the calls
//! already made and the request to approve, and runs the remaining work again once the
//! call is approved.

pub mod catalog;
pub mod sandbox;

use std::cell::RefCell;
use std::rc::Rc;

use serde_json::{Value, json};

use crate::approval::approval_required;
use crate::client_transport::ClientTransport;
use crate::json::{dumps, strict_json};
use crate::proxy::scripts::REGISTER_METHOD;
use catalog::Entry;
use sandbox::{CallOutcome, Caller, Limits, Run};

/// MCP revisions this server answers `initialize` with; the client's choice when known.
const VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const DEFAULT_VERSION: &str = "2025-06-18";
const MAX_LIST_PAGES: usize = 20;

/// One gateway endpoint (`/mcp/<service>`) and the bridge that signs calls to it.
pub struct Service {
    pub name: String,
    pub bridge: ClientTransport,
    ready: bool,
    /// The script run already registered with this service's gateway.
    registered: Option<String>,
}

impl Service {
    pub fn new(name: impl Into<String>, bridge: ClientTransport) -> Self {
        Self {
            name: name.into(),
            bridge,
            ready: false,
            registered: None,
        }
    }
}

struct Services {
    list: Vec<Service>,
    next_id: u64,
    /// The script being run: `(run id, script hash, code)`.
    script: Option<(String, String, String)>,
}

impl Services {
    fn request(&mut self, index: usize, method: &str, params: Value) -> Result<Value, String> {
        self.next_id += 1;
        let message =
            json!({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params});
        let service = &mut self.list[index];
        let reply = service
            .bridge
            .exchange(&dumps(&message))
            .ok_or_else(|| format!("{}: no answer", service.name))?;
        if let Some(error) = reply.get("error") {
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("error");
            return Err(format!("{}: {message}", service.name));
        }
        Ok(reply)
    }

    fn ensure_ready(&mut self, index: usize) -> Result<(), String> {
        if self.list[index].ready {
            return Ok(());
        }
        self.request(
            index,
            "initialize",
            json!({
                "protocolVersion": crate::client_transport::PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "tokencrumb-code-mode", "version": env!("CARGO_PKG_VERSION")},
            }),
        )?;
        let initialized = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        let service = &mut self.list[index];
        let _ = service.bridge.exchange(&dumps(&initialized));
        service.ready = true;
        Ok(())
    }

    fn list_tools(&mut self, index: usize) -> Result<Vec<Entry>, String> {
        self.ensure_ready(index)?;
        let mut tools = Vec::new();
        let mut cursor: Option<Value> = None;
        for _ in 0..MAX_LIST_PAGES {
            let params = match &cursor {
                Some(cursor) => json!({"cursor": cursor}),
                None => json!({}),
            };
            let reply = self.request(index, "tools/list", params)?;
            let result = &reply["result"];
            if let Some(page) = result.get("tools").and_then(Value::as_array) {
                tools.extend(page.iter().cloned());
            }
            match result.get("nextCursor") {
                Some(next) if !next.is_null() => cursor = Some(next.clone()),
                _ => break,
            }
        }
        Ok(catalog::entries(&self.list[index].name, &tools))
    }

    /// Tag every request with the running script, or stop tagging.
    fn set_script(&mut self, script: Option<(String, String, String)>) {
        for service in &mut self.list {
            service.bridge.script = script.as_ref().map(|(r, h, _)| (r.clone(), h.clone()));
        }
        self.script = script;
    }

    /// Put the script's code in the gateway's audit before its first call there. A
    /// gateway that does not know the request refuses it; the calls still carry the
    /// script hash.
    fn register(&mut self, index: usize) {
        let Some((run, hash, code)) = self.script.clone() else {
            return;
        };
        if self.list[index].registered.as_deref() == Some(run.as_str()) {
            return;
        }
        self.list[index].registered = Some(run.clone());
        let _ = self.request(
            index,
            REGISTER_METHOD,
            json!({"run": run, "hash": hash, "code": code}),
        );
    }

    fn call(&mut self, entry: &Entry, arguments: &Value) -> CallOutcome {
        let Some(index) = self.list.iter().position(|s| s.name == entry.service) else {
            return CallOutcome::Error("unknown service".to_owned());
        };
        if let Err(e) = self.ensure_ready(index) {
            return CallOutcome::Error(e);
        }
        self.register(index);
        let reply = match self.request(
            index,
            "tools/call",
            json!({"name": entry.tool, "arguments": arguments}),
        ) {
            Ok(reply) => reply,
            Err(e) => return CallOutcome::Error(e),
        };
        if let Some(mut held) = approval_required(&reply) {
            if let Value::Object(map) = &mut held {
                map.insert("tool".to_owned(), Value::String(entry.name.clone()));
            }
            return CallOutcome::Held(held);
        }
        let result = &reply["result"];
        if result.get("isError") == Some(&json!(true)) {
            return CallOutcome::Error(catalog::error_text(result));
        }
        CallOutcome::Value(catalog::result_value(result))
    }
}

/// The Code Mode MCP server: one JSON-RPC line in, at most one line out.
pub struct Server {
    services: Rc<RefCell<Services>>,
    catalog: Option<Vec<Entry>>,
    pub limits: Limits,
}

impl Server {
    pub fn new(services: Vec<Service>, limits: Limits) -> Self {
        Self {
            services: Rc::new(RefCell::new(Services {
                list: services,
                next_id: 0,
                script: None,
            })),
            catalog: None,
            limits,
        }
    }

    /// Present a renewed mandate to every service from now on.
    pub fn rotate_token(&mut self, token: &str, agent_id: Option<&str>) -> bool {
        let mut changed = false;
        for service in &mut self.services.borrow_mut().list {
            if let Some(id) = agent_id {
                service.bridge.agent_id = id.to_owned();
            }
            changed |= service.bridge.rotate_token(token);
        }
        if changed {
            // A new mandate may grant other tools.
            self.catalog = None;
        }
        changed
    }

    fn service_names(&self) -> Vec<String> {
        self.services
            .borrow()
            .list
            .iter()
            .map(|s| s.name.clone())
            .collect()
    }

    /// The merged catalog, listed once per mandate. A service that cannot be listed is
    /// left out and reported.
    fn catalog(&mut self) -> (Vec<Entry>, Vec<String>) {
        if let Some(entries) = &self.catalog {
            return (entries.clone(), Vec::new());
        }
        let mut entries: Vec<Entry> = Vec::new();
        let mut problems = Vec::new();
        let count = self.services.borrow().list.len();
        for index in 0..count {
            match self.services.borrow_mut().list_tools(index) {
                Ok(found) => {
                    for entry in found {
                        if entries.iter().any(|e| e.name == entry.name) {
                            problems.push(format!("duplicate tool name {} skipped", entry.name));
                        } else {
                            entries.push(entry);
                        }
                    }
                }
                Err(e) => problems.push(e),
            }
        }
        if problems.is_empty() {
            self.catalog = Some(entries.clone());
        }
        (entries, problems)
    }

    /// Handle one line from the client.
    pub fn handle(&mut self, raw: &str) -> Option<Value> {
        let Ok(message) = strict_json(raw.as_bytes()) else {
            return Some(error(Value::Null, -32700, "parse error"));
        };
        let Some(map) = message.as_object() else {
            return Some(error(Value::Null, -32600, "invalid request"));
        };
        let id = map.get("id").cloned();
        let method = map.get("method").and_then(Value::as_str).unwrap_or("");
        let params = map.get("params").cloned().unwrap_or_else(|| json!({}));
        let id = id?; // Notifications need no answer.
        let outcome = match method {
            "initialize" => {
                let asked = params.get("protocolVersion").and_then(Value::as_str);
                let version = asked
                    .filter(|v| VERSIONS.contains(v))
                    .unwrap_or(DEFAULT_VERSION);
                Ok(json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "tokencrumb-code-mode", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": INSTRUCTIONS,
                }))
            }
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": self.tool_definitions()})),
            "tools/call" => self.call_tool(&params),
            _ => Err((-32601, "method not found")),
        };
        Some(match outcome {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err((code, message)) => error(id, code, message),
        })
    }

    fn tool_definitions(&self) -> Value {
        let services = self.service_names().join(", ");
        let code = json!({
            "type": "object",
            "properties": {"code": {"type": "string",
                "description": "A JavaScript async arrow function, e.g. `async () => { ... }`."}},
            "required": ["code"],
            "additionalProperties": false,
        });
        json!([
            {
                "name": "search",
                "description": format!(
                    "Find the tools of the connected services ({services}). The code runs in a \
                     sandbox where `codemode.tools()` returns every tool as {{name, service, \
                     description, inputSchema, typescript}}; filter it and return what you \
                     need, e.g. `async () => codemode.tools().filter(t => \
                     t.service === 'github').map(t => t.typescript)`. No tool can be called here."
                ),
                "inputSchema": code,
                "annotations": {"readOnlyHint": true},
            },
            {
                "name": "execute",
                "description": format!(
                    "Run JavaScript that calls the tools of the connected services ({services}) \
                     as `await codemode.<service>_<tool>(args)`; use `search` first to learn \
                     their names and arguments. Return the value you need: only the return \
                     value and console.log output come back. A failed call throws an \
                     exception you can catch. Each call is authorized and audited by the \
                     gateway; a call that needs a person's approval stops the script. \
                     No network, file system or timers. Limits: {} calls, {} s.",
                    self.limits.max_calls,
                    self.limits.timeout.as_secs()
                ),
                "inputSchema": code,
            },
        ])
    }

    fn call_tool(&mut self, params: &Value) -> Result<Value, (i64, &'static str)> {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let code = params
            .get("arguments")
            .and_then(|a| a.get("code"))
            .and_then(Value::as_str);
        let (Some(code), "search" | "execute") = (code, name) else {
            return match name {
                "search" | "execute" => Err((-32602, "the `code` argument is required")),
                _ => Err((-32602, "unknown tool")),
            };
        };
        let (entries, problems) = self.catalog();
        let tools = Value::Array(entries.iter().map(Entry::describe).collect());
        let caller: Option<Caller> = (name == "execute").then(|| {
            let services = self.services.clone();
            let by_name = entries.clone();
            let caller: Caller =
                Rc::new(RefCell::new(
                    move |tool: &str, arguments: &Value| match by_name
                        .iter()
                        .find(|e| e.name == tool)
                    {
                        Some(entry) => services.borrow_mut().call(entry, arguments),
                        None => CallOutcome::Error(format!(
                            "codemode.{tool} is not a known tool; use search to list them"
                        )),
                    },
                ));
            caller
        });
        if name == "execute" {
            self.services.borrow_mut().set_script(Some(script_id(code)));
        }
        let run = sandbox::run(code, &tools, caller, &self.limits);
        self.services.borrow_mut().set_script(None);
        Ok(self.render(run, problems))
    }

    fn render(&self, run: Run, problems: Vec<String>) -> Value {
        let mut report = serde_json::Map::new();
        if let Some(held) = &run.held {
            report.insert("approval_required".to_owned(), held.clone());
        }
        if let Some(result) = &run.result {
            report.insert("result".to_owned(), result.clone());
        }
        if let Some(error) = &run.error {
            report.insert("error".to_owned(), Value::String(error.clone()));
        }
        if !run.logs.is_empty() {
            report.insert("logs".to_owned(), json!(run.logs));
        }
        if !run.calls.is_empty() {
            report.insert(
                "calls".to_owned(),
                Value::Array(
                    run.calls
                        .iter()
                        .map(|c| json!({"tool": c.tool, "status": c.status}))
                        .collect(),
                ),
            );
        }
        if !problems.is_empty() {
            report.insert("catalog_problems".to_owned(), json!(problems));
        }
        let body = sandbox::truncate_chars(&dumps(&Value::Object(report)), self.limits.max_output);
        let mut content = Vec::new();
        if let Some(held) = &run.held {
            let tool = held.get("tool").and_then(Value::as_str).unwrap_or("a call");
            content.push(json!({"type": "text", "text": format!(
                "APPROVAL REQUIRED — the script stopped at {tool}. The calls listed as ok \
                 were made. Once the call is approved, run the remaining work again."
            )}));
        }
        content.push(json!({"type": "text", "text": body}));
        json!({
            "content": content,
            "isError": run.held.is_some() || run.error.is_some(),
        })
    }
}

/// A fresh run id, the script's hash and its code.
fn script_id(code: &str) -> (String, String, String) {
    let mut run = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut run);
    (
        hex::encode(run),
        format!("sha256:{}", crate::canonical::sha256_hex(code.as_bytes())),
        code.to_owned(),
    )
}

const INSTRUCTIONS: &str = "TokenCrumb Code Mode: call `search` to find tools, then `execute` \
    to run JavaScript that calls them. Combine several calls in one script and return only \
    what you need.";

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}
