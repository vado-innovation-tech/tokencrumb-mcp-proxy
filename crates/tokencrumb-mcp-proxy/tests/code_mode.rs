//! Code Mode, client side (ADR 0007), end to end through a real gateway.
//!
//! The gateway runs on a loopback socket with a hardened policy (every call must carry
//! an attestation signed by the agent key anchored in the mandate). The Code Mode server
//! reaches its two endpoints over HTTP, as `tokencrumb code-mode` does. What must hold:
//!   - one entry, two tools, a merged catalog from every service;
//!   - each call a script makes is an ordinary signed `tools/call`, verified, forwarded
//!     to its own upstream and audited by the gateway;
//!   - a refused call is an exception the script can catch, and reaches no upstream.

mod common;

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use common::proxy::{TEST_AUDIENCE, World, build_token, date_term, in_seconds, options, str_term};
use futures_util::future::BoxFuture;
use serde_json::{Value, json};
use tokencrumb_mcp_proxy::client_transport::{ClientTransport, http_agent};
use tokencrumb_mcp_proxy::codemode::sandbox::Limits;
use tokencrumb_mcp_proxy::codemode::{Server, Service};
use tokencrumb_mcp_proxy::policy::parse_policy;
use tokencrumb_mcp_proxy::proxy::upstream::{
    ForwardHeaders, SharedUpstream, Upstream, UpstreamResponse,
};

/// A minimal MCP server: answers initialize, lists its tools, echoes calls.
struct McpUpstream {
    tools: Vec<Value>,
    calls: Mutex<Vec<Value>>,
}

impl McpUpstream {
    fn new(tools: Vec<Value>) -> Arc<Self> {
        Arc::new(Self {
            tools,
            calls: Mutex::new(Vec::new()),
        })
    }

    fn called(&self) -> Vec<Value> {
        self.calls.lock().unwrap().clone()
    }
}

impl Upstream for McpUpstream {
    fn forward<'a>(
        &'a self,
        _method: &'a str,
        body: Bytes,
        _headers: &'a ForwardHeaders,
    ) -> BoxFuture<'a, tokencrumb_mcp_proxy::Result<UpstreamResponse>> {
        let message: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let id = message.get("id").cloned();
        let result = match message["method"].as_str() {
            Some("initialize") => Some(json!({
                "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake", "version": "1"}})),
            Some("tools/list") => Some(json!({"tools": self.tools})),
            Some("tools/call") => {
                self.calls.lock().unwrap().push(message["params"].clone());
                Some(json!({"content": [{"type": "text",
                    "text": json!({"echo": message["params"]}).to_string()}]}))
            }
            _ => None,
        };
        let response = match (id, result) {
            (Some(id), Some(result)) => UpstreamResponse {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body: Bytes::from(
                    json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string(),
                ),
            },
            _ => UpstreamResponse {
                status: 202,
                headers: Vec::new(),
                body: Bytes::new(),
            },
        };
        Box::pin(async move { Ok(response) })
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

fn tool(name: &str) -> Value {
    json!({"name": name, "description": format!("The {name} tool."),
           "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}})
}

struct Stack {
    world: World,
    kdrive: Arc<McpUpstream>,
    github: Arc<McpUpstream>,
    base: String,
    _runtime: tokio::runtime::Runtime,
}

/// A hardened two-service gateway served on a loopback port.
fn stack() -> Stack {
    stack_with(json!({}))
}

/// The same gateway with extra top-level policy keys.
fn stack_with(extra: Value) -> Stack {
    let world = World::new();
    let mut raw = json!({
        "deny_unknown_tools": true,
        "min_profile": "hardened_biscuit_anchored",
        "upstreams": {"kdrive": "http://kdrive/mcp", "github": "http://github/mcp"},
        "tools": [
            {"name": "list-files", "operation": "read", "upstream": "kdrive",
             "require": ["call_signature_valid", "nonce_fresh", "arguments_bound"],
             "allow": {"budget": 50}},
            {"name": "create_issue", "operation": "write", "upstream": "github",
             "require": ["call_signature_valid", "nonce_fresh", "arguments_bound"],
             "allow": {"budget": 50}},
            {"name": "delete_repo", "operation": "write", "upstream": "github",
             "require": ["call_signature_valid", "nonce_fresh", "arguments_bound"],
             "allow": {"budget": 50}},
        ],
    });
    for (key, value) in extra.as_object().unwrap() {
        raw[key] = value.clone();
    }
    let mut policy = parse_policy(&raw).unwrap();
    policy.policy_digest = "test-policy-digest".into();
    let kdrive = McpUpstream::new(vec![tool("list-files")]);
    let github = McpUpstream::new(vec![tool("create_issue"), tool("delete_repo")]);
    let verifier = world.verifier(policy, Some(options()));
    let app = world.proxy_with(
        vec![
            (Some("kdrive".into()), kdrive.clone() as SharedUpstream),
            (Some("github".into()), github.clone() as SharedUpstream),
        ],
        None,
        verifier,
        true,
    );
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    runtime.spawn(async move { axum::serve(listener, app).await.unwrap() });
    Stack {
        world,
        kdrive,
        github,
        base,
        _runtime: runtime,
    }
}

/// A mandate for listing files and creating issues; not for deleting repositories.
fn mandate(w: &World) -> String {
    build_token(
        &w.authority.private_str,
        r#"agent_id("agent-1"); audience({aud}); required_profile("hardened_biscuit_anchored");
           agent_pubkey({k}); right("list-files", "read"); right("create_issue", "write");
           budget_cap(1000); expires_at({exp}); check if time($t), $t < {exp};"#,
        &[
            ("aud", str_term(TEST_AUDIENCE)),
            ("k", str_term(&w.agent.public_str)),
            ("exp", date_term(in_seconds(3600))),
        ],
    )
}

fn server(s: &Stack, signing: bool) -> Server {
    let token = mandate(&s.world);
    let private = signing.then(|| s.world.agent.private_str.clone());
    let services = ["kdrive", "github"]
        .iter()
        .map(|name| {
            Service::new(
                *name,
                ClientTransport::new(
                    http_agent(None).unwrap(),
                    format!("{}/mcp/{name}", s.base),
                    token.clone(),
                    "agent-1",
                    private.clone(),
                ),
            )
        })
        .collect();
    Server::new(services, Limits::default())
}

fn call(server: &mut Server, tool: &str, code: &str) -> (bool, Value) {
    let line = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                      "params": {"name": tool, "arguments": {"code": code}}});
    let reply = server.handle(&line.to_string()).unwrap();
    let result = &reply["result"];
    let content = result["content"].as_array().unwrap();
    let report = content.last().unwrap()["text"].as_str().unwrap();
    (
        result["isError"] == json!(true),
        serde_json::from_str(report).unwrap(),
    )
}

#[test]
fn one_entry_exposes_search_and_execute() {
    let s = stack();
    let mut server = server(&s, true);
    let reply = server
        .handle(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#)
        .unwrap();
    assert_eq!(reply["result"]["protocolVersion"], "2025-06-18");
    assert!(
        server
            .handle(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
            .is_none()
    );
    let reply = server
        .handle(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
        .unwrap();
    let names: Vec<&str> = reply["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["search", "execute"]);
    let reply = server
        .handle(r#"{"jsonrpc":"2.0","id":3,"method":"resources/list"}"#)
        .unwrap();
    assert_eq!(reply["error"]["code"], -32601);
}

#[test]
fn search_returns_the_merged_catalog_without_calling_anything() {
    let s = stack();
    let mut server = server(&s, true);
    let (failed, report) = call(
        &mut server,
        "search",
        "async () => codemode.tools().map(t => [t.name, t.service])",
    );
    assert!(!failed, "{report}");
    assert_eq!(
        report["result"],
        json!([
            ["kdrive_list_files", "kdrive"],
            ["github_create_issue", "github"],
            ["github_delete_repo", "github"]
        ])
    );
    let (_, report) = call(
        &mut server,
        "search",
        "async () => codemode.tools().find(t => t.name === 'kdrive_list_files').typescript",
    );
    assert_eq!(
        report["result"],
        "/** The list-files tool. */\ncodemode.kdrive_list_files(args: { path?: string }): Promise<unknown>"
    );
    assert!(s.kdrive.called().is_empty() && s.github.called().is_empty());
}

#[test]
fn a_script_chains_signed_calls_across_services() {
    let s = stack();
    let mut server = server(&s, true);
    let (failed, report) = call(
        &mut server,
        "execute",
        "async () => {
           const files = await codemode.kdrive_list_files({path: '/reports'});
           const issue = await codemode.github_create_issue({path: files.echo.arguments.path});
           return issue.echo;
         }",
    );
    assert!(!failed, "{report}");
    assert_eq!(
        report["result"],
        json!({"name": "create_issue", "arguments": {"path": "/reports"}})
    );
    assert_eq!(
        report["calls"],
        json!([{"tool": "kdrive_list_files", "status": "ok"},
               {"tool": "github_create_issue", "status": "ok"}])
    );
    // Each service received only its own call, under the gateway's tool name.
    assert_eq!(
        s.kdrive.called(),
        [json!({"name": "list-files", "arguments": {"path": "/reports"}})]
    );
    assert_eq!(s.github.called().len(), 1);
    // The gateway verified and audited both calls.
    let allowed: Vec<Value> = s
        .world
        .audit_entries()
        .into_iter()
        .filter(|e| e["decision"] == "ALLOW" && !e["tool"].is_null())
        .map(|e| e["tool"].clone())
        .collect();
    assert_eq!(allowed, [json!("list-files"), json!("create_issue")]);
}

#[test]
fn a_refused_call_is_a_catchable_exception_and_reaches_no_upstream() {
    let s = stack();
    let mut server = server(&s, true);
    let (failed, report) = call(
        &mut server,
        "execute",
        "async () => {
           try { await codemode.github_delete_repo({path: 'acme'}); return 'deleted'; }
           catch (e) { return e.name; }
         }",
    );
    assert!(!failed, "{report}");
    assert_eq!(report["result"], "ToolError");
    assert_eq!(report["calls"][0]["status"], "error");
    assert!(s.github.called().is_empty());
    let last = s.world.audit_entries().pop().unwrap();
    assert_eq!(last["decision"], "DENY");
}

#[test]
fn without_the_agent_key_no_call_passes_a_hardened_gateway() {
    let s = stack();
    let mut server = server(&s, false);
    let (failed, report) = call(
        &mut server,
        "execute",
        "async () => codemode.kdrive_list_files({path: '/x'})",
    );
    assert!(failed);
    assert!(report["error"].as_str().unwrap().starts_with("ToolError"));
    assert!(s.kdrive.called().is_empty());
}

#[test]
fn unknown_tools_and_missing_code_are_reported() {
    let s = stack();
    let mut server = server(&s, true);
    let (failed, report) = call(&mut server, "execute", "async () => codemode.nope_x({})");
    assert!(failed);
    assert!(
        report["error"]
            .as_str()
            .unwrap()
            .contains("not a known tool")
    );
    let reply = server
        .handle(r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"execute","arguments":{}}}"#)
        .unwrap();
    assert_eq!(reply["error"]["code"], -32602);
}

// -- gateway side: catalog, flows, script audit (ADR 0007, points 5, 10 and 14) ---------

fn script_names(server: &mut Server) -> Value {
    call(
        server,
        "search",
        "async () => codemode.tools().map(t => t.name)",
    )
    .1["result"]
        .clone()
}

#[test]
fn a_granted_catalog_shows_only_what_the_mandate_grants() {
    let s = stack_with(json!({"tools_list": "granted"}));
    let mut server = server(&s, true);
    assert_eq!(
        script_names(&mut server),
        json!(["kdrive_list_files", "github_create_issue"])
    );
    // Without a mandate, nothing is listed.
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let reply: Value = ureq::post(&format!("{}/mcp/github", s.base))
        .set("Content-Type", "application/json")
        .set("Accept", "application/json, text/event-stream")
        .send_string(body)
        .unwrap()
        .into_string()
        .map(|t| serde_json::from_str::<Value>(&t).unwrap())
        .unwrap();
    assert_eq!(reply["result"]["tools"], json!([]));
}

#[test]
fn the_declared_catalog_remains_the_default() {
    let s = stack();
    let mut server = server(&s, true);
    assert_eq!(script_names(&mut server).as_array().unwrap().len(), 3);
}

#[test]
fn a_denied_flow_is_refused_within_a_script_and_audited() {
    let s = stack_with(json!({"flows": {"deny": [{"from": "kdrive", "to": "github"}]}}));
    let mut server = server(&s, true);
    let (failed, report) = call(
        &mut server,
        "execute",
        "async () => {
           await codemode.kdrive_list_files({path: '/secret'});
           try { await codemode.github_create_issue({path: 'leak'}); return 'sent'; }
           catch (e) { return e.name; }
         }",
    );
    assert!(!failed, "{report}");
    assert_eq!(report["result"], "ToolError");
    assert!(
        s.github.called().is_empty(),
        "the denied flow reached GitHub"
    );
    let denial = s
        .world
        .audit_entries()
        .into_iter()
        .find(|e| e["decision"] == "DENY")
        .unwrap();
    assert_eq!(
        denial["reason"],
        "flow from kdrive to github is denied within a script"
    );
    assert_eq!(denial["tool"], "create_issue");
}

#[test]
fn the_taint_lasts_one_script() {
    let s = stack_with(json!({"flows": {"deny": [{"from": "kdrive", "to": "github"}]}}));
    let mut server = server(&s, true);
    let (failed, _) = call(
        &mut server,
        "execute",
        "async () => codemode.kdrive_list_files({path: '/a'})",
    );
    assert!(!failed);
    // A new script starts clean; the reverse direction is not denied either.
    let (failed, report) = call(
        &mut server,
        "execute",
        "async () => { await codemode.github_create_issue({path: 'x'});
                       return codemode.kdrive_list_files({path: '/b'}); }",
    );
    assert!(!failed, "{report}");
    assert_eq!(s.github.called().len(), 1);
}

#[test]
fn a_default_deny_flow_policy_only_lets_listed_pairs_through() {
    let s = stack_with(json!({"flows": {"default": "deny",
                                        "allow": [{"from": "github", "to": "kdrive"}]}}));
    let mut server = server(&s, true);
    let (_, report) = call(
        &mut server,
        "execute",
        "async () => { await codemode.github_create_issue({path: 'x'});
                       await codemode.kdrive_list_files({path: '/b'});
                       try { await codemode.github_create_issue({path: 'y'}); }
                       catch (e) { return 'refused'; } }",
    );
    // github -> kdrive is allowed; going back to github after kdrive is not.
    assert_eq!(report["result"], "refused");
    assert_eq!(s.github.called().len(), 1);
}

#[test]
fn the_audit_holds_the_script_and_ties_each_call_to_it() {
    let s = stack();
    let mut server = server(&s, true);
    let code = "async () => { await codemode.kdrive_list_files({path: '/a'});
                              return codemode.github_create_issue({path: 'b'}); }";
    let (failed, _) = call(&mut server, "execute", code);
    assert!(!failed);
    let entries = s.world.audit_entries();
    let scripts: Vec<&Value> = entries
        .iter()
        .filter(|e| e["decision"] == "SCRIPT")
        .collect();
    // Registered once with each gateway endpoint the script called.
    assert_eq!(scripts.len(), 2);
    let script = &scripts[0]["detail"];
    assert_eq!(script["code"], code);
    let expected = format!(
        "sha256:{}",
        tokencrumb_mcp_proxy::canonical::sha256_hex(code.as_bytes())
    );
    assert_eq!(script["script"]["hash"], json!(expected));
    let calls: Vec<&Value> = entries
        .iter()
        .filter(|e| e["decision"] == "ALLOW" && !e["tool"].is_null())
        .collect();
    assert_eq!(calls.len(), 2);
    for entry in calls {
        assert_eq!(entry["detail"]["script"], script["script"]);
    }
    // A search script calls nothing and is not registered.
    call(&mut server, "search", "async () => 1");
    assert_eq!(
        s.world
            .audit_entries()
            .iter()
            .filter(|e| e["decision"] == "SCRIPT")
            .count(),
        2
    );
}

#[test]
fn malformed_script_headers_and_registrations_are_refused() {
    let s = stack();
    let post = |headers: &[(&str, &str)], body: &str| {
        let mut request = ureq::post(&format!("{}/mcp/kdrive", s.base))
            .set("Content-Type", "application/json")
            .set("Accept", "application/json, text/event-stream")
            .set("Authorization", &format!("Biscuit {}", mandate(&s.world)));
        for (k, v) in headers {
            request = request.set(k, v);
        }
        match request.send_string(body) {
            Ok(r) => (
                r.status(),
                r.into_string()
                    .map(|t| serde_json::from_str::<Value>(&t).unwrap_or(Value::Null))
                    .unwrap(),
            ),
            Err(ureq::Error::Status(code, r)) => (
                code,
                r.into_string()
                    .map(|t| serde_json::from_str::<Value>(&t).unwrap_or(Value::Null))
                    .unwrap(),
            ),
            Err(e) => panic!("{e}"),
        }
    };
    let ping = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    let (status, _) = post(
        &[("TokenCrumb-Script-Run", "0123456789abcdef0123456789abcdef")],
        ping,
    );
    assert_eq!(status, 400, "a run id without its hash");
    let (status, _) = post(
        &[
            ("TokenCrumb-Script-Run", "not-hex"),
            ("TokenCrumb-Script-Hash", "sha256:00"),
        ],
        ping,
    );
    assert_eq!(status, 400);
    let register = |hash: &str| {
        json!({"jsonrpc": "2.0", "id": 2, "method": "tokencrumb/script", "params": {
            "run": "0123456789abcdef0123456789abcdef", "hash": hash, "code": "async () => 1"}})
        .to_string()
    };
    let (_, reply) = post(&[], &register(&format!("sha256:{}", "0".repeat(64))));
    assert!(
        reply["error"].is_object(),
        "a hash that does not match the code"
    );
    let good = format!(
        "sha256:{}",
        tokencrumb_mcp_proxy::canonical::sha256_hex(b"async () => 1")
    );
    let (_, reply) = post(&[], &register(&good));
    assert_eq!(reply["result"], json!({}));
    assert!(
        s.kdrive.called().is_empty(),
        "registration never reaches the upstream"
    );
    // Without a mandate, registration is refused.
    let reply: Value = ureq::post(&format!("{}/mcp/kdrive", s.base))
        .set("Content-Type", "application/json")
        .set("Accept", "application/json, text/event-stream")
        .send_string(&register(&good))
        .unwrap()
        .into_string()
        .map(|t| serde_json::from_str::<Value>(&t).unwrap())
        .unwrap();
    assert!(reply["error"].is_object());
}
