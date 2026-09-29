//! The stdio -> Streamable HTTP bridge behind `client-wrap`.
//!
//! Ported from `test_client_transport_pairs_sse_and_preserves_session_without_raw_sse`
//! (`tests/test_security_lifecycle.py`), extended to every refusal the bridge makes:
//! a response must be complete, bounded, uncompressed and paired with its request, and
//! any failure is a generic JSON-RPC error with no retry.

mod common;

use std::sync::{Arc, Mutex};

use tokencrumb_mcp_proxy::attestation::{Expected, verify_attestation};
use tokencrumb_mcp_proxy::canonical::arguments_hash;
use tokencrumb_mcp_proxy::client_transport::{ClientTransport, http_agent};
use tokencrumb_mcp_proxy::json::{dumps, strict_json};
use tokencrumb_mcp_proxy::keys::generate_keypair;
use tokencrumb_mcp_proxy::nonce_cache::NonceCache;
use common::stub::{self, StubRequest, StubResponse};
use common::{bm_stdin, stderr, stdout};
use serde_json::{Value, json};

const TRANSPORT_ERROR: &str = "transport or request error";

fn bridge(url: &str) -> ClientTransport {
    ClientTransport::new(
        http_agent(None).unwrap(),
        format!("{url}/mcp"),
        "token",
        "alice",
        None,
    )
}

fn echo(request: &StubRequest) -> StubResponse {
    let message = request.json();
    StubResponse::json(&json!({"jsonrpc": "2.0", "id": message["id"], "result": {}}))
}

fn is_transport_error(reply: &Option<Value>, id: Value) -> bool {
    reply.as_ref().is_some_and(|r| {
        r["id"] == id
            && r["error"]["code"] == json!(-32603)
            && r["error"]["message"] == json!(TRANSPORT_ERROR)
    })
}

#[test]
fn client_transport_pairs_sse_and_preserves_session_without_raw_sse() {
    let server = stub::serve(|request| {
        let message = request.json();
        if message["method"] == "initialize" {
            return StubResponse::new(
                200,
                "text/event-stream",
                "data: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1,\"result\":{\"protocolVersion\":\"2025-06-18\"}}\n\n",
            )
            .header("mcp-session-id", "session-A");
        }
        echo(request)
    });
    let mut bridge = bridge(&server.url);
    let reply = bridge
        .exchange("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}")
        .unwrap();
    assert_eq!(reply["id"], json!(1));
    assert_eq!(reply["result"]["protocolVersion"], "2025-06-18");
    let reply = bridge
        .exchange("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}")
        .unwrap();
    assert_eq!(reply["id"], json!(2));
    let calls = server.calls();
    assert_eq!(calls[1].header("mcp-session-id"), Some("session-A"));
    assert!(is_transport_error(
        &bridge.exchange("bad json"),
        Value::Null
    ));
    assert_eq!(
        server.calls().len(),
        2,
        "a malformed line never reaches the proxy"
    );
}

#[test]
fn every_request_carries_the_mandate_and_the_fixed_header_set() {
    let server = stub::serve(echo);
    let mut bridge = bridge(&server.url);
    bridge.exchange("{\"jsonrpc\":\"2.0\",\"id\":\"a\",\"method\":\"ping\"}");
    let call = &server.calls()[0];
    assert_eq!(call.method, "POST");
    assert_eq!(call.path, "/mcp");
    assert_eq!(call.header("authorization"), Some("Biscuit token"));
    assert_eq!(call.header("content-type"), Some("application/json"));
    assert_eq!(
        call.header("accept"),
        Some("application/json, text/event-stream")
    );
    assert_eq!(call.header("accept-encoding"), Some("identity"));
    assert_eq!(call.header("mcp-protocol-version"), Some("2025-06-18"));
    assert_eq!(call.header("mcp-session-id"), None);
    assert_eq!(
        call.header("agent-attestation"),
        None,
        "no key, no attestation"
    );
    // The body is the message re-serialized the way the former bridge did.
    assert_eq!(
        String::from_utf8(call.body.clone()).unwrap(),
        "{\"jsonrpc\": \"2.0\", \"id\": \"a\", \"method\": \"ping\"}"
    );
}

#[test]
fn tools_call_is_attested_with_the_agent_key() {
    let agent = generate_keypair();
    let server = stub::serve(echo);
    let mut bridge = ClientTransport::new(
        http_agent(None).unwrap(),
        format!("{}/mcp", server.url),
        "the-token",
        "agent-7",
        Some(agent.private_str.clone()),
    );
    let arguments = json!({"path": "/projets/acme/a.txt"});
    let line = json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                      "params": {"name": "read_file", "arguments": arguments}});
    assert_eq!(bridge.exchange(&line.to_string()).unwrap()["id"], json!(3));
    let header = server.calls()[0]
        .header("agent-attestation")
        .unwrap()
        .to_owned();
    let expected = Expected {
        agent_pubkey: &agent.public_str,
        tool: "read_file",
        arguments_hash: &arguments_hash(&arguments).unwrap(),
        token_b64: "the-token",
        now: chrono::Utc::now(),
        freshness_seconds: 60,
        clock_skew_seconds: 30,
    };
    let result = verify_attestation(&header, &expected, &NonceCache::in_memory(), true);
    assert!(result.ok, "{:?}", result.reason);
    assert_eq!(result.agent_id.as_deref(), Some("agent-7"));

    // A tools/call without a tool name cannot be attested, so it is not sent.
    let before = server.calls().len();
    let bad =
        json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"arguments": {}}});
    assert!(is_transport_error(
        &bridge.exchange(&bad.to_string()),
        json!(4)
    ));
    assert_eq!(server.calls().len(), before);
}

#[test]
fn malformed_requests_are_refused_locally() {
    let server = stub::serve(echo);
    let mut bridge = bridge(&server.url);
    for (line, id) in [
        ("[]", Value::Null),
        (
            "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"ping\"}",
            Value::Null,
        ),
        ("{\"jsonrpc\":\"2.0\",\"id\":1}", Value::Null),
        (
            "{\"jsonrpc\":\"2.0\",\"id\":1.5,\"method\":\"ping\"}",
            json!(1.5),
        ),
        (
            "{\"jsonrpc\":\"2.0\",\"id\":true,\"method\":\"ping\"}",
            json!(true),
        ),
        (
            "{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"ping\"}",
            Value::Null,
        ),
        (
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":[]}",
            json!(1),
        ),
        (
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"id\":2,\"method\":\"ping\"}",
            Value::Null,
        ),
    ] {
        let reply = bridge.exchange(line);
        let reply_id = reply.as_ref().map(|r| r["id"].clone());
        assert!(
            reply
                .as_ref()
                .is_some_and(|r| r["error"]["message"] == TRANSPORT_ERROR),
            "{line}"
        );
        // The echoed id is exactly what was read (a float stays a float).
        assert_eq!(dumps(&reply_id.unwrap()), dumps(&id), "{line}");
    }
    let too_large = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{{\"x\":\"{}\"}}}}",
        "é".repeat(600_000)
    );
    assert!(is_transport_error(
        &bridge.exchange(&too_large),
        Value::Null
    ));
    // A malformed notification is dropped silently: there is no id to answer.
    assert!(
        bridge
            .exchange("{\"jsonrpc\":\"2.0\",\"method\":\"n\",\"params\":1}")
            .is_none()
    );
    assert!(server.calls().is_empty());
}

#[test]
fn unpaired_unbounded_or_compressed_responses_are_refused() {
    let mode = Arc::new(Mutex::new("wrong-id"));
    let current = mode.clone();
    let server = stub::serve(move |request| {
        let message = request.json();
        match *current.lock().unwrap() {
            "wrong-id" => StubResponse::json(&json!({"jsonrpc": "2.0", "id": 99, "result": {}})),
            "two" => StubResponse::new(
                200,
                "text/event-stream",
                format!(
                    "data: {}\n\ndata: {}\n\n",
                    json!({"jsonrpc": "2.0", "id": message["id"], "result": {}}),
                    json!({"jsonrpc": "2.0", "id": message["id"], "result": {}})
                ),
            ),
            "server-request" => StubResponse::json(
                &json!({"jsonrpc": "2.0", "id": message["id"], "method": "sampling/createMessage"}),
            ),
            "huge" => StubResponse::new(200, "application/json", vec![b' '; 4 * 1024 * 1024 + 1]),
            "gzip" => echo(request).header("Content-Encoding", "gzip"),
            "500" => StubResponse::new(500, "text/plain", "boom"),
            "redirect" => StubResponse::new(307, "text/plain", "").header("Location", "/elsewhere"),
            "version" => StubResponse::json(
                &json!({"jsonrpc": "2.0", "id": message["id"], "result": {"protocolVersion": "2024-11-05"}}),
            ),
            _ => echo(request),
        }
    });
    let mut bridge = bridge(&server.url);
    for case in [
        "wrong-id",
        "two",
        "server-request",
        "huge",
        "gzip",
        "500",
        "redirect",
    ] {
        *mode.lock().unwrap() = case;
        let reply = bridge.exchange("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}");
        assert!(is_transport_error(&reply, json!(7)), "{case}: {reply:?}");
    }
    *mode.lock().unwrap() = "version";
    let reply =
        bridge.exchange("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}");
    assert!(
        is_transport_error(&reply, json!(1)),
        "a different MCP revision is refused"
    );
    // No retry: one request per exchange, whatever the outcome.
    assert_eq!(server.calls().len(), 8);
}

#[test]
fn notifications_expect_no_answer_and_404_drops_the_session() {
    let mode = Arc::new(Mutex::new(0u16));
    let current = mode.clone();
    let server = stub::serve(move |request| match *current.lock().unwrap() {
        202 => StubResponse::new(202, "application/json", ""),
        404 => StubResponse::new(404, "text/plain", "gone"),
        _ => {
            let message = request.json();
            StubResponse::json(
                &json!({"jsonrpc": "2.0", "id": message["id"], "result": {"protocolVersion": "2025-06-18"}}),
            )
            .header("Mcp-Session-Id", "S1")
        }
    });
    let mut bridge = bridge(&server.url);
    bridge.exchange("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}");
    assert_eq!(bridge.session.as_deref(), Some("S1"));

    *mode.lock().unwrap() = 202;
    assert!(
        bridge
            .exchange("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}")
            .is_none()
    );
    // A notification answered with a message is refused — silently, it has no id.
    *mode.lock().unwrap() = 200;
    assert!(
        bridge
            .exchange("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/x\"}")
            .is_none()
    );

    *mode.lock().unwrap() = 404;
    let reply = bridge.exchange("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}");
    assert!(is_transport_error(&reply, json!(2)));
    assert!(bridge.session.is_none(), "an expired session is forgotten");
}

// --------------------------------------------------------------------------- //
// The binary
// --------------------------------------------------------------------------- //

#[test]
fn cli_client_wrap_relays_lines_and_keeps_stdout_for_mcp() {
    let dir = tempfile::tempdir().unwrap();
    let authority = generate_keypair();
    let agent = common::keyfiles(dir.path(), "agent");
    let token = tokencrumb_mcp_proxy::biscuit_ops::forge(
        &authority.private_str,
        &tokencrumb_mcp_proxy::biscuit_ops::ForgeRequest {
            agent_id: "agent-from-token".into(),
            tool: "read_file".into(),
            audience: common::TEST_AUDIENCE.into(),
            agent_pubkey: Some(agent.public_str.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    std::fs::write(dir.path().join("mandate.b64"), format!("{token}\n")).unwrap();
    let server = stub::serve(|request| {
        let message = request.json();
        if message.get("id").is_none() {
            return StubResponse::new(202, "application/json", "");
        }
        echo(request)
    });
    let proxy = format!("{}/mcp", server.url);
    let input = [
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}",
        "",
        "   ",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}",
        "garbage",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{}}}",
    ]
    .join("\n");
    let output = bm_stdin(
        dir.path(),
        &[
            "client-wrap",
            "--proxy",
            &proxy,
            "--token",
            "mandate.b64",
            "--agent-key",
            "agent.key",
        ],
        input.as_bytes(),
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        stderr(&output).trim(),
        format!("client-wrap -> {proxy}  (agent=agent-from-token, signing=on)")
    );
    let replies: Vec<Value> = stdout(&output)
        .lines()
        .map(|l| strict_json(l).unwrap())
        .collect();
    assert_eq!(replies.len(), 3);
    assert_eq!(replies[0], json!({"jsonrpc": "2.0", "id": 1, "result": {}}));
    assert_eq!(replies[1]["id"], Value::Null);
    assert_eq!(replies[1]["error"]["message"], TRANSPORT_ERROR);
    assert_eq!(replies[2]["id"], json!(2));
    // Output lines are Python `json.dumps` renderings.
    assert_eq!(
        stdout(&output).lines().next().unwrap(),
        "{\"jsonrpc\": \"2.0\", \"id\": 1, \"result\": {}}"
    );
    let calls = server.calls();
    assert_eq!(calls.len(), 3);
    assert_eq!(
        calls[0].header("authorization"),
        Some(format!("Biscuit {token}").as_str())
    );
    assert!(calls[2].header("agent-attestation").is_some());
}

#[test]
fn cli_client_wrap_answers_an_oversized_line_and_goes_on() {
    let dir = tempfile::tempdir().unwrap();
    let server = stub::serve(echo);
    let proxy = format!("{}/mcp", server.url);
    let mut input = vec![b'x'; 1024 * 1024 + 10];
    input.extend_from_slice(b"\n{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"ping\"}\n");
    let output = bm_stdin(
        dir.path(),
        &[
            "client-wrap",
            "--proxy",
            &proxy,
            "--token",
            "tok",
            "--agent-id",
            "me",
        ],
        &input,
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines[0],
        "{\"jsonrpc\": \"2.0\", \"id\": null, \"error\": {\"code\": -32600, \"message\": \"request too large\"}}"
    );
    assert_eq!(strict_json(lines[1]).unwrap()["id"], json!(5));
    assert!(stderr(&output).contains("(agent=me, signing=off)"));
    assert_eq!(server.calls().len(), 1);
}

#[test]
fn cli_client_wrap_requires_an_existing_ca_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let output = bm_stdin(
        dir.path(),
        &[
            "client-wrap",
            "--proxy",
            "https://proxy/mcp",
            "--token",
            "tok",
            "--agent-id",
            "a",
            "--ca",
            "nope.pem",
        ],
        b"",
    );
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        stderr(&output).trim(),
        "client-wrap: CA bundle not found: nope.pem"
    );
    assert!(stdout(&output).is_empty());

    // A file that holds no certificate is refused rather than silently trusted.
    std::fs::write(dir.path().join("empty.pem"), "not a certificate\n").unwrap();
    let output = bm_stdin(
        dir.path(),
        &[
            "client-wrap",
            "--proxy",
            "https://proxy/mcp",
            "--token",
            "tok",
            "--agent-id",
            "a",
            "--ca",
            "empty.pem",
        ],
        b"",
    );
    assert_eq!(output.status.code(), Some(1));
}
