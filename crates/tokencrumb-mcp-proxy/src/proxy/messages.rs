//! JSON-RPC messages as they travel through the gateway.

use serde_json::{Value, json};

use crate::error::{Error, Result};
use crate::json::strict_json;

// JSON-RPC error codes (spec 2.0)
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const PARSE_ERROR: i64 = -32700;
pub const INTERNAL_ERROR: i64 = -32603;

/// Decode an upstream (or proxy) response body into its JSON-RPC messages.
///
/// A `text/event-stream` body is split into complete SSE events and each `data:` payload
/// is parsed; anything else is one JSON document. Server-initiated messages (with a
/// `method`) and messages without `result`/`error` are refused: the server -> client
/// channel is closed. Returns the messages and whether the body was SSE.
pub fn response_messages(
    status: u16,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<(Vec<Value>, bool)> {
    if body.is_empty() && (status == 202 || status == 204) {
        return Ok((Vec::new(), false));
    }
    let is_sse = content_type.is_some_and(|c| c.contains("text/event-stream"));
    let messages = if is_sse {
        let normalized = String::from_utf8_lossy(body).replace("\r\n", "\n");
        let mut out = Vec::new();
        for event in normalized.split("\n\n") {
            let data: Vec<&str> = event
                .split('\n')
                .filter_map(|line| line.strip_prefix("data:"))
                .map(|d| d.trim_start_matches(' '))
                .collect();
            if !data.is_empty() {
                out.push(strict_json(data.join("\n"))?);
            }
        }
        out
    } else {
        vec![strict_json(body)?]
    };
    for message in &messages {
        let Some(map) = message.as_object() else {
            return Err(Error::value(
                "unsupported server-initiated or malformed upstream message",
            ));
        };
        if map.contains_key("method") || !(map.contains_key("result") || map.contains_key("error"))
        {
            return Err(Error::value(
                "unsupported server-initiated or malformed upstream message",
            ));
        }
    }
    Ok((messages, is_sse))
}

/// A real JSON-RPC error — used for refused methods and refused batches.
pub fn error_response(id: Value, code: i64, message: &str, correlation_id: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message, "data": {"correlation_id": correlation_id}},
    })
}

/// MCP-idiomatic denial for `tools/call`: a CallToolResult with `isError: true`.
pub fn deny_result(id: Value, correlation_id: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{
                "type": "text",
                "text": format!("DENY — authorization failed · correlation_id: {correlation_id}"),
            }],
            "isError": true,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_and_json_bodies() {
        let sse = b"event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\r\n\r\n";
        let (messages, is_sse) = response_messages(200, Some("text/event-stream"), sse).unwrap();
        assert!(is_sse && messages.len() == 1);
        assert!(
            response_messages(
                200,
                Some("application/json"),
                br#"{"jsonrpc":"2.0","method":"x"}"#
            )
            .is_err()
        );
        assert!(response_messages(202, None, b"").unwrap().0.is_empty());
    }
}
