//! MCP 2026-07-28 ("modern") support next to the `initialize` era ("legacy").
//!
//! A modern request carries its revision and client capabilities in `params._meta`,
//! and on Streamable HTTP mirrors `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` and
//! `Mcp-Param-*` into headers. The body is the source of truth: the gateway checks the
//! headers it receives against the body before any decision, decides on the body, and
//! recomputes the headers it sends upstream from the body it actually forwards.
//!
//! An upstream's era is a property of the server: it is detected once per endpoint
//! (a `server/discover` probe) and remembered.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value, json};

use crate::verifier::Headers;

pub const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
pub const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";

/// MCP-defined error codes (2026-07-28 reserves -32020 to -32099 for the specification).
pub const HEADER_MISMATCH: i64 = -32020;
pub const MISSING_REQUIRED_CLIENT_CAPABILITY: i64 = -32021;
pub const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;
/// JSON-RPC "Invalid params": a modern request missing a required `_meta` field.
pub const INVALID_PARAMS: i64 = -32602;

/// Freshness hint on a mandate-filtered catalog: short, so a policy reload shows quickly.
pub const LIST_TTL_MS: u64 = 30_000;

/// Headers mirrored from the body. `mcp-param-*` is matched by prefix.
pub const MIRRORED: &[&str] = &["mcp-method", "mcp-name"];
pub const PARAM_PREFIX: &str = "mcp-param-";

/// Methods that only exist in the `initialize` era.
pub const LEGACY_ONLY_METHODS: &[&str] = &["initialize", "notifications/initialized", "ping"];

/// What the gateway knows about one upstream's era.
#[derive(Debug, Clone)]
pub enum Era {
    /// Answers `initialize`; sessions and `Last-Event-ID` apply.
    Legacy,
    /// Answers `server/discover`: the versions it listed and, when the probe succeeded,
    /// its `DiscoverResult`.
    Modern {
        versions: Vec<String>,
        discover: Option<Map<String, Value>>,
    },
}

pub fn is_mirrored(name: &str) -> bool {
    MIRRORED.contains(&name) || name.starts_with(PARAM_PREFIX)
}

fn meta(message: &Map<String, Value>) -> Option<&Map<String, Value>> {
    message
        .get("params")
        .and_then(|p| p.get("_meta"))
        .and_then(Value::as_object)
}

/// The revision a request declares in its body, if it declares one.
pub fn body_version(message: &Map<String, Value>) -> Option<&Value> {
    meta(message).and_then(|m| m.get(META_PROTOCOL_VERSION))
}

pub fn has_client_capabilities(message: &Map<String, Value>) -> bool {
    meta(message)
        .and_then(|m| m.get(META_CLIENT_CAPABILITIES))
        .is_some_and(Value::is_object)
}

/// Set `params._meta` protocol fields, keeping any other `_meta` key. The client
/// capabilities are always replaced: an upstream may only rely on what the gateway
/// lets it ask the agent for, which today is nothing (as for `initialize`).
pub fn set_meta(message: &mut Map<String, Value>, version: &str) {
    let params = message
        .entry("params")
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(params) = params.as_object_mut() else {
        return;
    };
    let meta = params
        .entry("_meta")
        .or_insert_with(|| Value::Object(Map::new()));
    if !meta.is_object() {
        *meta = Value::Object(Map::new());
    }
    let meta = meta.as_object_mut().expect("object");
    meta.insert(META_PROTOCOL_VERSION.into(), json!(version));
    meta.insert(META_CLIENT_CAPABILITIES.into(), json!({}));
}

/// Remove the per-request protocol fields (for an `initialize`-era upstream).
pub fn strip_meta(message: &mut Map<String, Value>) {
    if let Some(meta) = message
        .get_mut("params")
        .and_then(|p| p.get_mut("_meta"))
        .and_then(Value::as_object_mut)
    {
        meta.retain(|k, _| !k.starts_with("io.modelcontextprotocol/"));
    }
}

/// `Mcp-Name` source: `params.name` or `params.uri`.
fn name_source(message: &Map<String, Value>) -> Option<&Value> {
    let params = message.get("params")?;
    params.get("name").or_else(|| params.get("uri"))
}

fn requires_name(method: &str) -> bool {
    matches!(method, "tools/call" | "resources/read" | "prompts/get")
}

/// Decode a received header value: visible ASCII, space and tab only, with the
/// `=?base64?...?=` sentinel decoded to UTF-8.
pub fn decode_header_value(raw: &str) -> Option<String> {
    if !raw.chars().all(|c| c == '\t' || (' '..='~').contains(&c)) {
        return None;
    }
    match raw
        .strip_prefix("=?base64?")
        .and_then(|r| r.strip_suffix("?="))
    {
        Some(encoded) => String::from_utf8(STANDARD.decode(encoded).ok()?).ok(),
        None => Some(raw.to_owned()),
    }
}

/// Encode a value for a header, with the Base64 sentinel when it is not plain ASCII,
/// has surrounding whitespace, or itself looks like the sentinel.
pub fn encode_header_value(value: &str) -> String {
    let plain = value.chars().all(|c| (' '..='~').contains(&c))
        && value.trim() == value
        && !(value.starts_with("=?base64?") && value.ends_with("?="));
    if plain {
        value.to_owned()
    } else {
        format!("=?base64?{}?=", STANDARD.encode(value.as_bytes()))
    }
}

/// One `x-mcp-header` annotation: `Mcp-Param-<name>` mirrors the argument at `path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamHeader {
    pub name: String,
    pub path: Vec<String>,
}

fn is_tchar(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

/// The `x-mcp-header` annotations of a tool's `inputSchema`, reached through
/// `properties` only. `Err` when an annotation is invalid: the tool is then dropped
/// from the catalog, as the revision requires of a client.
pub fn param_headers(tool: &Value) -> std::result::Result<Vec<ParamHeader>, String> {
    fn walk(
        schema: &Value,
        path: &mut Vec<String>,
        out: &mut Vec<ParamHeader>,
    ) -> std::result::Result<(), String> {
        let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
            return Ok(());
        };
        for (key, property) in properties {
            path.push(key.clone());
            if let Some(name) = property.get("x-mcp-header") {
                let name = name
                    .as_str()
                    .filter(|n| !n.is_empty() && n.chars().all(is_tchar))
                    .ok_or("invalid x-mcp-header name")?;
                let primitive = match property.get("type") {
                    None => true,
                    Some(Value::String(t)) => {
                        matches!(t.as_str(), "string" | "integer" | "boolean")
                    }
                    Some(_) => false,
                };
                if !primitive {
                    return Err("x-mcp-header on a non-primitive parameter".into());
                }
                let lowered = name.to_ascii_lowercase();
                if out.iter().any(|p| p.name == lowered) {
                    return Err("duplicate x-mcp-header name".into());
                }
                out.push(ParamHeader {
                    name: lowered,
                    path: path.clone(),
                });
            }
            walk(property, path, out)?;
            path.pop();
        }
        Ok(())
    }
    let mut out = Vec::new();
    if let Some(schema) = tool.get("inputSchema") {
        walk(schema, &mut Vec::new(), &mut out)?;
    }
    Ok(out)
}

/// The argument an annotation mirrors, as its header string; `None` when absent or null.
fn param_value(arguments: &Value, path: &[String]) -> Option<Value> {
    let mut value = arguments;
    for key in path {
        value = value.get(key)?;
    }
    (!value.is_null()).then(|| value.clone())
}

fn render(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn same_value(header: &str, body: &Value) -> bool {
    match body {
        Value::Number(n) => match (header.parse::<f64>(), n.as_f64()) {
            (Ok(h), Some(b)) => h == b,
            _ => false,
        },
        other => render(other).as_deref() == Some(header),
    }
}

/// Check a modern request's mirrored headers against its body. `params` are the
/// annotations known for the called tool, if any. Returns the mismatch reason.
pub fn check_headers(
    message: &Map<String, Value>,
    headers: &Headers,
    params: Option<&[ParamHeader]>,
) -> std::result::Result<(), String> {
    let method = message.get("method").and_then(Value::as_str).unwrap_or("");
    match (headers.get("mcp-protocol-version"), body_version(message)) {
        (None, _) | (Some(""), _) => return Err("MCP-Protocol-Version header missing".into()),
        (Some(h), Some(Value::String(b))) if h == b => {}
        _ => return Err("MCP-Protocol-Version header does not match _meta".into()),
    }
    match headers.get("mcp-method") {
        Some(h) if h == method => {}
        Some(_) => return Err("Mcp-Method header does not match the body".into()),
        None if message.contains_key("id") => return Err("Mcp-Method header missing".into()),
        None => {}
    }
    match (headers.get("mcp-name"), name_source(message)) {
        (None, _) if !requires_name(method) => {}
        (None, _) => return Err("Mcp-Name header missing".into()),
        (Some(h), Some(Value::String(b))) if decode_header_value(h).as_deref() == Some(b) => {}
        _ => return Err("Mcp-Name header does not match the body".into()),
    }
    for (name, value) in &headers.0 {
        if name.starts_with(PARAM_PREFIX) && decode_header_value(value).is_none() {
            return Err(format!("{name} header carries invalid characters"));
        }
    }
    if let Some(params) = params {
        let arguments = message
            .get("params")
            .and_then(|p| p.get("arguments"))
            .cloned()
            .unwrap_or(Value::Null);
        for param in params {
            let header = format!("{PARAM_PREFIX}{}", param.name);
            let decoded = headers.get(&header).and_then(decode_header_value);
            match (param_value(&arguments, &param.path), decoded) {
                (None, None) => {}
                (Some(body), Some(h)) if same_value(&h, &body) => {}
                _ => return Err(format!("{header} header does not match the body")),
            }
        }
    }
    Ok(())
}

/// The headers sent to a modern upstream: the incoming ones without session, resume or
/// mirrored headers, then mirrors recomputed from `message` — the body actually sent.
/// Unrecognized `Mcp-Param-*` headers are passed on untouched, as the revision requires
/// of an intermediary; the upstream checks them against the same body.
pub fn modern_forward(
    incoming: &Headers,
    message: &Map<String, Value>,
    params: Option<&[ParamHeader]>,
) -> Headers {
    let known = |name: &str| {
        params.is_some_and(|ps| {
            ps.iter()
                .any(|p| name.strip_prefix(PARAM_PREFIX) == Some(p.name.as_str()))
        })
    };
    let mut out: Vec<(String, String)> = incoming
        .0
        .iter()
        .filter(|(k, _)| {
            !matches!(
                k.as_str(),
                "mcp-session-id" | "last-event-id" | "mcp-protocol-version"
            ) && !MIRRORED.contains(&k.as_str())
                && !known(k)
        })
        .cloned()
        .collect();
    if let Some(Value::String(version)) = body_version(message) {
        out.push(("mcp-protocol-version".into(), version.clone()));
    }
    if let Some(method) = message.get("method").and_then(Value::as_str) {
        out.push(("mcp-method".into(), method.to_owned()));
        if let Some(Value::String(name)) = name_source(message) {
            out.push(("mcp-name".into(), encode_header_value(name)));
        }
    }
    if let Some(params) = params {
        let arguments = message
            .get("params")
            .and_then(|p| p.get("arguments"))
            .cloned()
            .unwrap_or(Value::Null);
        for param in params {
            if let Some(value) = param_value(&arguments, &param.path)
                .as_ref()
                .and_then(render)
            {
                out.push((
                    format!("{PARAM_PREFIX}{}", param.name),
                    encode_header_value(&value),
                ));
            }
        }
    }
    Headers(out)
}

/// The headers sent to an `initialize`-era upstream: the incoming ones without the
/// 2026-07-28 mirrors, which that era does not define.
pub fn legacy_forward(incoming: &Headers) -> Headers {
    Headers(
        incoming
            .0
            .iter()
            .filter(|(k, _)| !is_mirrored(k))
            .cloned()
            .collect(),
    )
}

/// True for an error only a modern server returns.
pub fn is_modern_error(message: &Value) -> bool {
    message
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(Value::as_i64)
        .is_some_and(|c| (UNSUPPORTED_PROTOCOL_VERSION..=HEADER_MISMATCH).contains(&c))
}

/// Read a `server/discover` probe reply. `None` means legacy: anything that is neither
/// a `DiscoverResult` nor a recognized modern error.
pub fn classify_discover(message: Option<&Value>) -> Option<Era> {
    let message = message?;
    if let Some(result) = message.get("result").and_then(Value::as_object)
        && let Some(versions) = result.get("supportedVersions").and_then(Value::as_array)
    {
        return Some(Era::Modern {
            versions: versions
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
            discover: Some(result.clone()),
        });
    }
    if is_modern_error(message) {
        let versions = message
            .pointer("/error/data/supported")
            .and_then(Value::as_array)
            .map(|v| {
                v.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        return Some(Era::Modern {
            versions,
            discover: None,
        });
    }
    None
}

/// The probe request, declaring `version`.
pub fn discover_request(version: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": "tokencrumb-discover",
        "method": "server/discover",
        "params": {"_meta": {
            META_PROTOCOL_VERSION: version,
            META_CLIENT_CAPABILITIES: {},
        }},
    })
}

/// `capabilities` reduced to `tools`, as the gateway relays only tools.
pub fn tools_only(capabilities: Option<&Value>) -> Value {
    let has_tools = match capabilities {
        Some(Value::Object(map)) => map.contains_key("tools"),
        Some(Value::Array(items)) => items.contains(&json!("tools")),
        Some(Value::String(s)) => s.contains("tools"),
        _ => false,
    };
    if has_tools {
        json!({"tools": {}})
    } else {
        json!({})
    }
}

/// A gateway-issued list or discovery result is per-mandate: never shared, kept briefly.
pub fn mark_private(result: &mut Map<String, Value>) {
    let ttl = result
        .get("ttlMs")
        .and_then(Value::as_u64)
        .map_or(LIST_TTL_MS, |t| t.min(LIST_TTL_MS));
    result.insert("ttlMs".into(), json!(ttl));
    result.insert("cacheScope".into(), json!("private"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_values_round_trip() {
        for value in [
            "us-west1",
            "Hello, 世界",
            " padded ",
            "line1\nline2",
            "=?base64?x?=",
        ] {
            let encoded = encode_header_value(value);
            assert_eq!(decode_header_value(&encoded).as_deref(), Some(value));
        }
        assert_eq!(encode_header_value("us-west1"), "us-west1");
        assert_eq!(
            encode_header_value("Hello, 世界"),
            "=?base64?SGVsbG8sIOS4lueVjA==?="
        );
        assert!(decode_header_value("caf\u{e9}").is_none());
    }

    #[test]
    fn annotations_follow_properties_only() {
        let tool = json!({"inputSchema": {"type": "object", "properties": {
            "region": {"type": "string", "x-mcp-header": "Region"},
            "opts": {"type": "object", "properties": {"n": {"type": "integer", "x-mcp-header": "N"}}},
        }}});
        let found = param_headers(&tool).unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(found[1].path, vec!["opts".to_owned(), "n".to_owned()]);
        let bad = json!({"inputSchema": {"properties": {
            "a": {"type": "number", "x-mcp-header": "A"}}}});
        assert!(param_headers(&bad).is_err());
        let dup = json!({"inputSchema": {"properties": {
            "a": {"x-mcp-header": "A"}, "b": {"x-mcp-header": "a"}}}});
        assert!(param_headers(&dup).is_err());
    }

    #[test]
    fn numbers_compare_numerically() {
        assert!(same_value("42.0", &json!(42)));
        assert!(!same_value("43", &json!(42)));
        assert!(same_value("true", &json!(true)));
    }
}
