//! The merged tool catalog a Code Mode script sees, and how tool results become
//! JavaScript values.
//!
//! Names follow Cloudflare Code Mode: `<service>_<tool>`, with `-` and `.` replaced by
//! `_`, a leading digit prefixed by `_` and reserved words suffixed by `_`. The gateway
//! name of the tool is kept apart: it is the one the call attestation signs.

use serde_json::{Map, Value, json};

use crate::json::strict_json;

/// One upstream tool, as exposed to scripts.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    /// `codemode.<name>` in scripts.
    pub name: String,
    pub service: String,
    /// The tool name the gateway lists, signed in the attestation.
    pub tool: String,
    pub description: String,
    pub input_schema: Value,
}

impl Entry {
    /// What `codemode.tools()` returns for this tool.
    pub fn describe(&self) -> Value {
        json!({
            "name": self.name,
            "service": self.service,
            "description": self.description,
            "inputSchema": self.input_schema,
            "typescript": self.typescript(),
        })
    }

    /// A TypeScript declaration of the call, documentation comment included.
    pub fn typescript(&self) -> String {
        let mut out = String::new();
        let description = self.description.trim();
        if !description.is_empty() {
            out.push_str("/** ");
            out.push_str(&description.replace("*/", "* /").replace('\n', "\n * "));
            out.push_str(" */\n");
        }
        out.push_str(&format!(
            "codemode.{}(args: {}): Promise<unknown>",
            self.name,
            ts_type(&self.input_schema, 0)
        ));
        out
    }
}

const RESERVED: &[&str] = &[
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "debugger",
    "default",
    "delete",
    "do",
    "else",
    "enum",
    "export",
    "extends",
    "false",
    "finally",
    "for",
    "function",
    "if",
    "import",
    "in",
    "instanceof",
    "new",
    "null",
    "return",
    "super",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "typeof",
    "var",
    "void",
    "while",
    "with",
    "yield",
    "let",
    "static",
    "await",
    "tools",
    "then",
];

/// A JavaScript identifier for `<service>_<tool>`.
pub fn script_name(service: &str, tool: &str) -> String {
    let mut name: String = format!("{service}_{tool}")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '$' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if name.starts_with(|c: char| c.is_ascii_digit()) {
        name.insert(0, '_');
    }
    if RESERVED.contains(&name.as_str()) {
        name.push('_');
    }
    name
}

/// The entries of one service's `tools/list` result. Malformed tools are skipped.
pub fn entries(service: &str, tools: &[Value]) -> Vec<Entry> {
    tools
        .iter()
        .filter_map(|tool| {
            let name = tool.get("name")?.as_str()?;
            Some(Entry {
                name: script_name(service, name),
                service: service.to_owned(),
                tool: name.to_owned(),
                description: tool
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                input_schema: tool
                    .get("inputSchema")
                    .cloned()
                    .unwrap_or_else(|| json!({"type": "object"})),
            })
        })
        .collect()
}

fn ts_type(schema: &Value, depth: usize) -> String {
    if depth > 6 {
        return "unknown".to_owned();
    }
    let Some(schema) = schema.as_object() else {
        return "unknown".to_owned();
    };
    if let Some(Value::Array(values)) = schema.get("enum") {
        let literals: Vec<String> = values.iter().map(Value::to_string).collect();
        if !literals.is_empty() {
            return literals.join(" | ");
        }
    }
    for key in ["anyOf", "oneOf"] {
        if let Some(Value::Array(options)) = schema.get(key) {
            let types: Vec<String> = options.iter().map(|o| ts_type(o, depth + 1)).collect();
            if !types.is_empty() {
                return types.join(" | ");
            }
        }
    }
    let kind = match schema.get("type") {
        Some(Value::String(kind)) => kind.as_str(),
        Some(Value::Array(kinds)) => {
            let types: Vec<String> = kinds
                .iter()
                .filter_map(Value::as_str)
                .map(|k| ts_type(&single_type(schema, k), depth + 1))
                .collect();
            return if types.is_empty() {
                "unknown".to_owned()
            } else {
                types.join(" | ")
            };
        }
        _ if schema.contains_key("properties") => "object",
        _ => return "unknown".to_owned(),
    };
    match kind {
        "string" => "string".to_owned(),
        "integer" | "number" => "number".to_owned(),
        "boolean" => "boolean".to_owned(),
        "null" => "null".to_owned(),
        "array" => format!(
            "Array<{}>",
            schema
                .get("items")
                .map_or_else(|| "unknown".to_owned(), |i| ts_type(i, depth + 1))
        ),
        "object" => object_type(schema, depth),
        _ => "unknown".to_owned(),
    }
}

fn single_type(schema: &Map<String, Value>, kind: &str) -> Value {
    let mut copy = schema.clone();
    copy.insert("type".to_owned(), Value::String(kind.to_owned()));
    Value::Object(copy)
}

fn object_type(schema: &Map<String, Value>, depth: usize) -> String {
    let Some(Value::Object(properties)) = schema.get("properties") else {
        return "Record<string, unknown>".to_owned();
    };
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|r| r.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let fields: Vec<String> = properties
        .iter()
        .map(|(name, property)| {
            let key = if name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
                && !name.starts_with(|c: char| c.is_ascii_digit())
            {
                name.clone()
            } else {
                Value::String(name.clone()).to_string()
            };
            let optional = if required.contains(&name.as_str()) {
                ""
            } else {
                "?"
            };
            format!("{key}{optional}: {}", ts_type(property, depth + 1))
        })
        .collect();
    if fields.is_empty() {
        "{}".to_owned()
    } else {
        format!("{{ {} }}", fields.join("; "))
    }
}

/// The value a script receives from a successful `tools/call` result:
/// `structuredContent` when present, else the text blocks joined (parsed as JSON when
/// they are JSON), else the content blocks as they are.
pub fn result_value(result: &Value) -> Value {
    if let Some(structured) = result.get("structuredContent")
        && !structured.is_null()
    {
        return structured.clone();
    }
    let blocks = result
        .get("content")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if blocks.iter().all(|b| b.get("type") == Some(&json!("text"))) {
        let text: String = blocks
            .iter()
            .filter_map(|b| b.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n");
        return strict_json(text.as_bytes()).unwrap_or(Value::String(text));
    }
    Value::Array(blocks)
}

/// The message of a failed `tools/call` result (`isError: true`).
pub fn error_text(result: &Value) -> String {
    let text: Vec<&str> = result
        .get("content")
        .and_then(Value::as_array)
        .map(|blocks| {
            blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    if text.is_empty() {
        "tool error".to_owned()
    } else {
        text.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_identifiers() {
        assert_eq!(script_name("kdrive", "list-files"), "kdrive_list_files");
        assert_eq!(script_name("my-server", "get.data"), "my_server_get_data");
        assert_eq!(script_name("1st", "x"), "_1st_x");
    }

    #[test]
    fn declarations_follow_the_schema() {
        let entry = &entries(
            "kdrive",
            &[json!({
                "name": "list-files",
                "description": "List a folder.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "limit": {"type": "integer"},
                        "kind": {"enum": ["file", "dir"]},
                        "tags": {"type": "array", "items": {"type": "string"}},
                        "odd key": {"type": ["string", "null"]}
                    },
                    "required": ["path"]
                }
            })],
        )[0];
        assert_eq!(entry.tool, "list-files");
        assert_eq!(
            entry.typescript(),
            "/** List a folder. */\ncodemode.kdrive_list_files(args: { path: string; limit?: number; \
             kind?: \"file\" | \"dir\"; tags?: Array<string>; \"odd key\"?: string | null }): Promise<unknown>"
        );
    }

    #[test]
    fn results_become_values() {
        assert_eq!(
            result_value(
                &json!({"content": [{"type": "text", "text": "x"}], "structuredContent": {"a": 1}})
            ),
            json!({"a": 1})
        );
        assert_eq!(
            result_value(&json!({"content": [{"type": "text", "text": "[1,2]"}]})),
            json!([1, 2])
        );
        assert_eq!(
            result_value(&json!({"content": [{"type": "text", "text": "plain"}]})),
            json!("plain")
        );
        let image =
            json!({"content": [{"type": "image", "data": "AA==", "mimeType": "image/png"}]});
        assert_eq!(result_value(&image), image["content"]);
        assert_eq!(
            error_text(&json!({"isError": true, "content": [{"type": "text", "text": "denied"}]})),
            "denied"
        );
    }
}
