//! Strict boundary validation shared by configuration, tokens and JSON-RPC.
//!
//! Every message is the one the former implementation produced: they surface in
//! refusal reasons that land in the signed audit log.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::json::{as_integer, is_integer_literal};

pub const MAX_INTEGER: i128 = (1_i128 << 53) - 1;

/// Python's `str.isspace()` for one character.
pub fn py_isspace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Python's `str.strip()` (no argument).
pub fn py_strip(value: &str) -> &str {
    value.trim_matches(py_isspace)
}

/// An object whose keys all belong to `allowed`.
pub fn mapping<'a>(
    value: &'a Value,
    allowed: &[&str],
    place: &str,
) -> Result<&'a Map<String, Value>> {
    let Value::Object(map) = value else {
        return Err(Error::value(format!("{place}: expected an object")));
    };
    let unknown: BTreeSet<&str> = map
        .keys()
        .map(String::as_str)
        .filter(|k| !allowed.contains(k))
        .collect();
    if !unknown.is_empty() {
        let listed: Vec<String> = unknown.iter().map(|k| crate::error::py_repr(k)).collect();
        return Err(Error::value(format!(
            "{place}: unknown keys [{}]",
            listed.join(", ")
        )));
    }
    Ok(map)
}

fn integer_message(place: &str, minimum: i128, maximum: i128) -> Error {
    Error::value(format!(
        "{place}: expected integer in [{minimum}, {maximum}]"
    ))
}

/// A JSON integer (never a bool or a float) within `[minimum, maximum]`.
pub fn integer_value(value: &Value, place: &str, minimum: i128, maximum: i128) -> Result<i128> {
    match as_integer(value) {
        Some(n) if (minimum..=maximum).contains(&n) => Ok(n),
        _ => Err(integer_message(place, minimum, maximum)),
    }
}

/// Range check for a value already typed as an integer.
pub fn integer(value: i128, place: &str, minimum: i128, maximum: i128) -> Result<i128> {
    if (minimum..=maximum).contains(&value) {
        Ok(value)
    } else {
        Err(integer_message(place, minimum, maximum))
    }
}

pub fn non_negative(value: i128, place: &str) -> Result<i128> {
    integer(value, place, 0, MAX_INTEGER)
}

/// A nonempty, trimmed, bounded string without control characters.
pub fn string<'a>(value: &'a str, place: &str, maximum: usize) -> Result<&'a str> {
    if py_strip(value).is_empty() || py_strip(value) != value {
        return Err(Error::value(format!(
            "{place}: expected a nonempty string without surrounding whitespace"
        )));
    }
    if value.chars().count() > maximum || value.chars().any(|c| (c as u32) < 32) {
        return Err(Error::value(format!(
            "{place}: invalid length or control character"
        )));
    }
    Ok(value)
}

/// [`string`] for an untyped JSON value (a non-string fails with the same message).
pub fn string_value<'a>(value: Option<&'a Value>, place: &str, maximum: usize) -> Result<&'a str> {
    match value {
        Some(Value::String(s)) => string(s, place, maximum),
        _ => Err(Error::value(format!(
            "{place}: expected a nonempty string without surrounding whitespace"
        ))),
    }
}

/// One of a closed set of strings.
pub fn choice<'a>(value: &'a str, options: &[&str], place: &str) -> Result<&'a str> {
    if options.contains(&value) {
        Ok(value)
    } else {
        Err(choice_message(options, place))
    }
}

pub fn choice_value<'a>(value: &'a Value, options: &[&str], place: &str) -> Result<&'a str> {
    match value {
        Value::String(s) => choice(s, options, place),
        _ => Err(choice_message(options, place)),
    }
}

fn choice_message(options: &[&str], place: &str) -> Error {
    let mut sorted: Vec<&str> = options.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let listed: Vec<String> = sorted.iter().map(|o| crate::error::py_repr(o)).collect();
    Error::value(format!("{place}: expected one of [{}]", listed.join(", ")))
}

/// `ed25519/<64 hex>`, normalized to lowercase.
pub fn public_key(value: &str) -> Result<String> {
    let valid = value.len() == 72
        && value.starts_with("ed25519/")
        && value[8..].bytes().all(|b| b.is_ascii_hexdigit());
    if !valid {
        return Err(Error::value(
            "agent_pubkey: expected ed25519/<64 hex digits>",
        ));
    }
    Ok(value.to_ascii_lowercase())
}

pub fn public_key_value(value: Option<&Value>) -> Result<String> {
    match value {
        Some(Value::String(s)) => public_key(s),
        _ => Err(Error::value(
            "agent_pubkey: expected ed25519/<64 hex digits>",
        )),
    }
}

/// True for a JSON integer literal (Python `type(v) is int`).
pub fn is_int(value: &Value) -> bool {
    matches!(value, Value::Number(n) if is_integer_literal(&n.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn integer_rejects_bool_and_float() {
        assert!(integer_value(&json!(true), "x", 0, 10).is_err());
        assert!(integer_value(&crate::json::strict_json("5.0").unwrap(), "x", 0, 10).is_err());
        assert_eq!(integer_value(&json!(5), "x", 0, 10).unwrap(), 5);
    }

    #[test]
    fn string_rules() {
        assert!(string(" a", "x", 10).is_err());
        assert!(string("a\u{1}", "x", 10).is_err());
        assert!(string("\u{a0}", "x", 10).is_err());
        assert_eq!(string("é", "x", 1).unwrap(), "é");
    }

    #[test]
    fn mapping_lists_unknown_keys_sorted() {
        let err = mapping(&json!({"b": 1, "a": 2, "ok": 3}), &["ok"], "policy").unwrap_err();
        assert_eq!(err.message, "policy: unknown keys ['a', 'b']");
    }
}
