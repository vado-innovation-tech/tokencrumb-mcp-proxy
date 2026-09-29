//! JSON at the trust boundary: strict parsing, RFC 8785 canonical form, and the
//! byte-exact rendering of Python's `json.dumps` used by the stored formats.
//!
//! `serde_json` runs with `arbitrary_precision`, so a number keeps the literal it was
//! written with. That lets this module tell an integer literal from a float one, which
//! is what JCS (integers are bounded to ±(2^53−1)) and the former implementation both
//! depend on.

use std::fmt::Write as _;

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use crate::error::{Error, Result};

pub const MAX_SAFE_INTEGER: i128 = (1_i128 << 53) - 1;

// --------------------------------------------------------------------------- //
// Strict parsing
// --------------------------------------------------------------------------- //

struct StrictValue(Value);

impl<'de> de::Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor).map(StrictValue)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("JSON number exceeds finite range"))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(StrictValue(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        // With `arbitrary_precision`, a number arrives as a one-entry map whose key is
        // serde_json's private token; hand it back to serde_json to rebuild it.
        let mut out = Map::new();
        let Some(first) = map.next_key::<String>()? else {
            return Ok(Value::Object(out));
        };
        if first == "$serde_json::private::Number" {
            let literal: String = map.next_value()?;
            let number: Number = literal
                .parse()
                .map_err(|_| de::Error::custom(format!("invalid JSON number: {literal}")))?;
            return Ok(Value::Number(number));
        }
        let StrictValue(v) = map.next_value()?;
        out.insert(first, v);
        while let Some(key) = map.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate JSON key: {key}")));
            }
            let StrictValue(v) = map.next_value()?;
            out.insert(key, v);
        }
        Ok(Value::Object(out))
    }
}

/// Parse untrusted JSON: duplicate keys, non-finite numbers and nesting deeper than
/// `max_depth` are refused instead of silently resolved.
pub fn strict_json_depth(data: &[u8], max_depth: usize) -> Result<Value> {
    let text = std::str::from_utf8(data).map_err(|e| Error::value(e.to_string()))?;
    // Python's json accepts surrounding whitespace, and so does serde_json; the only
    // leading byte it tolerates that serde_json does not is none — keep both strict.
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value = StrictValue::deserialize(&mut deserializer)
        .map(|v| v.0)
        .map_err(serde_error)?;
    deserializer.end().map_err(serde_error)?;

    let mut pending = vec![(&value, 0usize)];
    while let Some((v, depth)) = pending.pop() {
        if depth > max_depth {
            return Err(Error::value("JSON nesting limit exceeded"));
        }
        match v {
            Value::Object(map) => pending.extend(map.values().map(|x| (x, depth + 1))),
            Value::Array(items) => pending.extend(items.iter().map(|x| (x, depth + 1))),
            Value::Number(n) => check_finite(n)?,
            _ => {}
        }
    }
    Ok(value)
}

pub fn strict_json(data: impl AsRef<[u8]>) -> Result<Value> {
    strict_json_depth(data.as_ref(), 32)
}

use serde::Deserialize as _;

fn check_finite(n: &Number) -> Result<()> {
    let literal = n.to_string();
    if !is_integer_literal(&literal) {
        match literal.parse::<f64>() {
            Ok(f) if f.is_finite() => {}
            _ => return Err(Error::value("JSON number exceeds finite range")),
        }
    }
    Ok(())
}

/// Our own refusals (duplicate key, non-finite number) are reported in their exact
/// words, without the position serde_json appends; its depth guard (128) fires before
/// ours can and is reported in our words too.
fn serde_error(error: serde_json::Error) -> Error {
    let message = error.to_string();
    if message.starts_with("recursion limit exceeded") {
        return Error::value("JSON nesting limit exceeded");
    }
    if error.classify() == serde_json::error::Category::Data {
        if let Some(position) = message.rfind(" at line ") {
            return Error::value(&message[..position]);
        }
    }
    Error::value(message)
}

// --------------------------------------------------------------------------- //
// Number helpers
// --------------------------------------------------------------------------- //

pub fn is_integer_literal(literal: &str) -> bool {
    !literal.contains(['.', 'e', 'E'])
}

/// The integer a JSON number denotes, when it was written as an integer.
pub fn as_integer(value: &Value) -> Option<i128> {
    match value {
        Value::Number(n) => {
            let literal = n.to_string();
            if is_integer_literal(&literal) {
                literal.parse::<i128>().ok()
            } else {
                None
            }
        }
        _ => None,
    }
}

pub fn as_float(n: &Number) -> Option<f64> {
    n.to_string().parse::<f64>().ok()
}

/// An integer JSON value built from any Rust integer.
pub fn int(value: i128) -> Value {
    Value::Number(value.to_string().parse().expect("integer literal"))
}

/// A float JSON value (Python float semantics are rendered by the dumpers).
pub fn float(value: f64) -> Value {
    Number::from_f64(value)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

// --------------------------------------------------------------------------- //
// RFC 8785 (JCS)
// --------------------------------------------------------------------------- //

/// Canonical JSON bytes, identical to the `rfc8785` package: integers bounded to the
/// safe domain, floats in ECMAScript form, keys sorted by UTF-16 code units.
pub fn canonicalize(value: &Value) -> Result<Vec<u8>> {
    let mut out = String::new();
    jcs(value, &mut out)?;
    Ok(out.into_bytes())
}

fn jcs(value: &Value, out: &mut String) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            let literal = n.to_string();
            if is_integer_literal(&literal) {
                let parsed = literal.parse::<i128>().ok();
                match parsed {
                    Some(i) if (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&i) => {
                        write!(out, "{i}").expect("write to string");
                    }
                    _ => {
                        let shown = literal.trim_start_matches('-').trim_start_matches('0');
                        let sign = if literal.starts_with('-') { "-" } else { "" };
                        let shown = if shown.is_empty() { "0" } else { shown };
                        return Err(Error::value(format!(
                            "{sign}{shown} exceeds safe integer domain for JSON floats"
                        )));
                    }
                }
            } else {
                let f: f64 = literal
                    .parse()
                    .map_err(|_| Error::value(format!("{literal} is not representable in JCS")))?;
                if !f.is_finite() {
                    return Err(Error::value(format!(
                        "{} is not representable in JCS",
                        py_float_repr(f)
                    )));
                }
                if f == 0.0 {
                    out.push('0');
                } else {
                    let mut buffer = ryu_js::Buffer::new();
                    out.push_str(buffer.format_finite(f));
                }
            }
        }
        Value::String(s) => jcs_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jcs(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push('{');
            for (i, (k, v)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jcs_string(k, out);
                out.push(':');
                jcs(v, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn jcs_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                write!(out, "\\u{:04x}", c as u32).expect("write to string");
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

// --------------------------------------------------------------------------- //
// Python `json.dumps` rendering
// --------------------------------------------------------------------------- //

/// `json.dumps(value)` with Python's defaults: `", "` / `": "` separators and
/// `ensure_ascii=True`. Used wherever the stored bytes must match the former format.
pub fn dumps(value: &Value) -> String {
    let mut out = String::new();
    py_dump(value, &mut out, None, 0, true);
    out
}

/// `json.dumps(value, ensure_ascii=False)`.
pub fn dumps_unicode(value: &Value) -> String {
    let mut out = String::new();
    py_dump(value, &mut out, None, 0, false);
    out
}

/// `json.dumps(value, indent=n)` (item separator `,`, key separator `": "`).
pub fn dumps_indent(value: &Value, indent: usize) -> String {
    let mut out = String::new();
    py_dump(value, &mut out, Some(indent), 0, true);
    out
}

/// Recursively sort object keys (Python `sort_keys=True`).
pub fn sort_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut sorted = Map::new();
            for k in keys {
                sorted.insert(k.clone(), sort_keys(&map[k]));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_keys).collect()),
        other => other.clone(),
    }
}

fn py_dump(value: &Value, out: &mut String, indent: Option<usize>, level: usize, ascii: bool) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&py_number(n)),
        Value::String(s) => py_string(s, out, ascii),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(if indent.is_some() { "," } else { ", " });
                }
                newline(out, indent, level + 1);
                py_dump(item, out, indent, level + 1, ascii);
            }
            newline(out, indent, level);
            out.push(']');
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (k, v)) in map.iter().enumerate() {
                if i > 0 {
                    out.push_str(if indent.is_some() { "," } else { ", " });
                }
                newline(out, indent, level + 1);
                py_string(k, out, ascii);
                out.push_str(": ");
                py_dump(v, out, indent, level + 1, ascii);
            }
            newline(out, indent, level);
            out.push('}');
        }
    }
}

fn newline(out: &mut String, indent: Option<usize>, level: usize) {
    if let Some(width) = indent {
        out.push('\n');
        out.push_str(&" ".repeat(width * level));
    }
}

fn py_number(n: &Number) -> String {
    let literal = n.to_string();
    if is_integer_literal(&literal) {
        match literal.parse::<i128>() {
            Ok(i) => i.to_string(),
            Err(_) => literal,
        }
    } else {
        match literal.parse::<f64>() {
            Ok(f) => py_float_repr(f),
            Err(_) => literal,
        }
    }
}

/// Python's `repr(float)`: shortest round-trip digits, scientific notation outside
/// `1e-4 <= |x| < 1e16`, at least one fractional digit in fixed notation.
pub fn py_float_repr(f: f64) -> String {
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return if f > 0.0 {
            "Infinity".into()
        } else {
            "-Infinity".into()
        };
    }
    if f == 0.0 {
        return if f.is_sign_negative() {
            "-0.0".into()
        } else {
            "0.0".into()
        };
    }
    let sci = format!("{f:e}"); // e.g. "1.5e20", "-1e-7"
    let (mantissa, exponent) = sci.split_once('e').expect("exponent form");
    let exponent: i32 = exponent.parse().expect("exponent");
    let negative = mantissa.starts_with('-');
    let digits: String = mantissa.chars().filter(|c| c.is_ascii_digit()).collect();
    let sign = if negative { "-" } else { "" };
    if (-4..16).contains(&exponent) {
        let point = exponent + 1; // digits before the decimal point
        let body = if point <= 0 {
            format!("0.{}{}", "0".repeat((-point) as usize), digits)
        } else if point as usize >= digits.len() {
            format!("{}{}.0", digits, "0".repeat(point as usize - digits.len()))
        } else {
            format!(
                "{}.{}",
                &digits[..point as usize],
                &digits[point as usize..]
            )
        };
        format!("{sign}{body}")
    } else {
        let head = &digits[..1];
        let tail = &digits[1..];
        let mantissa = if tail.is_empty() {
            head.to_string()
        } else {
            format!("{head}.{tail}")
        };
        let esign = if exponent < 0 { '-' } else { '+' };
        format!("{sign}{mantissa}e{esign}{:02}", exponent.abs())
    }
}

fn py_string(s: &str, out: &mut String, ascii: bool) {
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                write!(out, "\\u{:04x}", c as u32).expect("write to string");
            }
            c if ascii && (c as u32) > 0x7e => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    write!(out, "\\u{unit:04x}").expect("write to string");
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

// --------------------------------------------------------------------------- //
// Small accessors
// --------------------------------------------------------------------------- //

pub fn obj(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

/// Python's `type(value).__name__`, for messages that name the offending type.
pub fn py_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) => {
            if is_integer_literal(&n.to_string()) {
                "int"
            } else {
                "float"
            }
        }
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_repr_matches_python() {
        for (f, want) in [
            (1.0, "1.0"),
            (0.1, "0.1"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (1e-5, "1e-05"),
            (0.0001, "0.0001"),
            (123456789012.5, "123456789012.5"),
            (1.5e300, "1.5e+300"),
            (-2.5e-7, "-2.5e-07"),
        ] {
            assert_eq!(py_float_repr(f), want, "{f}");
        }
    }

    #[test]
    fn dumps_matches_python() {
        let v = strict_json(br#"{"b": [1, 2.5, "\u00e9"], "a": {}, "c": null}"#).unwrap();
        assert_eq!(
            dumps(&v),
            r#"{"b": [1, 2.5, "\u00e9"], "a": {}, "c": null}"#
        );
        assert_eq!(
            dumps_indent(&v, 2),
            "{\n  \"b\": [\n    1,\n    2.5,\n    \"\\u00e9\"\n  ],\n  \"a\": {},\n  \"c\": null\n}"
        );
    }

    #[test]
    fn strict_rejects_duplicates_at_any_depth() {
        assert!(strict_json(br#"{"a":{"x":1,"x":2}}"#).is_err());
        assert!(strict_json(br#"{"a":1,"b":2}"#).is_ok());
    }
}
