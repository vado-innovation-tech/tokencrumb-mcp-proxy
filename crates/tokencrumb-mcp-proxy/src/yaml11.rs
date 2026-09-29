//! YAML loading with PyYAML `SafeLoader` semantics (YAML 1.1 implicit typing).
//!
//! `policy.yaml` was always read by PyYAML, where a plain `yes` is a boolean, `010` is
//! octal (8), `1:30` is 90 and an unquoted date is a date. A YAML 1.2 loader would read
//! `budget: 010` as 10 — a different security bound for the same file. This module
//! resolves plain scalars with PyYAML's own regular expressions and constructors, so a
//! policy means exactly what it meant before.
//!
//! Values that have no JSON counterpart (dates, timestamps, infinities, binary) are
//! kept as strings starting with NUL: no validator accepts a control character, so
//! they are refused everywhere a typed value is expected, as they were before.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};
use yaml_rust2::parser::{Event, EventReceiver, Parser, Tag};
use yaml_rust2::scanner::TScalarStyle;

use crate::error::{Error, Result, py_repr};
use crate::json::float;

/// Prefix of the values that have no JSON counterpart.
pub const OPAQUE: char = '\0';

static BOOL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)$")
        .unwrap()
});
static FLOAT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?",
        r"|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?",
        r"|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*",
        r"|[-+]?\.(?:inf|Inf|INF)",
        r"|\.(?:nan|NaN|NAN))$"
    ))
    .unwrap()
});
static INT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(?:[-+]?0b[0-1_]+",
        r"|[-+]?0[0-7_]+",
        r"|[-+]?(?:0|[1-9][0-9_]*)",
        r"|[-+]?0x[0-9a-fA-F_]+",
        r"|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$"
    ))
    .unwrap()
});
static NULL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(?:~|null|Null|NULL|)$").unwrap());
static TIMESTAMP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]",
        r"|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?",
        r"(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?",
        r"(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)$"
    ))
    .unwrap()
});

fn opaque(kind: &str, text: &str) -> Value {
    Value::String(format!("{OPAQUE}{kind}:{text}"))
}

fn construct_int(text: &str) -> Result<Value> {
    let invalid = || Error::value(format!("invalid literal for int(): {}", py_repr(text)));
    let mut value: String = text.replace('_', "");
    let mut sign: i128 = 1;
    if value.starts_with('-') {
        sign = -1;
    }
    if value.starts_with(['+', '-']) {
        value.remove(0);
    }
    let parsed = if value == "0" {
        Some(0)
    } else if let Some(bits) = value.strip_prefix("0b") {
        i128::from_str_radix(bits, 2).ok()
    } else if let Some(hex) = value.strip_prefix("0x") {
        i128::from_str_radix(hex, 16).ok()
    } else if value.starts_with('0') {
        i128::from_str_radix(&value, 8).ok()
    } else if value.contains(':') {
        value
            .split(':')
            .rev()
            .try_fold((0_i128, 1_i128), |(total, base), part| {
                let total = total.checked_add(part.parse::<i128>().ok()?.checked_mul(base)?)?;
                Some((total, base.checked_mul(60)?))
            })
            .map(|(total, _)| total)
    } else {
        value.parse::<i128>().ok()
    };
    let magnitude = parsed.ok_or_else(invalid)?;
    Ok(crate::json::int(sign * magnitude))
}

fn construct_float(text: &str) -> Result<Value> {
    let value = text.replace('_', "").to_lowercase();
    let (sign, body) = match value.strip_prefix('-') {
        Some(rest) => (-1.0, rest.to_owned()),
        None => (1.0, value.strip_prefix('+').unwrap_or(&value).to_owned()),
    };
    if body == ".inf" || body == ".nan" {
        return Ok(opaque("float", &value));
    }
    let magnitude = if body.contains(':') {
        let mut total = 0.0;
        let mut base = 1.0;
        for part in body.split(':').rev() {
            total += part
                .parse::<f64>()
                .map_err(|e| Error::value(e.to_string()))?
                * base;
            base *= 60.0;
        }
        total
    } else {
        body.parse::<f64>().map_err(|_| {
            Error::value(format!(
                "could not convert string to float: {}",
                py_repr(text)
            ))
        })?
    };
    let result = sign * magnitude;
    Ok(if result.is_finite() {
        float(result)
    } else {
        opaque("float", &value)
    })
}

fn construct_bool(text: &str) -> Result<Value> {
    match text.to_lowercase().as_str() {
        "yes" | "true" | "on" => Ok(Value::Bool(true)),
        "no" | "false" | "off" => Ok(Value::Bool(false)),
        _ => Err(Error::value(format!("invalid boolean: {}", py_repr(text)))),
    }
}

/// The tag suffix for a `tag:yaml.org,2002:` tag, however it was spelled.
fn core_tag(tag: &Tag) -> Option<&str> {
    match tag.handle.as_str() {
        "!!" | "tag:yaml.org,2002:" => Some(tag.suffix.as_str()),
        "!" if tag.suffix.starts_with("tag:yaml.org,2002:") => {
            tag.suffix.strip_prefix("tag:yaml.org,2002:")
        }
        _ => None,
    }
}

fn scalar(text: &str, style: TScalarStyle, tag: Option<&Tag>) -> Result<Value> {
    if let Some(tag) = tag {
        return match core_tag(tag) {
            Some("str") => Ok(Value::String(text.to_owned())),
            Some("int") => construct_int(text),
            Some("float") => construct_float(text),
            Some("bool") => construct_bool(text),
            Some("null") => Ok(Value::Null),
            Some(kind @ ("timestamp" | "binary")) => Ok(opaque(kind, text)),
            _ => Err(Error::value(format!(
                "could not determine a constructor for the tag {}",
                py_repr(&format!("{}{}", tag.handle, tag.suffix))
            ))),
        };
    }
    if style != TScalarStyle::Plain {
        return Ok(Value::String(text.to_owned()));
    }
    // PyYAML's implicit resolvers, in their registration order.
    if BOOL.is_match(text) {
        return construct_bool(text);
    }
    if FLOAT.is_match(text) {
        return construct_float(text);
    }
    if INT.is_match(text) {
        return construct_int(text);
    }
    if text == "<<" {
        return Err(Error::value(
            "could not determine a constructor for the tag 'tag:yaml.org,2002:merge'",
        ));
    }
    if NULL.is_match(text) {
        return Ok(Value::Null);
    }
    if TIMESTAMP.is_match(text) {
        return Ok(opaque("timestamp", text));
    }
    if text == "=" {
        return Err(Error::value(
            "could not determine a constructor for the tag 'tag:yaml.org,2002:value'",
        ));
    }
    Ok(Value::String(text.to_owned()))
}

#[derive(Default)]
struct Events(Vec<Event>);

impl EventReceiver for Events {
    fn on_event(&mut self, event: Event) {
        self.0.push(event);
    }
}

struct Composer {
    events: std::vec::IntoIter<Event>,
    anchors: std::collections::HashMap<usize, Value>,
    strict: bool,
}

/// Python's `repr()` of a scalar key, for the duplicate-key message.
fn key_repr(key: &Value) -> String {
    match key {
        Value::String(s) => py_repr(s),
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        other => crate::json::dumps(other),
    }
}

impl Composer {
    fn next(&mut self) -> Result<Event> {
        self.events
            .next()
            .ok_or_else(|| Error::value("unexpected end of YAML stream"))
    }

    fn node(&mut self, event: Event) -> Result<Value> {
        match event {
            Event::Scalar(text, style, anchor, tag) => {
                let value = scalar(&text, style, tag.as_ref())?;
                self.remember(anchor, &value);
                Ok(value)
            }
            Event::Alias(id) => self
                .anchors
                .get(&id)
                .cloned()
                .ok_or_else(|| Error::value("found undefined alias")),
            Event::SequenceStart(anchor, _) => {
                let mut items = Vec::new();
                loop {
                    match self.next()? {
                        Event::SequenceEnd => break,
                        event => items.push(self.node(event)?),
                    }
                }
                let value = Value::Array(items);
                self.remember(anchor, &value);
                Ok(value)
            }
            Event::MappingStart(anchor, _) => {
                let mut map = Map::new();
                loop {
                    let key = match self.next()? {
                        Event::MappingEnd => break,
                        event => self.node(event)?,
                    };
                    let event = self.next()?;
                    let value = self.node(event)?;
                    match key {
                        Value::String(k) if !(self.strict && map.contains_key(&k)) => {
                            map.insert(k, value);
                        }
                        other if self.strict => {
                            return Err(Error::value(format!(
                                "policy: duplicate or invalid key {}",
                                key_repr(&other)
                            )));
                        }
                        other => {
                            map.insert(key_repr(&other), value);
                        }
                    }
                }
                let value = Value::Object(map);
                self.remember(anchor, &value);
                Ok(value)
            }
            other => Err(Error::value(format!("unexpected YAML event {other:?}"))),
        }
    }

    fn remember(&mut self, anchor: usize, value: &Value) {
        if anchor != 0 {
            self.anchors.insert(anchor, value.clone());
        }
    }
}

/// Load one YAML document. `strict` refuses duplicate and non-string keys (the
/// policy loader); otherwise the last duplicate wins, as `yaml.safe_load` does.
pub fn load(text: &str, strict: bool) -> Result<Value> {
    let mut events = Events::default();
    Parser::new_from_str(text)
        .load(&mut events, true)
        .map_err(|e| Error::value(format!("invalid YAML: {e}")))?;
    let mut composer = Composer {
        events: events.0.into_iter(),
        anchors: Default::default(),
        strict,
    };
    let mut documents = Vec::new();
    loop {
        match composer.next()? {
            Event::StreamStart | Event::DocumentEnd | Event::Nothing => {}
            Event::StreamEnd => break,
            Event::DocumentStart => {
                let event = composer.next()?;
                documents.push(composer.node(event)?);
            }
            other => return Err(Error::value(format!("unexpected YAML event {other:?}"))),
        }
    }
    match documents.len() {
        0 => Ok(Value::Null),
        1 => Ok(documents.pop().expect("one document")),
        _ => Err(Error::value("expected a single document in the stream")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn yaml_1_1_typing() {
        let v = load("a: yes\nb: 010\nc: 1:30\nd: 0x1f\ne: '010'\nf: 1_000\ng: 1e3\nh: 1.5\ni: ~\nj: 2025-06-18\n", true).unwrap();
        assert_eq!(v["a"], json!(true));
        assert_eq!(v["b"], json!(8));
        assert_eq!(v["c"], json!(90));
        assert_eq!(v["d"], json!(31));
        assert_eq!(v["e"], json!("010"));
        assert_eq!(v["f"], json!(1000));
        assert_eq!(v["g"], json!("1e3"));
        assert_eq!(crate::json::dumps(&v["h"]), "1.5");
        assert_eq!(v["i"], Value::Null);
        assert!(v["j"].as_str().unwrap().starts_with(OPAQUE));
    }

    #[test]
    fn duplicates_and_documents() {
        assert!(load("a: 1\na: 2\n", true).is_err());
        assert_eq!(load("a: 1\na: 2\n", false).unwrap()["a"], json!(2));
        assert!(load("1: a\n", true).is_err());
        assert_eq!(load("", true).unwrap(), Value::Null);
        assert!(load("a: 1\n---\nb: 2\n", true).is_err());
        assert_eq!(load("x: &k [1]\ny: *k\n", true).unwrap()["y"], json!([1]));
    }
}
