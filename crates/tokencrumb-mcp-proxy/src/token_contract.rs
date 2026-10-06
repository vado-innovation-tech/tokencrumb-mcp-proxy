//! Typed mandate metadata read with the Biscuit parser, never regex-extracted values.
//!
//! A verified token exposes its blocks as rendered Datalog source. A quoted-string-aware
//! statement scanner isolates declarations; the Biscuit fact parser decodes their names
//! and typed terms. Unsupported declarations fail closed. Rules may not produce governed
//! metadata or local context. Checks remain evaluated by Biscuit.

use biscuit_auth::builder::{Fact, Term as BiscuitTerm};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use crate::error::{Error, Result};
use crate::profiles;
use crate::validation::{MAX_INTEGER, public_key, py_isspace, py_strip, string};

/// Facts the proxy injects at authorization time: a token may never declare them.
pub const CONTEXT_FACTS: &[&str] = &[
    "time",
    "operation",
    "tool",
    "upstream",
    "resource",
    "budget",
    "delegation_depth",
    "arg",
    "call_signature_valid",
    "nonce_fresh",
    "arguments_bound",
    "capability_bound",
];

/// Identity facts: one unary fact, authority block only.
pub const IDENTITY_FACTS: &[&str] = &[
    "agent_id",
    "agent_pubkey",
    "required_profile",
    "audience",
    "user",
    "client",
    "issuer",
    "key_id",
    "jti",
    "purpose",
];

/// Bounds: one unary fact per block, any block (the proxy takes the tightest).
pub const BOUND_FACTS: &[&str] = &["budget_cap", "max_delegation_depth", "expires_at"];

pub fn is_context(name: &str) -> bool {
    CONTEXT_FACTS.contains(&name)
}

pub fn is_identity(name: &str) -> bool {
    IDENTITY_FACTS.contains(&name)
}

pub fn is_governed(name: &str) -> bool {
    is_identity(name) || BOUND_FACTS.contains(&name)
}

/// A scalar fact term, as the former SDK exposed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Term {
    Int(i64),
    Str(String),
    /// Seconds since the UNIX epoch, UTC.
    Date(u64),
    Bytes(Vec<u8>),
    Bool(bool),
}

impl Term {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Term::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_date(&self) -> Option<DateTime<Utc>> {
        match self {
            Term::Date(secs) => DateTime::from_timestamp(i64::try_from(*secs).ok()?, 0),
            _ => None,
        }
    }

    /// The value as the reference corpus renders it (dates and bytes are tagged).
    pub fn to_json(&self) -> Value {
        match self {
            Term::Int(i) => json!(i),
            Term::Str(s) => json!(s),
            Term::Bool(b) => json!(b),
            Term::Bytes(b) => json!({"$bytes": hex::encode(b)}),
            Term::Date(_) => json!({"$date": py_isoformat(&self.as_date().expect("date"))}),
        }
    }

    /// Human rendering (the Datalog literal).
    pub fn display(&self) -> String {
        match self {
            Term::Int(i) => i.to_string(),
            Term::Str(s) => s.clone(),
            Term::Bool(b) => b.to_string(),
            Term::Bytes(b) => format!("hex:{}", hex::encode(b)),
            Term::Date(_) => self
                .as_date()
                .expect("date")
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        }
    }
}

pub use crate::isotime::py_isoformat;

/// Facts of one block, in first-appearance order: `name -> [terms of each fact]`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockFacts(pub Vec<(String, Vec<Vec<Term>>)>);

impl BlockFacts {
    pub fn get(&self, name: &str) -> Option<&Vec<Vec<Term>>> {
        self.0.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    fn push(&mut self, name: &str, terms: Vec<Term>) {
        match self.0.iter_mut().find(|(n, _)| n == name) {
            Some((_, facts)) => facts.push(terms),
            None => self.0.push((name.to_owned(), vec![terms])),
        }
    }

    pub fn to_json(&self) -> Value {
        let mut map = serde_json::Map::new();
        for (name, facts) in &self.0 {
            let rendered: Vec<Value> = facts
                .iter()
                .map(|f| Value::Array(f.iter().map(Term::to_json).collect()))
                .collect();
            map.insert(name.clone(), Value::Array(rendered));
        }
        Value::Object(map)
    }
}

/// Split rendered block source into statements (quoted-string aware).
pub fn statements(source: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut buffer = String::new();
    for c in source.chars() {
        if escaped {
            escaped = false;
            buffer.push(c);
            continue;
        }
        if quoted && c == '\\' {
            escaped = true;
        } else if c == '"' {
            quoted = !quoted;
        } else if c == ';' && !quoted {
            out.push(py_strip(&buffer).to_owned());
            buffer.clear();
            continue;
        }
        buffer.push(c);
    }
    if quoted || !py_strip(&buffer).is_empty() {
        return Err(Error::value("unsupported or unterminated block statement"));
    }
    Ok(out)
}

/// The predicate name a declaration starts with (`name(`), if any.
fn declaration_name(statement: &str) -> Option<&str> {
    let mut chars = statement.char_indices();
    let (_, first) = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    let end = statement
        .char_indices()
        .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_'))
        .map(|(i, _)| i)?;
    let rest = statement[end..].trim_start_matches(py_isspace);
    rest.starts_with('(').then(|| &statement[..end])
}

fn has_collection(statement: &str) -> bool {
    let mut quoted = false;
    let mut escaped = false;
    for c in statement.chars() {
        if escaped {
            escaped = false;
        } else if quoted && c == '\\' {
            escaped = true;
        } else if c == '"' {
            quoted = !quoted;
        } else if !quoted && (c == '[' || c == '{') {
            return true;
        }
    }
    false
}

fn convert_terms(name: &str, fact: &Fact) -> Result<Vec<Term>> {
    fact.predicate
        .terms
        .iter()
        .map(|term| match term {
            BiscuitTerm::Integer(i) => Ok(Term::Int(*i)),
            BiscuitTerm::Str(s) => Ok(Term::Str(s.clone())),
            BiscuitTerm::Date(d) => Ok(Term::Date(*d)),
            BiscuitTerm::Bytes(b) => Ok(Term::Bytes(b.clone())),
            BiscuitTerm::Bool(b) => Ok(Term::Bool(*b)),
            _ => Err(Error::value(format!("unsupported terms for {name}"))),
        })
        .collect()
}

/// Governed (and optionally ordinary) facts declared in one block.
///
/// `enforce` refuses context predicates; `include_ordinary` also returns the block's
/// other scalar facts (for human inspection).
pub fn block_facts(source: &str, enforce: bool, include_ordinary: bool) -> Result<BlockFacts> {
    let mut out = BlockFacts::default();
    for statement in statements(source)? {
        if statement.is_empty()
            || ["check ", "reject ", "allow ", "deny "]
                .iter()
                .any(|p| statement.starts_with(p))
        {
            continue;
        }
        let Some(name) = declaration_name(&statement) else {
            return Err(Error::value("unsupported block declaration"));
        };
        if enforce && is_context(name) {
            return Err(Error::value(format!("reserved context predicate: {name}")));
        }
        let fact = match Fact::try_from(statement.as_str()) {
            Ok(fact) => fact,
            Err(_) => {
                if is_governed(name) {
                    return Err(Error::value(format!(
                        "governed predicate cannot be a rule: {name}"
                    )));
                }
                continue; // a verified token's ordinary business rule; Biscuit evaluates it
            }
        };
        if !is_governed(name) && (!include_ordinary || has_collection(&statement)) {
            continue;
        }
        let terms = convert_terms(name, &fact)?;
        out.push(&fact.predicate.name, terms);
    }
    Ok(out)
}

/// Identity facts of the authority block, and every bound across the chain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Metadata {
    /// Identity fact name -> its single value (authority block only).
    pub identity: Vec<(String, String)>,
    pub budget_cap: Vec<i64>,
    pub max_delegation_depth: Vec<i64>,
    pub expires_at: Vec<DateTime<Utc>>,
}

impl Metadata {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.identity
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn to_json(&self) -> Value {
        let mut identity = serde_json::Map::new();
        for (name, value) in &self.identity {
            identity.insert(name.clone(), json!([value]));
        }
        json!([
            Value::Object(identity),
            {
                "budget_cap": self.budget_cap,
                "expires_at": self.expires_at.iter().map(|d| json!({"$date": py_isoformat(d)})).collect::<Vec<_>>(),
                "max_delegation_depth": self.max_delegation_depth,
            }
        ])
    }
}

pub fn metadata<S: AsRef<str>>(blocks: &[S]) -> Result<Metadata> {
    let mut meta = Metadata::default();
    for (index, source) in blocks.iter().enumerate() {
        let parsed = block_facts(source.as_ref(), true, false)?;
        for (name, facts) in &parsed.0 {
            if facts.len() != 1 || facts[0].len() != 1 {
                return Err(Error::value(format!(
                    "{name}: exactly one unary fact per block is required"
                )));
            }
            let value = &facts[0][0];
            if is_identity(name) {
                if index != 0 {
                    return Err(Error::value(format!(
                        "{name}: must originate in authority block"
                    )));
                }
                let text = match value {
                    Term::Str(s) => s.as_str(),
                    _ => {
                        return Err(Error::value(format!(
                            "{name}: expected a nonempty string without surrounding whitespace"
                        )));
                    }
                };
                string(text, name, if name == "issuer" { 4096 } else { 256 })?;
                let text = if name == "agent_pubkey" {
                    public_key(text)?
                } else {
                    text.to_owned()
                };
                if name == "required_profile" {
                    profiles::rank(&text)?;
                }
                meta.identity.retain(|(n, _)| n != name);
                meta.identity.push((name.clone(), text));
            } else if name == "expires_at" {
                match value.as_date() {
                    Some(date) => meta.expires_at.push(date),
                    None => return Err(Error::value("expires_at: expected a timezone-aware date")),
                }
            } else {
                let bound = match value {
                    Term::Int(i) if *i >= 0 && i128::from(*i) <= MAX_INTEGER => *i,
                    _ => {
                        return Err(Error::value(format!(
                            "{name}: expected integer in [0, {MAX_INTEGER}]"
                        )));
                    }
                };
                if name == "budget_cap" {
                    meta.budget_cap.push(bound);
                } else {
                    meta.max_delegation_depth.push(bound);
                }
            }
        }
    }
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statements_respect_quotes() {
        let parts = statements("a(\"x;y\");\nb(1);").unwrap();
        assert_eq!(parts, vec!["a(\"x;y\")", "b(1)"]);
        assert!(statements("a(\"x").is_err());
        assert!(statements("a(1)").is_err());
    }

    #[test]
    fn declaration_names() {
        assert_eq!(declaration_name("right(\"a\")"), Some("right"));
        assert_eq!(declaration_name("can_read ($r) <- x($r)"), Some("can_read"));
        assert_eq!(declaration_name("trusting authority"), None);
    }
}
