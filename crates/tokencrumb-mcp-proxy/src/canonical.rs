//! Canonicalization primitives.
//!
//! Two independent concerns, both security-critical:
//!
//! 1. **Argument canonicalization** (RFC 8785 / JCS) — a deterministic byte string
//!    for the MCP tool arguments, so that `arguments_hash` is reproducible on both
//!    the signer (client-wrap) and the verifier (proxy).
//!
//! 2. **Resource canonicalization** — neutralize path traversal (`../`, `%2e%2e`),
//!    double percent-encoding, and Unicode tricks *before* any `starts_with` prefix
//!    check. The exact same function MUST be applied to the incoming resource AND to
//!    the policy's declared prefix, otherwise a prefix check is bypassable.

use serde_json::Value;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::error::{Error, ErrorKind, Result, py_repr};
use crate::json;
use crate::validation::py_strip;

fn resource_error(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::Resource, message)
}

fn argument_error(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::Argument, message)
}

/// RFC 8785 JCS canonical JSON as UTF-8 bytes.
pub fn canonicalize(value: &Value) -> Result<Vec<u8>> {
    json::canonicalize(value)
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// SHA-256 (hex) of the JCS-canonical arguments, all business arguments included.
pub fn arguments_hash(arguments: &Value) -> Result<String> {
    if !arguments.is_object() {
        return Err(Error::value("arguments must be a JSON object"));
    }
    Ok(sha256_hex(&canonicalize(arguments)?))
}

/// `urllib.parse.unquote` (UTF-8, `errors="replace"`): ASCII runs are percent-decoded
/// to bytes and decoded as UTF-8; non-ASCII text passes through untouched.
pub fn py_unquote(s: &str) -> String {
    if !s.contains('%') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if !run.is_empty() {
            out.push_str(&String::from_utf8_lossy(&unquote_to_bytes(run)));
            run.clear();
        }
    };
    for c in s.chars() {
        if c.is_ascii() {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

fn unquote_to_bytes(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            let hi = (bytes[i + 1] as char).to_digit(16).expect("hex");
            let lo = (bytes[i + 2] as char).to_digit(16).expect("hex");
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

/// Percent-decode repeatedly to defeat double/triple encoding (e.g. `%252e`).
fn percent_decode_stable(s: &str) -> Result<String> {
    let mut current = s.to_owned();
    for _ in 0..5 {
        let decoded = py_unquote(&current);
        if decoded == current {
            return Ok(current);
        }
        current = decoded;
    }
    Err(resource_error("excessive percent-encoding"))
}

/// `posixpath.normpath`.
pub fn normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let mut initial_slashes = usize::from(path.starts_with('/'));
    if initial_slashes == 1 && path.starts_with("//") && !path.starts_with("///") {
        initial_slashes = 2;
    }
    let mut components: Vec<&str> = Vec::new();
    for component in path.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component != ".."
            || (initial_slashes == 0 && components.is_empty())
            || components.last() == Some(&"..")
        {
            components.push(component);
        } else if !components.is_empty() {
            components.pop();
        }
    }
    let joined = format!("{}{}", "/".repeat(initial_slashes), components.join("/"));
    if joined.is_empty() {
        ".".into()
    } else {
        joined
    }
}

/// A canonical, traversal-safe resource string.
///
/// - percent-decode (defeats `%2e%2e` / double-encoding)
/// - Unicode NFC normalization
/// - for path-like resources (containing `/`): resolve `.` / `..` and reject anything
///   that escapes the root
pub fn canonicalize_resource(raw: &str) -> Result<String> {
    if raw.is_empty() {
        return Err(resource_error("resource must be a nonempty string"));
    }
    if raw.contains('\0') {
        return Err(resource_error("null byte in resource"));
    }
    let decoded = percent_decode_stable(raw)?;
    let mut s: String = decoded.nfc().collect();
    if s.contains('\0') || s.contains('\\') || s.starts_with("//") {
        return Err(resource_error("invalid resource separator or null byte"));
    }
    if s.contains('/') || s.starts_with("..") {
        let collapsed = normpath(&s);
        // normpath resolves .. — an absolute path can never escape to `../`, but a
        // relative one can; reject those outright.
        if collapsed == ".." || collapsed.starts_with("../") {
            return Err(resource_error(format!(
                "path traversal rejected: {}",
                py_repr(raw)
            )));
        }
        s = collapsed;
    }
    Ok(s)
}

/// [`canonicalize_resource`] for an untyped value: anything but a nonempty string is
/// refused with the same message.
pub fn canonicalize_resource_value(raw: &Value) -> Result<String> {
    match raw {
        Value::String(s) => canonicalize_resource(s),
        _ => Err(resource_error("resource must be a nonempty string")),
    }
}

fn is_arg_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-')
}

/// Canonicalize a mapped call argument for comparison against a signed fact.
///
/// This is NOT [`canonicalize_resource`]: that one is path-oriented and would happily
/// rewrite `INC-1/../INC-2` into `INC-2`. A business identifier has no path semantics,
/// so the rule here is a strict allowlist instead of a normalization: anything outside
/// `[A-Za-z0-9._:-]` is rejected rather than repaired.
///
/// Case is preserved and compared exactly — `inc-123` and `INC-123` are two different
/// identifiers, so an alias attempt is a DENY, not a silent match.
pub fn canonicalize_arg(raw: &Value) -> Result<String> {
    let text = match raw {
        Value::Null => return Err(argument_error("argument is required")),
        Value::String(s) => s,
        other => {
            return Err(argument_error(format!(
                "unsupported argument type: {}",
                json::py_type_name(other)
            )));
        }
    };
    let normalized: String = text.nfc().collect();
    if &normalized != text || py_strip(&normalized) != normalized {
        return Err(argument_error("noncanonical argument value"));
    }
    let count = normalized.chars().count();
    if !(1..=128).contains(&count) || !normalized.chars().all(is_arg_char) {
        return Err(argument_error(format!(
            "malformed argument value: {}",
            py_repr(text)
        )));
    }
    Ok(normalized)
}

/// Canonical resource *prefix* — same rules as a resource but the trailing `/` is
/// preserved so `starts_with` cannot cross a directory boundary (`/projets/acme/` must
/// not match `/projets/acme2`).
pub fn canonicalize_prefix(raw: &str) -> Result<String> {
    let mut canon = canonicalize_resource(raw)?;
    if canon.contains('/') && !canon.ends_with('/') {
        canon.push('/');
    }
    Ok(canon)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normpath_matches_posixpath() {
        for (input, want) in [
            ("", "."),
            ("/a//b", "/a/b"),
            ("a/../..", ".."),
            ("/../x", "/x"),
            ("//x", "//x"),
            ("///x", "/x"),
            ("a/b/../c", "a/c"),
            ("./x", "x"),
            ("x/", "x"),
        ] {
            assert_eq!(normpath(input), want, "{input}");
        }
    }

    #[test]
    fn unquote_matches_urllib() {
        assert_eq!(py_unquote("%2e%2E"), "..");
        assert_eq!(py_unquote("%zz"), "%zz");
        assert_eq!(py_unquote("%C3%A9"), "é");
        assert_eq!(py_unquote("%C3"), "\u{fffd}");
        assert_eq!(py_unquote("é%41"), "éA");
    }
}
