//! One error type for the whole library.
//!
//! The message is the contract: refusal reasons end up in the signed audit log and
//! are compared, word for word, against the reference corpus produced by the former
//! Python implementation. The kind only tells callers which family a failure
//! belongs to (a revocation failure is not a policy failure).

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Invalid value at a trust boundary (Python `ValueError`).
    Value,
    /// Resource string refused by canonicalization.
    Resource,
    /// Mapped call argument refused by canonicalization.
    Argument,
    /// `--fact` / `--scope-arg` specification refused.
    FactSpec,
    /// Human duration refused.
    Duration,
    /// Revocation snapshot refused.
    Revocation,
    /// Unrecoverable state problem (Python `RuntimeError`).
    Runtime,
    /// Missing file (Python `FileNotFoundError`).
    NotFound,
    /// Conflicting registration (Python `FileExistsError`).
    Exists,
    /// Filesystem or network failure (Python `OSError`).
    Io,
    /// Biscuit library failure.
    Biscuit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub message: String,
}

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn value(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Value, message)
    }

    pub fn runtime(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Runtime, message)
    }

    pub fn io(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Io, message)
    }

    pub fn is(&self, kind: ErrorKind) -> bool {
        self.kind == kind
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        let kind = match error.kind() {
            std::io::ErrorKind::NotFound => ErrorKind::NotFound,
            _ => ErrorKind::Io,
        };
        Self::new(kind, error.to_string())
    }
}

impl From<biscuit_auth::error::Token> for Error {
    fn from(error: biscuit_auth::error::Token) -> Self {
        Self::new(ErrorKind::Biscuit, error.to_string())
    }
}

impl From<biscuit_auth::error::Format> for Error {
    fn from(error: biscuit_auth::error::Format) -> Self {
        Self::new(ErrorKind::Biscuit, error.to_string())
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// `bail!(Value, "...")`-style shorthand used across the crate.
#[macro_export]
macro_rules! fail {
    ($kind:ident, $($arg:tt)*) => {
        return Err($crate::error::Error::new($crate::error::ErrorKind::$kind, format!($($arg)*)))
    };
}

/// Python's `repr()` of a string: the quoting the reference messages use.
pub fn py_repr(value: &str) -> String {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(value.len() + 2);
    out.push(quote);
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c if is_py_unprintable(c) => {
                let code = c as u32;
                if code <= 0xff {
                    out.push_str(&format!("\\x{code:02x}"));
                } else if code <= 0xffff {
                    out.push_str(&format!("\\u{code:04x}"));
                } else {
                    out.push_str(&format!("\\U{code:08x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Characters Python's `str.isprintable()` rejects beyond ASCII controls: C1 controls,
/// separators other than the ASCII space, and format characters commonly seen.
fn is_py_unprintable(c: char) -> bool {
    let code = c as u32;
    (0x80..=0xa0).contains(&code)
        || code == 0xad
        || code == 0x1680
        || (0x2000..=0x200f).contains(&code)
        || (0x2028..=0x202f).contains(&code)
        || (0x205f..=0x206f).contains(&code)
        || code == 0x3000
        || code == 0xfeff
        || (0xfff9..=0xfffb).contains(&code)
        || (0xd800..=0xdfff).contains(&code)
}

#[cfg(test)]
mod tests {
    use super::py_repr;

    #[test]
    fn repr_matches_python() {
        assert_eq!(py_repr("x"), "'x'");
        assert_eq!(py_repr("it's"), "\"it's\"");
        assert_eq!(py_repr("a'b\"c"), "'a\\'b\"c'");
        assert_eq!(py_repr("a\u{0}b"), "'a\\x00b'");
        assert_eq!(py_repr("é"), "'é'");
    }
}
