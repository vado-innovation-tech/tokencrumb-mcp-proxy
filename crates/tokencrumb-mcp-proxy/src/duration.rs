//! Human durations -> seconds.
//!
//! Shared by the CLI (`--ttl 8h`) and by `policy.yaml` (`max_ttl: 8h`), so the two
//! never drift into accepting different spellings of the same thing.

use crate::error::{Error, ErrorKind, Result, py_repr};
use crate::validation::{py_isspace, py_strip};

/// `"15m"` -> 900, `"8h"` -> 28800, `"300"` -> 300 (bare number = seconds).
pub fn parse_duration(text: &str) -> Result<i128> {
    parse(py_strip(text)).ok_or_else(|| {
        Error::new(
            ErrorKind::Duration,
            format!(
                "invalid duration: {} (use e.g. 300s, 15m, 8h, 1d)",
                py_repr(text)
            ),
        )
    })
}

fn parse(text: &str) -> Option<i128> {
    let digits_end = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    if digits_end == 0 {
        return None;
    }
    let digits = &text[..digits_end];
    let rest = text[digits_end..].trim_start_matches(py_isspace);
    let unit = match rest {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return None,
    };
    // A number too large for any bound is kept as the largest integer: the caller's
    // range check then refuses it with its own message, as the unbounded original did.
    let value = digits
        .bytes()
        .try_fold(0_i128, |acc, b| {
            acc.checked_mul(10)?.checked_add(i128::from(b - b'0'))
        })
        .unwrap_or(i128::MAX);
    Some(value.saturating_mul(unit))
}

#[cfg(test)]
mod tests {
    use super::parse_duration;

    #[test]
    fn spellings() {
        assert_eq!(parse_duration("15m").unwrap(), 900);
        assert_eq!(parse_duration(" 8h ").unwrap(), 28800);
        assert_eq!(parse_duration("8 h").unwrap(), 28800);
        assert_eq!(parse_duration("300").unwrap(), 300);
        assert_eq!(
            parse_duration("1.5h").unwrap_err().message,
            "invalid duration: '1.5h' (use e.g. 300s, 15m, 8h, 1d)"
        );
    }
}
