//! ISO 8601 timestamps with the semantics of Python's `datetime`.
//!
//! The attestation timestamp and the audit `ts` field were produced and parsed by
//! `datetime.isoformat()` / `datetime.fromisoformat()`; this module keeps both
//! directions identical so old and new signers and verifiers interoperate.

use chrono::{DateTime, FixedOffset, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};

use crate::error::{Error, Result, py_repr};

/// `datetime.now(UTC).isoformat()` with `+00:00` shortened to `Z` (audit, attestation).
pub fn iso_z(value: &DateTime<Utc>) -> String {
    py_isoformat(value).replace("+00:00", "Z")
}

/// `datetime.isoformat()` for a UTC datetime (`+00:00`, microseconds only when set).
pub fn py_isoformat(value: &DateTime<Utc>) -> String {
    let micros = value.timestamp_subsec_micros();
    if micros == 0 {
        value.format("%Y-%m-%dT%H:%M:%S+00:00").to_string()
    } else {
        format!("{}.{micros:06}+00:00", value.format("%Y-%m-%dT%H:%M:%S"))
    }
}

/// Result of `datetime.fromisoformat`: aware or naive.
pub enum Parsed {
    Aware(DateTime<FixedOffset>),
    Naive(NaiveDateTime),
}

fn digits(s: &str, n: usize) -> Option<(u32, &str)> {
    if s.len() < n || !s.as_bytes()[..n].iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some((s[..n].parse().ok()?, &s[n..]))
}

fn parse_date(s: &str) -> Option<(NaiveDate, &str)> {
    let (year, rest) = digits(s, 4)?;
    let (month, rest, extended) = match rest.strip_prefix('-') {
        Some(r) => {
            let (m, r) = digits(r, 2)?;
            (m, r, true)
        }
        None => {
            let (m, r) = digits(rest, 2)?;
            (m, r, false)
        }
    };
    let rest = if extended {
        rest.strip_prefix('-')?
    } else {
        rest
    };
    let (day, rest) = digits(rest, 2)?;
    Some((NaiveDate::from_ymd_opt(year as i32, month, day)?, rest))
}

fn parse_time(s: &str) -> Option<(NaiveTime, &str)> {
    let (hour, mut rest) = digits(s, 2)?;
    let extended = rest.starts_with(':');
    let next = |r: &'_ str| -> Option<(u32, usize)> {
        let skip = usize::from(extended);
        if extended && !r.starts_with(':') {
            return None;
        }
        let (v, _) = digits(&r[skip..], 2)?;
        Some((v, skip + 2))
    };
    let (mut minute, mut second, mut nanos) = (0, 0, 0);
    if let Some((m, used)) = next(rest) {
        minute = m;
        rest = &rest[used..];
        if let Some((sec, used)) = next(rest) {
            second = sec;
            rest = &rest[used..];
            if let Some(frac) = rest.strip_prefix(['.', ',']) {
                let count = frac.bytes().take_while(u8::is_ascii_digit).count();
                if count == 0 {
                    return None;
                }
                // Python keeps microseconds: anything beyond 6 digits is truncated.
                let mut padded: String = frac[..count.min(6)].to_owned();
                while padded.len() < 9 {
                    padded.push('0');
                }
                nanos = padded.parse().ok()?;
                rest = &frac[count..];
            }
        }
    }
    Some((
        NaiveTime::from_hms_nano_opt(hour, minute, second, nanos)?,
        rest,
    ))
}

fn parse_offset(s: &str) -> Option<FixedOffset> {
    if s == "Z" {
        return FixedOffset::east_opt(0);
    }
    let (sign, body) = match s.chars().next()? {
        '+' => (1, &s[1..]),
        '-' => (-1, &s[1..]),
        _ => return None,
    };
    let (time, rest) = parse_time(body)?;
    if !rest.is_empty() {
        return None;
    }
    use chrono::Timelike;
    let seconds = time.hour() * 3600 + time.minute() * 60 + time.second();
    FixedOffset::east_opt(sign * seconds as i32)
}

/// `datetime.fromisoformat(text)`.
pub fn fromisoformat(text: &str) -> Result<Parsed> {
    let invalid = || Error::value(format!("Invalid isoformat string: {}", py_repr(text)));
    let (date, rest) = parse_date(text).ok_or_else(invalid)?;
    if rest.is_empty() {
        return Ok(Parsed::Naive(date.and_hms_opt(0, 0, 0).expect("midnight")));
    }
    // Any single character separates date and time.
    let mut chars = rest.chars();
    chars.next();
    let rest = chars.as_str();
    let (time, rest) = parse_time(rest).ok_or_else(invalid)?;
    let naive = NaiveDateTime::new(date, time);
    if rest.is_empty() {
        return Ok(Parsed::Naive(naive));
    }
    let offset = parse_offset(rest).ok_or_else(invalid)?;
    let aware = offset
        .from_local_datetime(&naive)
        .single()
        .ok_or_else(invalid)?;
    Ok(Parsed::Aware(aware))
}

/// Seconds (with fraction) since the UNIX epoch, as `datetime.timestamp()`.
pub fn timestamp(value: &DateTime<impl TimeZone>) -> f64 {
    value.timestamp() as f64 + f64::from(value.timestamp_subsec_micros()) / 1e6
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_variants() {
        let now = DateTime::parse_from_rfc3339("2026-09-29T10:00:00.123456Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(iso_z(&now), "2026-09-29T10:00:00.123456Z");
        for text in [
            "2026-09-29T10:00:00Z",
            "2026-09-29 10:00:00+02:00",
            "20260929T100000Z",
            "2026-09-29T10:00:00.1234567+00:00",
        ] {
            assert!(
                matches!(fromisoformat(text).unwrap(), Parsed::Aware(_)),
                "{text}"
            );
        }
        assert!(matches!(
            fromisoformat("2026-09-29T10:00:00").unwrap(),
            Parsed::Naive(_)
        ));
        assert!(fromisoformat("yesterday").is_err());
    }
}
