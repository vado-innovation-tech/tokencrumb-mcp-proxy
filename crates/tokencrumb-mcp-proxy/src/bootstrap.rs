//! Verify an issuer response against a separately provisioned public trust anchor.
//!
//! The exchange with an issuer (Keycloak SPI, Java issuer) returns a mandate; the
//! response is only a transport. The authority public key it must verify against is
//! provisioned beforehand through a trusted channel, so an issuer — or anyone on the
//! path — can never substitute its own trust anchor.

use biscuit_auth::Biscuit;
use serde_json::Value;

use crate::biscuit_ops::verified_block_sources;
use crate::error::{Error, Result};
use crate::json::strict_json;
use crate::keys::biscuit_public;
use crate::token_contract::metadata;

/// The parts of Python's `urlsplit` the issuer check reads.
struct Split {
    scheme: String,
    username: Option<String>,
    password: Option<String>,
    fragment: String,
    hostname: Option<String>,
}

const SCHEME_CHARS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-.";

/// `urllib.parse.urlsplit`, reduced to what [`validate_issuer_url`] needs.
fn urlsplit(url: &str) -> Result<Split> {
    // WHATWG-unsafe bytes are dropped and leading C0/space stripped, as Python does.
    let cleaned: String = url
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut rest = cleaned.as_str();
    let mut scheme = String::new();
    if let Some(colon) = rest.find(':') {
        let candidate = &rest[..colon];
        if colon > 0
            && candidate.starts_with(|c: char| c.is_ascii_alphabetic())
            && candidate.chars().all(|c| SCHEME_CHARS.contains(c))
        {
            scheme = candidate.to_ascii_lowercase();
            rest = &rest[colon + 1..];
        }
    }
    let mut netloc = "";
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        netloc = &after[..end];
        rest = &after[end..];
        if netloc.contains('[') != netloc.contains(']') {
            return Err(Error::value("Invalid IPv6 URL"));
        }
    }
    let fragment = rest
        .split_once('#')
        .map(|(_, f)| f.to_owned())
        .unwrap_or_default();

    let (username, password) = match netloc.rsplit_once('@') {
        Some((userinfo, _)) => match userinfo.split_once(':') {
            Some((user, pass)) => (Some(user.to_owned()), Some(pass.to_owned())),
            None => (Some(userinfo.to_owned()), None),
        },
        None => (None, None),
    };
    let hostinfo = netloc.rsplit_once('@').map_or(netloc, |(_, h)| h);
    let host = if let Some(bracketed) = hostinfo.strip_prefix('[') {
        bracketed.split_once(']').map_or("", |(h, _)| h)
    } else {
        hostinfo.split_once(':').map_or(hostinfo, |(h, _)| h)
    };
    let hostname = (!host.is_empty()).then(|| host.to_ascii_lowercase());
    Ok(Split {
        scheme,
        username,
        password,
        fragment,
        hostname,
    })
}

/// Refuse an issuer URL that would leak credentials or be ambiguous.
///
/// No userinfo (credentials in a URL end up in logs), no fragment, a hostname, and
/// HTTPS everywhere except loopback — the exchange carries the analyst's JWT.
pub fn validate_issuer_url(url: &str) -> Result<()> {
    let parsed = urlsplit(url)?;
    let nonempty = |value: &Option<String>| value.as_deref().is_some_and(|v| !v.is_empty());
    if nonempty(&parsed.username)
        || nonempty(&parsed.password)
        || !parsed.fragment.is_empty()
        || parsed.hostname.is_none()
    {
        return Err(Error::value("invalid issuer URL"));
    }
    let loopback = matches!(
        parsed.hostname.as_deref(),
        Some("127.0.0.1" | "localhost" | "::1")
    );
    if parsed.scheme != "https" && !(parsed.scheme == "http" && loopback) {
        return Err(Error::value(
            "issuer credentials require HTTPS outside loopback",
        ));
    }
    Ok(())
}

/// Extract the mandate from an issuer response, verified against the pre-provisioned
/// authority key; the issuer must have signed an expiry.
pub fn accept_exchange(raw: &[u8], authority_public: &str) -> Result<String> {
    let document = strict_json(raw)?;
    let Some(Value::String(token_b64)) = document.as_object().and_then(|d| d.get("biscuit")) else {
        return Err(Error::value("invalid issuer response"));
    };
    let token = Biscuit::from_base64(token_b64, biscuit_public(authority_public)?)?;
    let bounds = metadata(&verified_block_sources(&token)?)?;
    if bounds.expires_at.is_empty() {
        return Err(Error::value("issuer did not sign expires_at"));
    }
    Ok(token_b64.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlsplit_matches_python() {
        let s = urlsplit("https://user:pw@Issuer.Example:8443/p?q#frag").unwrap();
        assert_eq!(s.scheme, "https");
        assert_eq!(s.username.as_deref(), Some("user"));
        assert_eq!(s.password.as_deref(), Some("pw"));
        assert_eq!(s.hostname.as_deref(), Some("issuer.example"));
        assert_eq!(s.fragment, "frag");
        let s = urlsplit("http://[::1]:8080/x").unwrap();
        assert_eq!(s.hostname.as_deref(), Some("::1"));
        assert!(urlsplit("https:issuer").unwrap().hostname.is_none());
    }
}
