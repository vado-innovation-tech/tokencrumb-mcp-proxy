//! DPoP proof (RFC 9449) signed by the agent's Ed25519 key.
//!
//! An issuer that anchors mandates through DPoP (the Keycloak « Biscuit Emitter »
//! mapper in `hardened_biscuit_anchored`) reads the agent's public key from the proof
//! that accompanies the token request, instead of trusting a key the client merely
//! declares. The proof is a short JWT: the key in its header, the HTTP method and URL
//! it is valid for in its payload, signed with that same key. The private key never
//! leaves the agent.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use rand::RngCore as _;
use serde_json::json;

use crate::error::{Error, Result};
use crate::keys::{public_from_private, public_raw, sign};

/// A DPoP proof for one request (`htm`, `htu`), issued at `now`.
pub fn proof(private_str: &str, method: &str, url: &str, now: DateTime<Utc>) -> Result<String> {
    let method = method.trim().to_ascii_uppercase();
    if method.is_empty() || !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(Error::value("DPoP method must be an HTTP method name"));
    }
    let url = url.trim();
    if !(url.starts_with("https://") || url.starts_with("http://")) || url.contains(['?', '#']) {
        // RFC 9449 §4.2: htu carries no query nor fragment.
        return Err(Error::value(
            "DPoP URL must be http(s) without query or fragment",
        ));
    }
    let public = public_raw(&public_from_private(private_str)?)?;
    let mut jti = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut jti);
    let header = json!({
        "typ": "dpop+jwt",
        "alg": "EdDSA",
        "jwk": {"kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(public)},
    });
    let payload = json!({
        "jti": hex::encode(jti),
        "htm": method,
        "htu": url,
        "iat": now.timestamp(),
    });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(payload.to_string())
    );
    let signature = sign(private_str, signing_input.as_bytes())?;
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{generate_keypair, verify};
    use serde_json::Value;

    fn part(jwt: &str, index: usize) -> Value {
        let raw = URL_SAFE_NO_PAD
            .decode(jwt.split('.').nth(index).unwrap())
            .unwrap();
        serde_json::from_slice(&raw).unwrap()
    }

    #[test]
    fn proof_carries_the_agent_key_and_verifies_with_it() {
        let agent = generate_keypair();
        let now = DateTime::from_timestamp(1_791_200_000, 0).unwrap();
        let jwt = proof(
            &agent.private_str,
            "post",
            "http://127.0.0.1:8080/realms/r/protocol/openid-connect/token",
            now,
        )
        .unwrap();

        let header = part(&jwt, 0);
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "EdDSA");
        let x = URL_SAFE_NO_PAD
            .decode(header["jwk"]["x"].as_str().unwrap())
            .unwrap();
        assert_eq!(x, public_raw(&agent.public_str).unwrap());

        let payload = part(&jwt, 1);
        assert_eq!(payload["htm"], "POST");
        assert_eq!(payload["iat"], 1_791_200_000);
        assert_eq!(payload["jti"].as_str().unwrap().len(), 32);

        let (input, signature) = jwt.rsplit_once('.').unwrap();
        verify(
            &agent.public_str,
            &URL_SAFE_NO_PAD.decode(signature).unwrap(),
            input.as_bytes(),
        )
        .unwrap();
    }

    #[test]
    fn each_proof_is_unique() {
        let agent = generate_keypair();
        let now = Utc::now();
        let url = "https://issuer.example/token";
        assert_ne!(
            part(&proof(&agent.private_str, "POST", url, now).unwrap(), 1)["jti"],
            part(&proof(&agent.private_str, "POST", url, now).unwrap(), 1)["jti"]
        );
    }

    #[test]
    fn malformed_requests_are_refused() {
        let agent = generate_keypair();
        let now = Utc::now();
        for (method, url) in [
            ("", "https://i/t"),
            ("PO ST", "https://i/t"),
            ("POST", "ftp://i/t"),
            ("POST", "https://i/t?x=1"),
            ("POST", "https://i/t#f"),
        ] {
            assert!(
                proof(&agent.private_str, method, url, now).is_err(),
                "{method} {url}"
            );
        }
    }
}
