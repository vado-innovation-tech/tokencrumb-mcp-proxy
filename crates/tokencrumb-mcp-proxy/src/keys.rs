//! Ed25519 key material for TokenCrumb - MCP Proxy.
//!
//! Two key formats are used throughout, both textual and interoperable:
//!     - private: `ed25519-private/<64 hex>`  (biscuit PrivateKey string form)
//!     - public : `ed25519/<64 hex>`          (biscuit PublicKey  string form)
//!
//! The same raw 32-byte Ed25519 seed/point underlies both the Biscuit signature
//! chain and the per-call attestation / audit signatures. This module is the single
//! place that bridges the two, so the rest of the code never re-implements key parsing.

use std::path::Path;
use std::str::FromStr;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result, py_repr};

pub const PRIVATE_PREFIX: &str = "ed25519-private/";
pub const PUBLIC_PREFIX: &str = "ed25519/";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keypair {
    /// `ed25519-private/<hex>`
    pub private_str: String,
    /// `ed25519/<hex>`
    pub public_str: String,
}

pub fn generate_keypair() -> Keypair {
    let kp = biscuit_auth::KeyPair::new();
    Keypair {
        private_str: kp.private().to_prefixed_string(),
        public_str: kp.public().to_string(),
    }
}

/// A keypair from an explicit private key string.
pub fn keypair_from_private(private_str: &str) -> Result<Keypair> {
    Ok(Keypair {
        private_str: private_str.to_owned(),
        public_str: public_from_private(private_str)?,
    })
}

// --------------------------------------------------------------------------- //
// biscuit bridges
// --------------------------------------------------------------------------- //
pub fn biscuit_private(private_str: &str) -> Result<biscuit_auth::PrivateKey> {
    biscuit_auth::PrivateKey::from_str(private_str).map_err(Error::from)
}

pub fn biscuit_public(public_str: &str) -> Result<biscuit_auth::PublicKey> {
    biscuit_auth::PublicKey::from_str(public_str).map_err(Error::from)
}

pub fn biscuit_keypair(private_str: &str) -> Result<biscuit_auth::KeyPair> {
    Ok(biscuit_auth::KeyPair::from(&biscuit_private(private_str)?))
}

// --------------------------------------------------------------------------- //
// raw bytes (attestation + audit signatures)
// --------------------------------------------------------------------------- //
fn from_hex(text: &str) -> Result<Vec<u8>> {
    // `bytes.fromhex` skips ASCII whitespace between byte pairs.
    let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    hex::decode(&compact).map_err(|_| Error::value("non-hexadecimal number found in fromhex() arg"))
}

/// The raw 32-byte Ed25519 point from an `ed25519/<hex>` string.
pub fn public_raw(public_str: &str) -> Result<[u8; 32]> {
    let Some(hex_part) = public_str.strip_prefix(PUBLIC_PREFIX) else {
        return Err(Error::value(format!(
            "not an ed25519 public key: {}",
            py_repr(public_str)
        )));
    };
    from_hex(hex_part)?
        .try_into()
        .map_err(|_| Error::value("ed25519 public key must be 32 bytes"))
}

pub fn private_raw(private_str: &str) -> Result<[u8; 32]> {
    let Some(hex_part) = private_str.strip_prefix(PRIVATE_PREFIX) else {
        return Err(Error::value("not an ed25519 private key"));
    };
    from_hex(hex_part)?
        .try_into()
        .map_err(|_| Error::value("ed25519 private key must be 32 bytes"))
}

pub fn signing_key(private_str: &str) -> Result<SigningKey> {
    Ok(SigningKey::from_bytes(&private_raw(private_str)?))
}

pub fn verify_key(public_str: &str) -> Result<VerifyingKey> {
    VerifyingKey::from_bytes(&public_raw(public_str)?)
        .map_err(|_| Error::value("invalid ed25519 public key"))
}

pub fn sign(private_str: &str, message: &[u8]) -> Result<Vec<u8>> {
    Ok(signing_key(private_str)?.sign(message).to_bytes().to_vec())
}

/// Constant-time Ed25519 verification; any malformed input is a failure.
pub fn verify(public_str: &str, signature: &[u8], message: &[u8]) -> Result<()> {
    let key = verify_key(public_str)?;
    let signature = Signature::from_slice(signature).map_err(|_| Error::value(""))?;
    key.verify_strict(message, &signature)
        .map_err(|_| Error::value(""))
}

/// Derive the `ed25519/<hex>` public key from a private key string.
pub fn public_from_private(private_str: &str) -> Result<String> {
    Ok(format!(
        "{PUBLIC_PREFIX}{}",
        hex::encode(signing_key(private_str)?.verifying_key().to_bytes())
    ))
}

/// Short, stable identifier for a public key (16 hex of its SHA-256).
pub fn key_id(public_str: &str) -> Result<String> {
    Ok(hex::encode(Sha256::digest(public_raw(public_str)?))[..16].to_owned())
}

// --------------------------------------------------------------------------- //
// On-disk persistence (optional passphrase encryption)
// --------------------------------------------------------------------------- //
fn derive(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = scrypt::Params::new(15, 8, 1, 32).map_err(|e| Error::value(e.to_string()))?;
    let mut key = [0u8; 32];
    scrypt::scrypt(passphrase.as_bytes(), salt, &params, &mut key)
        .map_err(|e| Error::value(e.to_string()))?;
    Ok(key)
}

/// Persist a private key. With a passphrase, encrypt with scrypt + AES-GCM.
///
/// Plaintext storage requires filesystem access controls; the key ceremony in production should
/// target an HSM/KMS (documented in the README). Never commit key files.
pub fn save_private_key(
    path: impl AsRef<Path>,
    private_str: &str,
    passphrase: Option<&str>,
) -> Result<()> {
    match passphrase.filter(|p| !p.is_empty()) {
        Some(passphrase) => {
            let mut salt = [0u8; 16];
            let mut nonce = [0u8; 12];
            rand::rngs::OsRng.fill_bytes(&mut salt);
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let key = derive(passphrase, &salt)?;
            let cipher = Aes256Gcm::new_from_slice(&key).expect("32-byte key");
            let ct = cipher
                .encrypt(Nonce::from_slice(&nonce), private_str.as_bytes())
                .map_err(|_| Error::value("encryption failed"))?;
            let blob = json!({
                "enc": "scrypt-aesgcm",
                "salt": STANDARD.encode(salt),
                "nonce": STANDARD.encode(nonce),
                "ct": STANDARD.encode(ct),
            });
            crate::storage::write_secure(path, crate::json::dumps(&blob).as_bytes())
        }
        None => crate::storage::write_secure(path, private_str.as_bytes()),
    }
}

pub fn load_private_key(path: impl AsRef<Path>, passphrase: Option<&str>) -> Result<String> {
    let blob = std::fs::read(path)?;
    let text = String::from_utf8(blob.clone()).map_err(|e| Error::value(e.to_string()))?;
    let text = crate::validation::py_strip(&text);
    if text.starts_with(PRIVATE_PREFIX) {
        return Ok(text.to_owned());
    }
    let document: Value = serde_json::from_slice(&blob).map_err(|e| Error::value(e.to_string()))?;
    if document.get("enc").and_then(Value::as_str) != Some("scrypt-aesgcm") {
        return Err(Error::value("unknown private key encryption"));
    }
    let Some(passphrase) = passphrase.filter(|p| !p.is_empty()) else {
        return Err(Error::value(
            "private key is encrypted; a passphrase is required",
        ));
    };
    let field = |name: &str| -> Result<Vec<u8>> {
        let text = document
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| Error::value(format!("'{name}'")))?;
        STANDARD
            .decode(text)
            .map_err(|e| Error::value(e.to_string()))
    };
    let key = derive(passphrase, &field("salt")?)?;
    let cipher = Aes256Gcm::new_from_slice(&key).expect("32-byte key");
    let nonce = field("nonce")?;
    if nonce.len() != 12 {
        return Err(Error::value("invalid nonce length"));
    }
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), field("ct")?.as_slice())
        .map_err(|_| Error::value("private key decryption failed (wrong passphrase?)"))?;
    String::from_utf8(plaintext).map_err(|e| Error::value(e.to_string()))
}

pub fn save_public_key(path: impl AsRef<Path>, public_str: &str) -> Result<()> {
    std::fs::write(path, format!("{public_str}\n"))?;
    Ok(())
}

pub fn load_public_key(path: impl AsRef<Path>) -> Result<String> {
    let text = std::fs::read_to_string(path)?;
    Ok(crate::validation::py_strip(&text).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_forms_round_trip() {
        let kp = generate_keypair();
        assert!(kp.private_str.starts_with(PRIVATE_PREFIX));
        assert_eq!(public_from_private(&kp.private_str).unwrap(), kp.public_str);
        let sig = sign(&kp.private_str, b"m").unwrap();
        verify(&kp.public_str, &sig, b"m").unwrap();
        assert!(verify(&kp.public_str, &sig, b"n").is_err());
    }
}
