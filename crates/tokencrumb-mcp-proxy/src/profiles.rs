//! Security profiles and anti-downgrade ordering.
//!
//! native                     (1) — bearer Biscuit only
//! registry_backed            (3a) — per-call attestation, agent key via registry
//! hardened_biscuit_anchored  (3b) — per-call attestation, agent key anchored in Biscuit

use crate::error::{Error, Result, py_repr};

pub const NATIVE: &str = "native";
pub const REGISTRY: &str = "registry_backed";
pub const HARDENED: &str = "hardened_biscuit_anchored";

pub fn rank(profile: &str) -> Result<u8> {
    match profile {
        NATIVE => Ok(1),
        REGISTRY => Ok(2),
        HARDENED => Ok(3),
        other => Err(Error::value(format!(
            "unknown security profile: {}",
            py_repr(other)
        ))),
    }
}

/// True if `presented` satisfies (>=) `required` — anti-downgrade.
pub fn at_least(presented: &str, required: &str) -> Result<bool> {
    Ok(rank(presented)? >= rank(required)?)
}

/// The profile actually presented on the call.
///
/// - no attestation                        -> native (profile 1)
/// - attestation + key anchored in Biscuit -> hardened_biscuit_anchored (3b)
/// - attestation + registry configured     -> registry_backed (3a)
/// - attestation but no key source         -> native here; the verifier refuses the
///   unusable attestation
pub fn detect_presented(
    has_attestation: bool,
    anchored_pubkey: Option<&str>,
    registry_enabled: bool,
) -> &'static str {
    if !has_attestation {
        return NATIVE;
    }
    if anchored_pubkey.is_some_and(|k| !k.is_empty()) {
        return HARDENED;
    }
    if registry_enabled {
        return REGISTRY;
    }
    NATIVE
}
