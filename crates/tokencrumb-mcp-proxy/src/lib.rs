//! TokenCrumb - MCP Proxy — MCP authorization proxy (TokenCrumb data plane).
//!
//! A proxy placed in front of an unmodified MCP server: it verifies a Biscuit
//! capability on every tool call, allows or refuses, and records a verifiable,
//! signed audit trail.

pub mod attestation;
pub mod audit;
pub mod biscuit_ops;
pub mod budget;
pub mod canonical;
pub mod duration;
pub mod error;
pub mod isotime;
pub mod json;
pub mod keys;
pub mod net;
pub mod nonce_cache;
pub mod policy;
pub mod profiles;
pub mod proxy;
pub mod revocation;
pub mod storage;
pub mod token_contract;
pub mod validation;
pub mod verifier;
pub mod yaml11;

pub use error::{Error, ErrorKind, Result};
