//! Code Mode scripts seen by the gateway (ADR 0007, points 10 and 14).
//!
//! A Code Mode client tags every call a script makes with two headers: a random run id
//! and the SHA-256 of the script. It also registers the script once with the
//! `tokencrumb/script` request, so the full code enters the signed audit; every call
//! entry then carries the run id and the hash.
//!
//! Per run, the gateway remembers which upstreams the script has already called
//! successfully. A call to an upstream the policy's `flows` forbid after one of those is
//! refused. The state is bounded, expires and is keyed by the mandate as well as the run
//! id, so one caller cannot taint another's run.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::verifier::Headers;

pub const RUN_HEADER: &str = "tokencrumb-script-run";
pub const HASH_HEADER: &str = "tokencrumb-script-hash";
/// The request registering a script's code; answered by the gateway, never forwarded.
pub const REGISTER_METHOD: &str = "tokencrumb/script";
/// Largest script accepted for registration.
pub const MAX_CODE: usize = 256 * 1024;

const RUN_TTL: Duration = Duration::from_secs(15 * 60);
const MAX_RUNS: usize = 4096;

/// One script run, as identified by its client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptId {
    /// 32 lowercase hexadecimal characters, random per run.
    pub run: String,
    /// `sha256:` followed by 64 lowercase hexadecimal characters.
    pub hash: String,
}

impl ScriptId {
    pub fn new(run: &str, hash: &str) -> Option<Self> {
        let hex = |s: &str, n: usize| {
            s.len() == n && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        };
        let digest = hash.strip_prefix("sha256:")?;
        (hex(run, 32) && hex(digest, 64)).then(|| Self {
            run: run.to_owned(),
            hash: hash.to_owned(),
        })
    }

    /// `Ok(None)` without the headers; `Err` when only one is present or either is
    /// malformed.
    pub fn from_headers(headers: &Headers) -> crate::Result<Option<Self>> {
        match (headers.get(RUN_HEADER), headers.get(HASH_HEADER)) {
            (None, None) => Ok(None),
            (Some(run), Some(hash)) => Self::new(run, hash)
                .map(Some)
                .ok_or_else(|| crate::Error::value("malformed script headers")),
            _ => Err(crate::Error::value("malformed script headers")),
        }
    }

    pub fn audit_detail(&self) -> Value {
        json!({"run": self.run, "hash": self.hash})
    }
}

/// `(mandate hash, run id)`.
type Key = (String, String);

struct Run {
    touched: Vec<String>,
    expires: Instant,
}

#[derive(Default)]
pub struct Scripts {
    order: VecDeque<Key>,
    runs: HashMap<Key, Run>,
}

impl Scripts {
    fn purge(&mut self, now: Instant) {
        while let Some(key) = self.order.front() {
            match self.runs.get(key) {
                Some(run) if run.expires > now && self.runs.len() <= MAX_RUNS => break,
                _ => {
                    let key = self.order.pop_front().expect("front");
                    self.runs.remove(&key);
                }
            }
        }
    }

    /// The upstreams this run has already called successfully.
    pub fn touched(&mut self, owner: &str, run: &str, now: Instant) -> Vec<String> {
        self.purge(now);
        self.runs
            .get(&(owner.to_owned(), run.to_owned()))
            .map(|r| r.touched.clone())
            .unwrap_or_default()
    }

    /// Record a successful call to `upstream` within the run.
    pub fn touch(&mut self, owner: &str, run: &str, upstream: &str, now: Instant) {
        self.purge(now);
        let key = (owner.to_owned(), run.to_owned());
        let entry = self.runs.entry(key.clone()).or_insert_with(|| {
            self.order.push_back(key);
            Run {
                touched: Vec::new(),
                expires: now + RUN_TTL,
            }
        });
        if !entry.touched.iter().any(|u| u == upstream) {
            entry.touched.push(upstream.to_owned());
        }
        self.purge(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUN: &str = "0123456789abcdef0123456789abcdef";

    fn hash() -> String {
        format!("sha256:{}", "ab".repeat(32))
    }

    #[test]
    fn ids_are_strict() {
        assert!(ScriptId::new(RUN, &hash()).is_some());
        assert!(ScriptId::new(&RUN.to_uppercase(), &hash()).is_none());
        assert!(ScriptId::new(RUN, &"ab".repeat(32)).is_none());
        assert!(ScriptId::new(&RUN[1..], &hash()).is_none());
        let only_run = Headers::new([(RUN_HEADER, RUN)]);
        assert!(ScriptId::from_headers(&only_run).is_err());
        assert_eq!(
            ScriptId::from_headers(&Headers::new::<&str, &str>([])),
            Ok(None)
        );
    }

    #[test]
    fn runs_are_per_mandate_and_expire() {
        let mut scripts = Scripts::default();
        let now = Instant::now();
        scripts.touch("alice", RUN, "kdrive", now);
        scripts.touch("alice", RUN, "kdrive", now);
        assert_eq!(scripts.touched("alice", RUN, now), ["kdrive"]);
        assert!(scripts.touched("mallory", RUN, now).is_empty());
        assert!(scripts.touched("alice", RUN, now + RUN_TTL).is_empty());
    }

    #[test]
    fn the_state_is_bounded() {
        let mut scripts = Scripts::default();
        let now = Instant::now();
        for i in 0..MAX_RUNS + 10 {
            scripts.touch("a", &format!("{i:032x}"), "x", now);
        }
        assert_eq!(scripts.runs.len(), MAX_RUNS);
        assert!(scripts.touched("a", &format!("{:032x}", 0), now).is_empty());
    }
}
