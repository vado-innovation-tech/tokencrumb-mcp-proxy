//! Per-capability call budgets, tracked LOCALLY at the proxy (never in the token).
//!
//! Two counters per mandate (architecture decision 5): a **global** one, and one **per tool**. A call
//! is refused as soon as either is exhausted. Both are keyed off the authority block's
//! revocation id (stable across attenuations of the same forged capability); the
//! per-tool counter appends the tool name to that key.
//!
//! Ceilings come from different places. The global ceiling is the minimum `budget_cap`
//! across all blocks (monotonic: an attenuation may lower it, never raise it), floored
//! by `budget_total` in `policy.yaml`. The per-tool ceiling is the tool's own `budget`
//! in the policy. Keeping the counters separate is what makes those two numbers mean
//! what they say — a single shared counter let reads exhaust a write budget.
//!
//! `serve` uses a persistent file by default; [`BudgetStore::in_memory`] is the
//! embedded API. File-backed transactions serialize local processes on one POSIX
//! filesystem; independent volumes are not a distributed budget.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use serde_json::{Value, json};

use crate::error::{Error, Result, py_repr};
use crate::json::strict_json;
use crate::storage::{FileLock, atomic_json};
use crate::validation::{MAX_INTEGER, integer, integer_value};

pub const CAPACITY: usize = 100_000;

#[derive(Debug, Default, Clone)]
struct State {
    used: BTreeMap<String, i128>,
    expires: BTreeMap<String, i128>,
    clock: i128,
    seen: bool,
}

pub struct BudgetStore {
    pub path: Option<PathBuf>,
    state: Mutex<State>,
}

/// An open transaction: the process lock and, for a file store, the file lock, with
/// the state freshly reloaded from disk. Every check and charge of one call happens
/// inside one transaction.
pub struct BudgetTx<'a> {
    store: &'a BudgetStore,
    state: MutexGuard<'a, State>,
    _lock: Option<FileLock>,
}

fn load(path: &Path, state: &mut State) -> Result<()> {
    let raw = match std::fs::read(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if state.seen {
                return Err(Error::runtime("budget state disappeared"));
            }
            return Ok(());
        }
        Err(e) => {
            return Err(Error::runtime(format!(
                "unreadable budget state {}: {e}",
                py_repr(&path.display().to_string())
            )));
        }
    };
    let data = strict_json(&raw).map_err(|e| {
        Error::runtime(format!(
            "unreadable budget state {}: {e}",
            py_repr(&path.display().to_string())
        ))
    })?;
    state.seen = true;
    let Value::Object(document) = &data else {
        return Err(Error::runtime(format!(
            "invalid budget state in {}: expected an object",
            py_repr(&path.display().to_string())
        )));
    };
    let counters = if let Some(version) = document.get("version") {
        let version = crate::json::as_integer(version).filter(|v| *v == 1 || *v == 2);
        let Some(version) = version else {
            return Err(Error::runtime("unsupported budget state schema"));
        };
        let allowed: &[&str] = if version == 1 {
            &["version", "used"]
        } else {
            &["version", "used", "expires", "clock"]
        };
        let keys: std::collections::BTreeSet<&str> = document.keys().map(String::as_str).collect();
        if keys != allowed.iter().copied().collect() {
            return Err(Error::runtime("unsupported budget state fields"));
        }
        state.clock = match document.get("clock") {
            Some(v) => integer_value(v, "budget clock", 0, MAX_INTEGER)?,
            None => 0,
        };
        state.expires = match document.get("expires") {
            None => BTreeMap::new(),
            Some(Value::Object(map)) => map
                .iter()
                .map(|(k, v)| {
                    Ok((
                        k.clone(),
                        integer_value(v, "budget expiration", 0, MAX_INTEGER)?,
                    ))
                })
                .collect::<Result<_>>()?,
            Some(_) => return Err(Error::runtime("invalid budget expirations")),
        };
        document.get("used").cloned().unwrap_or(Value::Null)
    } else {
        data.clone()
    };
    let Value::Object(counters) = counters else {
        return Err(Error::runtime("invalid budget counters"));
    };
    if counters.len() > CAPACITY {
        return Err(Error::value("budget state capacity exceeded"));
    }
    state.used = counters
        .iter()
        .map(|(k, v)| {
            Ok((
                k.clone(),
                integer_value(v, "budget counter", 0, MAX_INTEGER)?,
            ))
        })
        .collect::<Result<_>>()?;
    if state.expires.keys().any(|k| !state.used.contains_key(k)) {
        return Err(Error::value("orphan budget expiry"));
    }
    Ok(())
}

impl BudgetStore {
    pub fn in_memory() -> Self {
        Self {
            path: None,
            state: Mutex::new(State::default()),
        }
    }

    /// A file-backed store. Fail-closed: a corrupt state file stops the proxy rather
    /// than silently resetting every budget to zero.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let mut state = State::default();
        load(&path, &mut state)?;
        Ok(Self {
            path: Some(path),
            state: Mutex::new(state),
        })
    }

    pub fn transaction(&self) -> Result<BudgetTx<'_>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::runtime("budget lock poisoned"))?;
        let lock = match &self.path {
            Some(path) => {
                let lock = FileLock::acquire(path)?;
                load(path, &mut state)?;
                Some(lock)
            }
            None => None,
        };
        Ok(BudgetTx {
            store: self,
            state,
            _lock: lock,
        })
    }

    pub fn remaining(&self, cap_key: &str, ceiling: i128) -> Result<i128> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::runtime("budget lock poisoned"))?;
        Ok(ceiling - state.used.get(cap_key).copied().unwrap_or(0))
    }

    /// Advance the clock and forget expired counters, persisting the result.
    pub fn prepare(&self, now: i128) -> Result<()> {
        let mut tx = self.transaction()?;
        tx.prepare(now)?;
        tx.flush()
    }

    pub fn consume(&self, keys: &[&str], expires_at: Option<i128>) -> Result<()> {
        self.transaction()?.consume(keys, expires_at)
    }
}

impl BudgetTx<'_> {
    pub fn remaining(&self, cap_key: &str, ceiling: i128) -> i128 {
        ceiling - self.state.used.get(cap_key).copied().unwrap_or(0)
    }

    /// Advance the clock (never backwards) and forget expired counters. Inside a
    /// call's transaction nothing is written until something is charged.
    pub fn prepare(&mut self, now: i128) -> Result<()> {
        integer(now, "budget clock", 0, MAX_INTEGER)?;
        if now < self.state.clock {
            return Err(Error::value("budget clock rollback"));
        }
        self.state.clock = now;
        let expired: Vec<String> = self
            .state
            .expires
            .iter()
            .filter(|(_, e)| **e <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired {
            self.state.used.remove(&key);
            self.state.expires.remove(&key);
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if let Some(path) = &self.store.path {
            atomic_json(
                path,
                &json!({
                    "version": 2,
                    "used": self.state.used.iter().map(|(k, v)| (k.clone(), crate::json::int(*v))).collect::<serde_json::Map<_, _>>(),
                    "expires": self.state.expires.iter().map(|(k, v)| (k.clone(), crate::json::int(*v))).collect::<serde_json::Map<_, _>>(),
                    "clock": crate::json::int(self.state.clock),
                }),
            )?;
            self.state.seen = true;
        }
        Ok(())
    }

    /// Increment every given counter, flushing once.
    ///
    /// A call is charged to more than one counter — the mandate's global budget and
    /// its per-tool budget (architecture decision 5) — and those must move together: a partial write
    /// would let a restart resurrect spent budget on one level only.
    pub fn consume(&mut self, keys: &[&str], expires_at: Option<i128>) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }
        let previous = (self.state.used.clone(), self.state.expires.clone());
        let mut union: std::collections::BTreeSet<&str> =
            self.state.used.keys().map(String::as_str).collect();
        union.extend(keys.iter().copied());
        if union.len() > CAPACITY {
            return Err(Error::value("budget state capacity reached"));
        }
        for key in keys {
            if let Some(expiry) = expires_at {
                let entry = self.state.expires.entry((*key).to_owned()).or_insert(0);
                *entry = (*entry).max(expiry);
            }
            *self.state.used.entry((*key).to_owned()).or_insert(0) += 1;
        }
        if let Err(e) = self.flush() {
            self.state.used = previous.0;
            self.state.expires = previous.1;
            return Err(e);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_persist_and_expire() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.json");
        let store = BudgetStore::open(&path).unwrap();
        {
            let mut tx = store.transaction().unwrap();
            tx.prepare(100).unwrap();
            tx.consume(&["m", "m|t"], Some(200)).unwrap();
        }
        let reopened = BudgetStore::open(&path).unwrap();
        assert_eq!(reopened.remaining("m", 5).unwrap(), 4);
        reopened.prepare(250).unwrap();
        assert_eq!(reopened.remaining("m", 5).unwrap(), 5);
        assert!(reopened.prepare(10).is_err(), "clock rollback");
        std::fs::remove_file(&path).unwrap();
        assert!(reopened.transaction().is_err(), "state disappeared");
    }
}
