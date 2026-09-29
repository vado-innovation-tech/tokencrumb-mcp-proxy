//! Bounded replay protection, optionally shared through a durable local SQLite DB.

use std::collections::HashMap;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{Connection, TransactionBehavior, params};

use crate::error::{Error, Result};
use crate::validation::{MAX_INTEGER, integer};

/// Anything that can refuse a nonce it has already seen.
pub trait NonceStore: Send + Sync {
    /// Record `nonce`; false when it was already seen, the clock went backwards or
    /// the store is full (fail-closed).
    fn check_and_add(&self, nonce: &str, now_epoch: f64, expires_at: Option<f64>) -> Result<bool>;
}

struct Memory {
    // nonce -> expiry, plus insertion order for deterministic purging.
    store: HashMap<String, f64>,
    clock: f64,
}

pub struct NonceCache {
    pub capacity: usize,
    pub ttl: i128,
    pub path: Option<PathBuf>,
    memory: Mutex<Memory>,
}

fn sql_error(error: rusqlite::Error) -> Error {
    Error::io(error.to_string())
}

impl NonceCache {
    pub fn new(capacity: usize, ttl_seconds: i128, path: Option<&Path>) -> Result<Self> {
        integer(capacity as i128, "nonce capacity", 1, MAX_INTEGER)?;
        integer(ttl_seconds, "nonce TTL", 1, MAX_INTEGER)?;
        if let Some(path) = path {
            std::fs::OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .mode(0o600)
                .open(path)?;
            let db = Connection::open(path).map_err(sql_error)?;
            db.execute_batch(
                "CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, expiry REAL NOT NULL);
                 CREATE INDEX IF NOT EXISTS expiry_idx ON nonces(expiry);
                 CREATE TABLE IF NOT EXISTS clock (id INTEGER PRIMARY KEY CHECK(id=1), epoch REAL NOT NULL);
                 INSERT OR IGNORE INTO clock VALUES(1,0);",
            )
            .map_err(sql_error)?;
        }
        Ok(Self {
            capacity,
            ttl: ttl_seconds,
            path: path.map(Path::to_path_buf),
            memory: Mutex::new(Memory {
                store: HashMap::new(),
                clock: 0.0,
            }),
        })
    }

    /// In-memory cache with the defaults (100 000 entries, 120 s).
    pub fn in_memory() -> Self {
        Self::new(100_000, 120, None).expect("valid defaults")
    }

    fn check_sqlite(&self, path: &Path, nonce: &str, now: f64, expiry: f64) -> Result<bool> {
        if !path.is_file() {
            return Err(Error::value("nonce state disappeared"));
        }
        let mut db = Connection::open(path).map_err(sql_error)?;
        db.busy_timeout(Duration::from_secs(10))
            .map_err(sql_error)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let previous: f64 = tx
            .query_row("SELECT epoch FROM clock WHERE id=1", [], |r| r.get(0))
            .map_err(sql_error)?;
        let fresh = if now < previous - 1.0 {
            false
        } else {
            tx.execute(
                "UPDATE clock SET epoch=? WHERE id=1",
                params![now.max(previous)],
            )
            .map_err(sql_error)?;
            tx.execute("DELETE FROM nonces WHERE expiry<=?", params![now])
                .map_err(sql_error)?;
            let count: i64 = tx
                .query_row("SELECT COUNT(*) FROM nonces", [], |r| r.get(0))
                .map_err(sql_error)?;
            if count as usize >= self.capacity {
                false
            } else {
                tx.execute(
                    "INSERT OR IGNORE INTO nonces VALUES(?,?)",
                    params![nonce, expiry],
                )
                .map_err(sql_error)?
                    == 1
            }
        };
        tx.commit().map_err(sql_error)?;
        Ok(fresh)
    }
}

impl NonceStore for NonceCache {
    fn check_and_add(&self, nonce: &str, now_epoch: f64, expires_at: Option<f64>) -> Result<bool> {
        let expiry = (now_epoch + self.ttl as f64).max(expires_at.unwrap_or(0.0));
        if nonce.is_empty() || !expiry.is_finite() || !now_epoch.is_finite() {
            return Err(Error::value("invalid nonce or time"));
        }
        let mut memory = self.memory.lock().expect("nonce lock");
        if let Some(path) = &self.path {
            return self.check_sqlite(path, nonce, now_epoch, expiry);
        }
        if now_epoch < memory.clock - 1.0 {
            return Ok(false);
        }
        memory.clock = memory.clock.max(now_epoch);
        memory.store.retain(|_, end| *end > now_epoch);
        if memory.store.contains_key(nonce) || memory.store.len() >= self.capacity {
            return Ok(false);
        }
        memory.store.insert(nonce.to_owned(), expiry);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_and_rollback() {
        let cache = NonceCache::in_memory();
        assert!(cache.check_and_add("a", 100.0, None).unwrap());
        assert!(!cache.check_and_add("a", 100.0, None).unwrap());
        assert!(
            !cache.check_and_add("b", 98.0, None).unwrap(),
            "clock rollback"
        );
        assert!(
            cache.check_and_add("a", 300.0, None).unwrap(),
            "expired entry forgotten"
        );
    }

    #[test]
    fn sqlite_is_shared_and_durable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("n.db");
        let one = NonceCache::new(10, 120, Some(&path)).unwrap();
        let two = NonceCache::new(10, 120, Some(&path)).unwrap();
        assert!(one.check_and_add("x", 100.0, None).unwrap());
        assert!(!two.check_and_add("x", 100.0, None).unwrap());
        std::fs::remove_file(&path).unwrap();
        assert!(one.check_and_add("y", 100.0, None).is_err());
    }
}
