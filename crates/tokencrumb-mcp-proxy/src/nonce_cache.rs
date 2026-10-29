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

/// The outcome of one attempt to consume a receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reservation {
    /// The row was inserted: this call owns the receipt.
    Reserved,
    /// The receipt id was already there: refuse ("receipt already used").
    Used,
    /// The table is at capacity: refuse, fail closed.
    Full,
}

/// One receipt row, as read back for the audit and the tests.
#[derive(Debug, Clone, PartialEq)]
pub struct ReceiptRow {
    pub receipt_id: String,
    pub intent_hash: String,
    pub approver_id: String,
    pub state: String,
    pub instance_id: String,
    pub lease_until: f64,
}

/// Single-use approval receipts, in the nonce database (table `receipts`).
///
/// A receipt is consumed by inserting its id "if absent" inside an `IMMEDIATE`
/// transaction, so two processes sharing the file serialize, and a restart remembers
/// it. A row starts `reserved` with a lease covering the upstream call; the outcome
/// moves it to `ok`, `upstream_error` or `unknown`. A `reserved` row whose lease ran
/// out belongs to no live call: [`ReceiptStore::sweep`] marks it `unknown`. A row
/// is never deleted before its receipt has expired, so a consumed receipt can never
/// become usable again.
pub struct ReceiptStore {
    pub path: PathBuf,
    pub capacity: usize,
}

impl ReceiptStore {
    pub fn open(path: &Path, capacity: usize) -> Result<Self> {
        integer(capacity as i128, "receipt capacity", 1, MAX_INTEGER)?;
        std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        let db = Connection::open(path).map_err(sql_error)?;
        db.busy_timeout(Duration::from_secs(10))
            .map_err(sql_error)?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS receipts (
               receipt_id     TEXT PRIMARY KEY,
               intent_hash    TEXT NOT NULL,
               approver_id    TEXT NOT NULL,
               expires_at     REAL NOT NULL,
               state          TEXT NOT NULL,
               instance_id    TEXT NOT NULL,
               lease_until    REAL NOT NULL,
               correlation_id TEXT,
               updated_at     REAL NOT NULL
             );
             CREATE INDEX IF NOT EXISTS receipts_state_idx ON receipts(state, lease_until);",
        )
        .map_err(sql_error)?;
        Ok(Self {
            path: path.to_path_buf(),
            capacity,
        })
    }

    fn connect(&self) -> Result<Connection> {
        if !self.path.is_file() {
            return Err(Error::value("receipt state disappeared"));
        }
        let db = Connection::open(&self.path).map_err(sql_error)?;
        db.busy_timeout(Duration::from_secs(10))
            .map_err(sql_error)?;
        Ok(db)
    }

    /// Consume `receipt_id`: insert it `reserved` unless it is already known.
    /// `purge_before` drops final rows whose receipt expired before that instant.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve(
        &self,
        receipt_id: &str,
        intent_hash: &str,
        approver_id: &str,
        expires_at: f64,
        instance_id: &str,
        lease_until: f64,
        now: f64,
        purge_before: f64,
    ) -> Result<Reservation> {
        let mut db = self.connect()?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        tx.execute(
            "DELETE FROM receipts WHERE state<>'reserved' AND expires_at<?",
            params![purge_before],
        )
        .map_err(sql_error)?;
        let known: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM receipts WHERE receipt_id=?",
                params![receipt_id],
                |r| r.get(0),
            )
            .map_err(sql_error)?;
        let outcome = if known > 0 {
            Reservation::Used
        } else {
            let count: i64 = tx
                .query_row("SELECT COUNT(*) FROM receipts", [], |r| r.get(0))
                .map_err(sql_error)?;
            if count as usize >= self.capacity {
                Reservation::Full
            } else {
                tx.execute(
                    "INSERT INTO receipts VALUES(?,?,?,?,'reserved',?,?,NULL,?)",
                    params![
                        receipt_id,
                        intent_hash,
                        approver_id,
                        expires_at,
                        instance_id,
                        lease_until,
                        now
                    ],
                )
                .map_err(sql_error)?;
                Reservation::Reserved
            }
        };
        tx.commit().map_err(sql_error)?;
        Ok(outcome)
    }

    /// Record the outcome of the call that reserved `receipt_id`. Only a row this
    /// instance still holds `reserved` moves; false otherwise (already swept).
    pub fn finish(
        &self,
        receipt_id: &str,
        instance_id: &str,
        state: &str,
        now: f64,
    ) -> Result<bool> {
        let db = self.connect()?;
        let changed = db
            .execute(
                "UPDATE receipts SET state=?, updated_at=? \
                 WHERE receipt_id=? AND instance_id=? AND state='reserved'",
                params![state, now, receipt_id, instance_id],
            )
            .map_err(sql_error)?;
        Ok(changed == 1)
    }

    /// Mark `unknown` every `reserved` row whose lease ran out; returns them. A row
    /// whose lease still runs belongs to a live process and is left alone.
    pub fn sweep(&self, now: f64) -> Result<Vec<ReceiptRow>> {
        let mut db = self.connect()?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let rows = {
            let mut query = tx
                .prepare(
                    "SELECT receipt_id, intent_hash, approver_id, state, instance_id, lease_until \
                     FROM receipts WHERE state='reserved' AND lease_until<? ORDER BY receipt_id",
                )
                .map_err(sql_error)?;
            query
                .query_map(params![now], row)
                .map_err(sql_error)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(sql_error)?
        };
        tx.execute(
            "UPDATE receipts SET state='unknown', updated_at=? \
             WHERE state='reserved' AND lease_until<?",
            params![now, now],
        )
        .map_err(sql_error)?;
        tx.commit().map_err(sql_error)?;
        Ok(rows)
    }

    pub fn get(&self, receipt_id: &str) -> Result<Option<ReceiptRow>> {
        let db = self.connect()?;
        let mut query = db
            .prepare(
                "SELECT receipt_id, intent_hash, approver_id, state, instance_id, lease_until \
                 FROM receipts WHERE receipt_id=?",
            )
            .map_err(sql_error)?;
        let mut rows = query
            .query_map(params![receipt_id], row)
            .map_err(sql_error)?;
        rows.next().transpose().map_err(sql_error)
    }
}

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ReceiptRow> {
    Ok(ReceiptRow {
        receipt_id: r.get(0)?,
        intent_hash: r.get(1)?,
        approver_id: r.get(2)?,
        state: r.get(3)?,
        instance_id: r.get(4)?,
        lease_until: r.get(5)?,
    })
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
