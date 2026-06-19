// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Audit logging for policy engine mutations.
//!
//! The [`AuditBackend`] trait abstracts the storage destination so that
//! different backends (file, database, syslog, network) can be used without
//! changing the instrumentation code in the GraphQL mutations.
//!
//! Provided implementations:
//! - [`FileAuditLogger`] — appends JSON lines to a file and maintains an
//!   in-memory ring buffer for the `auditLog` GraphQL query.
//! - [`NoopAuditLogger`] — discards all events; runtime fallback when the log
//!   file cannot be created.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Mutex;

use async_graphql::SimpleObject;
use chrono::{DateTime, Utc};
use log::warn;
#[cfg(test)]
use mockall::automock;
use serde::{Deserialize, Serialize};

/// A single audit log entry.
#[derive(SimpleObject, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub operation: String,
    /// JSON representation of the mutation input (serialised as a scalar).
    #[graphql(name = "input")]
    pub input_json: serde_json::Value,
    /// `"ok"` or `"error"`.
    pub result: String,
    pub message: String,
    pub source_ip: String,
}

/// Trait for audit log backends.
///
/// Implement this trait to add new storage destinations. The provided
/// [`log_event`](AuditBackend::log_event) method constructs an [`AuditEntry`]
/// and delegates to [`record`](AuditBackend::record), so most implementors
/// only need to define `record` and `recent_entries`.
#[cfg_attr(test, automock)]
pub trait AuditBackend: Send + Sync {
    /// Persist a single audit entry. Implementations must not propagate errors
    /// — log a warning and continue instead.
    fn record(&self, entry: &AuditEntry);

    /// Return the most recent `limit` entries. Backends that do not support
    /// in-process querying (e.g. a remote database) should return an empty vec.
    fn recent_entries(&self, limit: usize) -> Vec<AuditEntry>;

    /// Return every entry whose `timestamp` falls within the inclusive window
    /// `[from, to]` (either bound may be `None` to leave that side open).
    ///
    /// Used by the audit export. The default implementation filters the
    /// in-memory ring (via [`recent_entries`](Self::recent_entries)), which is
    /// capped and lost on restart; backends with durable storage (e.g.
    /// [`FileAuditLogger`]) should override this to scan their full history.
    fn entries_between(
        &self,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
    ) -> Vec<AuditEntry> {
        self.recent_entries(1000)
            .into_iter()
            .filter(|e| entry_in_window(e, from, to))
            .collect()
    }

    /// Convenience method: build an [`AuditEntry`] and call [`record`](Self::record).
    fn log_event(
        &self,
        operation: &str,
        input: serde_json::Value,
        result: &str,
        message: &str,
        source_ip: &str,
    ) {
        let entry = AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            operation: operation.to_string(),
            input_json: input,
            result: result.to_string(),
            message: message.to_string(),
            source_ip: source_ip.to_string(),
        };
        self.record(&entry);
    }
}

/// Whether `entry`'s RFC 3339 `timestamp` falls within the inclusive window
/// `[from, to]`. An entry whose timestamp cannot be parsed is included only
/// when no bounds are given, so an unparseable row never silently drops from
/// an unfiltered export.
fn entry_in_window(
    entry: &AuditEntry,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
) -> bool {
    let ts = match DateTime::parse_from_rfc3339(&entry.timestamp) {
        Ok(t) => t.with_timezone(&Utc),
        Err(_) => return from.is_none() && to.is_none(),
    };
    from.is_none_or(|f| ts >= f) && to.is_none_or(|t| ts <= t)
}

// ---------------------------------------------------------------------------
// FileAuditLogger — append-only file + in-memory ring buffer
// ---------------------------------------------------------------------------

/// Audit backend that appends JSON lines to a file and caches the last 1000
/// entries in memory for the `auditLog` GraphQL query.
pub struct FileAuditLogger {
    file: Mutex<File>,
    ring: Mutex<VecDeque<AuditEntry>>,
    path: PathBuf,
}

impl FileAuditLogger {
    /// Open (or create) the log file at `path`, creating parent directories as
    /// needed.
    pub fn new(path: &str) -> anyhow::Result<Self> {
        if let Some(parent) = std::path::Path::new(path).parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Mutex::new(file),
            ring: Mutex::new(VecDeque::new()),
            path: PathBuf::from(path),
        })
    }
}

impl AuditBackend for FileAuditLogger {
    fn record(&self, entry: &AuditEntry) {
        if let Ok(mut file) = self.file.lock() {
            match serde_json::to_string(entry) {
                Ok(line) => {
                    if let Err(e) = writeln!(file, "{}", line) {
                        warn!("Audit log write failed: {}", e);
                    }
                }
                Err(e) => warn!("Audit log serialize failed: {}", e),
            }
        }
        if let Ok(mut ring) = self.ring.lock() {
            if ring.len() >= 1000 {
                ring.pop_front();
            }
            ring.push_back(entry.clone());
        }
    }

    fn recent_entries(&self, limit: usize) -> Vec<AuditEntry> {
        match self.ring.lock() {
            Ok(ring) => {
                let skip = ring.len().saturating_sub(limit);
                ring.iter().skip(skip).cloned().collect()
            }
            Err(_) => vec![],
        }
    }

    /// Scan the full on-disk NDJSON log — the durable source of truth — rather
    /// than the capped ring buffer. Malformed or unreadable lines are skipped;
    /// if the file can't be opened at all we fall back to filtering the ring
    /// (per the crate's never-propagate-errors convention).
    fn entries_between(
        &self,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
    ) -> Vec<AuditEntry> {
        let file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) => {
                warn!(
                    "Audit export: cannot read {}: {}; using in-memory buffer instead",
                    self.path.display(),
                    e
                );
                return self
                    .recent_entries(1000)
                    .into_iter()
                    .filter(|entry| entry_in_window(entry, from, to))
                    .collect();
            }
        };
        BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .filter_map(|line| serde_json::from_str::<AuditEntry>(&line).ok())
            .filter(|entry| entry_in_window(entry, from, to))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// NoopAuditLogger — silent discard; runtime fallback when log is disabled
// ---------------------------------------------------------------------------

/// Audit backend that silently discards all events.
///
/// Used as a runtime fallback when the log file cannot be created.
pub struct NoopAuditLogger;

impl AuditBackend for NoopAuditLogger {
    fn record(&self, _entry: &AuditEntry) {}
    fn recent_entries(&self, _limit: usize) -> Vec<AuditEntry> {
        vec![]
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    // --- FileAuditLogger ---

    fn temp_log_path(tag: &str) -> String {
        format!(
            "{}/policy_audit_{}_{}.log",
            std::env::temp_dir().display(),
            tag,
            std::process::id()
        )
    }

    #[test]
    fn file_logger_creates_and_records_event() {
        let logger = FileAuditLogger::new(&temp_log_path("creates")).unwrap();
        logger.log_event(
            "attach_ingress",
            serde_json::json!({"interface": "eth0"}),
            "ok",
            "Attached",
            "127.0.0.1",
        );
        let entries = logger.recent_entries(10);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].operation, "attach_ingress");
        assert_eq!(entries[0].result, "ok");
        assert_eq!(entries[0].source_ip, "127.0.0.1");
    }

    #[test]
    fn file_logger_ring_capped_at_1000() {
        let logger = FileAuditLogger::new(&temp_log_path("cap")).unwrap();
        for i in 0..1010u32 {
            logger.log_event("op", serde_json::json!({"i": i}), "ok", "msg", "127.0.0.1");
        }
        assert_eq!(logger.recent_entries(1000).len(), 1000);
    }

    #[test]
    fn file_logger_recent_entries_returns_latest() {
        let logger = FileAuditLogger::new(&temp_log_path("latest")).unwrap();
        for i in 0..5u32 {
            logger.log_event(
                &format!("op_{i}"),
                serde_json::Value::Null,
                "ok",
                "msg",
                "::1",
            );
        }
        let entries = logger.recent_entries(3);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].operation, "op_2");
        assert_eq!(entries[2].operation, "op_4");
    }

    #[test]
    fn file_logger_entries_between_reads_disk_and_filters() {
        let path = temp_log_path("between");
        let _ = std::fs::remove_file(&path);
        let logger = FileAuditLogger::new(&path).unwrap();
        let mk = |ts: &str, op: &str| AuditEntry {
            timestamp: ts.to_string(),
            operation: op.to_string(),
            input_json: serde_json::Value::Null,
            result: "ok".to_string(),
            message: "m".to_string(),
            source_ip: "::1".to_string(),
        };
        logger.record(&mk("2026-03-01T00:00:00Z", "early"));
        logger.record(&mk("2026-03-15T12:00:00Z", "mid"));
        logger.record(&mk("2026-04-01T00:00:00Z", "late"));

        let parse = |s: &str| DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc);
        let from = parse("2026-03-10T00:00:00Z");
        let to = parse("2026-03-20T00:00:00Z");

        let got = logger.entries_between(Some(from), Some(to));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].operation, "mid");

        // Open-ended bounds.
        assert_eq!(logger.entries_between(None, None).len(), 3);
        assert_eq!(logger.entries_between(Some(from), None).len(), 2); // mid + late
        assert_eq!(logger.entries_between(None, Some(to)).len(), 2); // early + mid
    }

    // --- Trait object usage ---

    #[test]
    fn trait_object_file_backend_works() {
        let backend: Arc<dyn AuditBackend> =
            Arc::new(FileAuditLogger::new(&temp_log_path("trait")).unwrap());
        backend.log_event(
            "add_rule",
            serde_json::json!({"id": 1}),
            "ok",
            "Added",
            "10.0.0.1",
        );
        assert_eq!(backend.recent_entries(5).len(), 1);
    }

    // --- MockAuditBackend ---

    #[test]
    fn mock_backend_records_calls() {
        let mut mock = MockAuditBackend::new();
        mock.expect_record().times(2).returning(|_| ());
        mock.expect_recent_entries().returning(|_| vec![]);

        // Call record() directly — log_event() is also mocked by mockall
        // and would need its own expectation if called.
        let entry = AuditEntry {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            operation: "op_a".to_string(),
            input_json: serde_json::Value::Null,
            result: "ok".to_string(),
            message: "a".to_string(),
            source_ip: "1.2.3.4".to_string(),
        };
        mock.record(&entry);
        mock.record(&entry);
        assert!(mock.recent_entries(5).is_empty());
    }
}
