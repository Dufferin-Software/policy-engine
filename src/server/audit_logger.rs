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
use std::io::Write;
use std::sync::Mutex;

use async_graphql::SimpleObject;
use log::warn;
#[cfg(test)]
use mockall::automock;
use serde::Serialize;

/// A single audit log entry.
#[derive(SimpleObject, Clone, Serialize)]
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

// ---------------------------------------------------------------------------
// FileAuditLogger — append-only file + in-memory ring buffer
// ---------------------------------------------------------------------------

/// Audit backend that appends JSON lines to a file and caches the last 1000
/// entries in memory for the `auditLog` GraphQL query.
pub struct FileAuditLogger {
    file: Mutex<File>,
    ring: Mutex<VecDeque<AuditEntry>>,
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
