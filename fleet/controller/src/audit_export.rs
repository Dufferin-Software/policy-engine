// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Audit log export formats for the controller.
//!
//! [`AuditExporter`] abstracts the on-the-wire format so new export targets
//! (CSV, JSON, …) can be added without touching the GraphQL resolver or the
//! web UI. Resolve a concrete exporter by name with [`exporter_for`].
//!
//! Exports project [`store::AuditEntry`] onto the same columns the operator
//! API exposes (`AuditEntryOutput`) — `tenant_id` is intentionally omitted
//! since readers are already tenant-scoped.

use anyhow::{bail, Result};
use serde::Serialize;

use crate::store::AuditEntry;

/// A single audit row as exported. Mirrors the GraphQL `AuditEntryOutput`
/// columns; `tenant_id` is deliberately excluded.
#[derive(Serialize)]
struct ExportRow<'a> {
    id: i64,
    ts: String,
    operator: Option<&'a str>,
    action: &'a str,
    node_id: Option<&'a str>,
    detail: Option<&'a str>,
}

impl<'a> From<&'a AuditEntry> for ExportRow<'a> {
    fn from(e: &'a AuditEntry) -> Self {
        Self {
            id: e.id,
            ts: e.ts.to_rfc3339(),
            operator: e.operator.as_deref(),
            action: &e.action,
            node_id: e.node_id.as_deref(),
            detail: e.detail.as_deref(),
        }
    }
}

/// Serialises a slice of audit entries into a downloadable text payload.
///
/// Implement this trait to add a new export format, then register it in
/// [`exporter_for`].
pub trait AuditExporter: Send + Sync {
    /// MIME content type for the payload, e.g. `"text/csv"`.
    fn content_type(&self) -> &'static str;

    /// File extension without the dot, e.g. `"csv"`.
    fn extension(&self) -> &'static str;

    /// Render `entries` into the export format.
    fn export(&self, entries: &[AuditEntry]) -> Result<String>;
}

/// Resolve an exporter by format name (case-insensitive).
pub fn exporter_for(format: &str) -> Result<Box<dyn AuditExporter>> {
    match format.trim().to_lowercase().as_str() {
        "json" => Ok(Box::new(JsonExporter)),
        "csv" => Ok(Box::new(CsvExporter)),
        other => bail!("unsupported audit export format: {other:?} (supported: csv, json)"),
    }
}

/// Pretty-printed JSON array of entries.
pub struct JsonExporter;

impl AuditExporter for JsonExporter {
    fn content_type(&self) -> &'static str {
        "application/json"
    }

    fn extension(&self) -> &'static str {
        "json"
    }

    fn export(&self, entries: &[AuditEntry]) -> Result<String> {
        let rows: Vec<ExportRow> = entries.iter().map(ExportRow::from).collect();
        Ok(serde_json::to_string_pretty(&rows)?)
    }
}

/// RFC 4180 CSV with a fixed header row.
pub struct CsvExporter;

impl CsvExporter {
    const HEADER: &'static str = "id,ts,operator,action,node_id,detail";
}

impl AuditExporter for CsvExporter {
    fn content_type(&self) -> &'static str {
        "text/csv"
    }

    fn extension(&self) -> &'static str {
        "csv"
    }

    fn export(&self, entries: &[AuditEntry]) -> Result<String> {
        let mut out = String::from(Self::HEADER);
        out.push_str("\r\n");
        for e in entries {
            let r = ExportRow::from(e);
            let id = r.id.to_string();
            let fields = [
                id.as_str(),
                r.ts.as_str(),
                r.operator.unwrap_or_default(),
                r.action,
                r.node_id.unwrap_or_default(),
                r.detail.unwrap_or_default(),
            ];
            for (i, f) in fields.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&csv_field(f));
            }
            out.push_str("\r\n");
        }
        Ok(out)
    }
}

/// Quote a CSV field per RFC 4180: always wrap in double quotes and double any
/// embedded double quotes, so commas, quotes and newlines are all safe.
fn csv_field(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample() -> Vec<AuditEntry> {
        vec![
            AuditEntry {
                id: 1,
                ts: chrono::Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
                operator: Some("operator:alice".to_string()),
                action: "config_pushed".to_string(),
                node_id: Some("node-1".to_string()),
                detail: Some("7 rules, said \"go\"".to_string()),
                tenant_id: "acme".to_string(),
            },
            AuditEntry {
                id: 2,
                ts: chrono::Utc.timestamp_opt(1_700_000_100, 0).unwrap(),
                operator: None,
                action: "node_decommissioned".to_string(),
                node_id: None,
                detail: None,
                tenant_id: "acme".to_string(),
            },
        ]
    }

    #[test]
    fn exporter_for_resolves_known_formats() {
        assert_eq!(exporter_for("csv").unwrap().extension(), "csv");
        assert_eq!(exporter_for("JSON").unwrap().extension(), "json");
        assert!(exporter_for("yaml").is_err());
    }

    #[test]
    fn json_export_projects_columns_and_omits_tenant() {
        let data = JsonExporter.export(&sample()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&data).unwrap();
        assert_eq!(parsed[0]["action"], "config_pushed");
        assert_eq!(parsed[0]["operator"], "operator:alice");
        assert_eq!(parsed[1]["operator"], serde_json::Value::Null);
        // tenant_id is never exported.
        assert!(parsed[0].get("tenant_id").is_none());
    }

    #[test]
    fn csv_export_has_header_and_escapes() {
        let data = CsvExporter.export(&sample()).unwrap();
        let lines: Vec<&str> = data.lines().collect();
        assert_eq!(lines[0], CsvExporter::HEADER);
        assert_eq!(lines.len(), 3);
        assert!(lines[1].contains("\"7 rules, said \"\"go\"\"\""));
        // Missing operator/node_id/detail render as empty quoted cells.
        assert!(lines[2].ends_with("\"node_decommissioned\",\"\",\"\""));
    }
}
