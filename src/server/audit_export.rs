// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Audit log export formats.
//!
//! [`AuditExporter`] abstracts the on-the-wire format so new export targets
//! (CSV, JSON, …) can be added without touching the GraphQL resolver or the
//! web UI. Resolve a concrete exporter by name with [`exporter_for`].

use anyhow::{bail, Result};

use super::audit_logger::AuditEntry;

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
        Ok(serde_json::to_string_pretty(entries)?)
    }
}

/// RFC 4180 CSV with a fixed header row. `input_json` is serialised to a
/// compact JSON string so it fits a single cell.
pub struct CsvExporter;

impl CsvExporter {
    const HEADER: &'static str = "timestamp,operation,input_json,result,message,source_ip";
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
            let input = serde_json::to_string(&e.input_json).unwrap_or_default();
            let fields = [
                e.timestamp.as_str(),
                e.operation.as_str(),
                input.as_str(),
                e.result.as_str(),
                e.message.as_str(),
                e.source_ip.as_str(),
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

    fn sample() -> Vec<AuditEntry> {
        vec![
            AuditEntry {
                timestamp: "2026-03-17T14:23:01.452Z".to_string(),
                operation: "attach_ingress".to_string(),
                input_json: serde_json::json!({"interface": "eth0", "mode": "auto"}),
                result: "ok".to_string(),
                message: "Attached, said \"hi\"".to_string(),
                source_ip: "127.0.0.1:54321".to_string(),
            },
            AuditEntry {
                timestamp: "2026-03-17T14:24:00.000Z".to_string(),
                operation: "detach_all".to_string(),
                input_json: serde_json::Value::Null,
                result: "ok".to_string(),
                message: "with, comma".to_string(),
                source_ip: "unknown".to_string(),
            },
        ]
    }

    #[test]
    fn exporter_for_resolves_known_formats() {
        assert_eq!(exporter_for("csv").unwrap().extension(), "csv");
        assert_eq!(exporter_for("JSON").unwrap().extension(), "json");
        assert_eq!(exporter_for(" Csv ").unwrap().content_type(), "text/csv");
        assert!(exporter_for("xml").is_err());
    }

    #[test]
    fn json_export_roundtrips() {
        let data = JsonExporter.export(&sample()).unwrap();
        let parsed: Vec<AuditEntry> = serde_json::from_str(&data).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].operation, "attach_ingress");
        assert_eq!(parsed[0].input_json["interface"], "eth0");
    }

    #[test]
    fn csv_export_has_header_and_escapes() {
        let data = CsvExporter.export(&sample()).unwrap();
        let lines: Vec<&str> = data.lines().collect();
        assert_eq!(lines[0], CsvExporter::HEADER);
        assert_eq!(lines.len(), 3); // header + 2 rows
                                    // Embedded quotes are doubled.
        assert!(lines[1].contains("\"Attached, said \"\"hi\"\"\""));
        // Embedded comma stays inside the quoted cell.
        assert!(lines[2].contains("\"with, comma\""));
        // Null input serialises to the literal `null`.
        assert!(lines[2].contains("\"null\""));
    }

    #[test]
    fn csv_export_empty_is_header_only() {
        let data = CsvExporter.export(&[]).unwrap();
        assert_eq!(data, format!("{}\r\n", CsvExporter::HEADER));
    }
}
