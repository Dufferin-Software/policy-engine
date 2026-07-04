// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Fleet Suricata ruleset synchronisation helpers.
//!
//! A ruleset materialises on each assigned node as one file,
//! `fleet-<name>.rules`, in the engine's Suricata rules directory. The
//! controller stores the canonical content and its SHA-256; the agent
//! reports per-file digests in every StateSnapshot. [`build_ruleset_push`]
//! diffs desired against reported and yields the minimal
//! `SuricataRulesetPush`, which the agent applies idempotently (write
//! changed files, delete stale `fleet-*` files, reload once).
//!
//! ## Digest contract
//!
//! `sha256` is computed over the *exact bytes* stored in `content` — the
//! engine writes rule files byte-verbatim and hashes them the same way, so
//! any canonicalisation must happen exactly once, at ruleset write time
//! ([`canonicalize_content`]). Anything else would make the digests
//! oscillate and re-push the ruleset on every snapshot.

use policy_controller_proto::controller::{SuricataRuleFile, SuricataRulesetPush};
use sha2::{Digest, Sha256};

use crate::store::{SuricataRuleFileReport, SuricataRuleset};

/// Per-ruleset content cap. Keeps a push with several files comfortably
/// under the 16 MiB gRPC message limit. Big public feeds (ET Open) stay
/// node-local via suricata-update; fleet rulesets are for curated content.
pub const MAX_RULESET_BYTES: usize = 4 * 1024 * 1024;

/// Canonical form of ruleset content: exactly one trailing newline.
pub fn canonicalize_content(content: &str) -> String {
    let trimmed = content.trim_end_matches('\n');
    format!("{}\n", trimmed)
}

/// Count non-empty, non-comment lines (matches the engine's rule counting).
pub fn rule_count(content: &str) -> u32 {
    content
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .count() as u32
}

/// Hex SHA-256 over the content bytes.
pub fn sha256_hex(content: &str) -> String {
    format!("{:x}", Sha256::digest(content.as_bytes()))
}

/// Ruleset names become filenames (`fleet-<name>.rules`), so restrict them
/// to a filesystem- and shell-safe alphabet.
pub fn validate_ruleset_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 64 {
        return Err("Ruleset name must be 1-64 characters".to_string());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(format!(
            "Invalid ruleset name {:?}: use lowercase letters, digits, '-' and '_'",
            name
        ));
    }
    Ok(())
}

/// Diff the node's desired rulesets against its agent-reported rule files
/// and build the minimal push, or `None` when the node is in sync.
///
/// Only `fleet-*` files participate: node-local rule files never appear in
/// `desired_filenames`, so the agent never deletes them. The push is built
/// un-gated (empty generation_id); callers that need the confirm handshake
/// stamp the generation via the pending machinery instead.
pub fn build_ruleset_push(
    desired: &[SuricataRuleset],
    reported: &[SuricataRuleFileReport],
) -> Option<SuricataRulesetPush> {
    let reported_fleet: std::collections::HashMap<&str, &str> = reported
        .iter()
        .filter(|f| f.filename.starts_with("fleet-"))
        .map(|f| (f.filename.as_str(), f.sha256.as_str()))
        .collect();

    let desired_filenames: Vec<String> = desired.iter().map(|r| r.filename()).collect();

    // Files whose reported digest is missing or different.
    let files: Vec<SuricataRuleFile> = desired
        .iter()
        .filter(|r| reported_fleet.get(r.filename().as_str()) != Some(&r.sha256.as_str()))
        .map(|r| SuricataRuleFile {
            filename: r.filename(),
            content: r.content.clone().into_bytes(),
            sha256: r.sha256.clone(),
            rule_count: r.rule_count,
        })
        .collect();

    // Stale fleet-managed files still present on the node.
    let has_stale = reported_fleet
        .keys()
        .any(|name| !desired_filenames.iter().any(|d| d == name));

    if files.is_empty() && !has_stale {
        return None;
    }

    Some(SuricataRulesetPush {
        files,
        desired_filenames,
        generation_id: String::new(),
        confirm_deadline_ms: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn ruleset(name: &str, content: &str) -> SuricataRuleset {
        let content = canonicalize_content(content);
        SuricataRuleset {
            id: format!("id-{}", name),
            tenant_id: "default".to_string(),
            name: name.to_string(),
            sha256: sha256_hex(&content),
            rule_count: rule_count(&content),
            content,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn report(filename: &str, sha256: &str) -> SuricataRuleFileReport {
        SuricataRuleFileReport {
            node_id: "n1".to_string(),
            filename: filename.to_string(),
            sha256: sha256.to_string(),
            rule_count: 1,
        }
    }

    #[test]
    fn canonicalize_is_idempotent_and_digest_stable() {
        let a = canonicalize_content("alert tcp any any -> any any (sid:1;)");
        let b = canonicalize_content(&a);
        let c = canonicalize_content("alert tcp any any -> any any (sid:1;)\n\n\n");
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(sha256_hex(&a), sha256_hex(&b));
    }

    #[test]
    fn in_sync_node_gets_no_push() {
        let rs = ruleset("base", "alert tcp any any -> any any (sid:1;)");
        let reported = vec![
            report(&rs.filename(), &rs.sha256),
            // Node-local file must be ignored entirely.
            report("custom.rules", "abcd"),
        ];
        assert!(build_ruleset_push(&[rs], &reported).is_none());
    }

    #[test]
    fn missing_and_mismatched_files_are_pushed() {
        let base = ruleset("base", "alert tcp any any -> any any (sid:1;)");
        let extra = ruleset("extra", "alert udp any any -> any any (sid:2;)");
        // base is reported with a stale digest; extra is absent.
        let reported = vec![report(&base.filename(), "deadbeef")];
        let push = build_ruleset_push(&[base.clone(), extra.clone()], &reported).unwrap();
        assert_eq!(push.files.len(), 2);
        assert_eq!(
            push.desired_filenames,
            vec![base.filename(), extra.filename()]
        );
        // Content bytes hash to the advertised digest (agent re-verifies).
        for f in &push.files {
            assert_eq!(format!("{:x}", sha2::Sha256::digest(&f.content)), f.sha256);
        }
    }

    #[test]
    fn stale_fleet_file_triggers_push_with_no_files() {
        // Nothing assigned, but a fleet- file lingers on the node: the push
        // carries only the (empty) desired set so the agent deletes it.
        let reported = vec![report("fleet-old.rules", "aa")];
        let push = build_ruleset_push(&[], &reported).unwrap();
        assert!(push.files.is_empty());
        assert!(push.desired_filenames.is_empty());
    }

    #[test]
    fn local_files_never_trigger_pushes() {
        let reported = vec![report("custom.rules", "aa"), report("other.rules", "bb")];
        assert!(build_ruleset_push(&[], &reported).is_none());
    }

    #[test]
    fn name_validation() {
        assert!(validate_ruleset_name("base-set_1").is_ok());
        assert!(validate_ruleset_name("").is_err());
        assert!(validate_ruleset_name("Bad Name").is_err());
        assert!(validate_ruleset_name("../evil").is_err());
    }
}
