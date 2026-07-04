// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use super::super::suricata_coordinator::SuricataCoordinator;
use crate::server::suricata_runtime::SuricataRuntime;
use anyhow::Result;
use mockall::predicate::*;
use mockall::*;
use std::path::PathBuf;
use std::sync::Arc;

mock! {
    pub Runtime {}
    impl SuricataRuntime for Runtime {
        fn is_running(&self) -> bool;
        fn start(&self) -> Result<()>;
        fn stop(&self) -> Result<()>;
        fn write_systemd_env(&self, iface: &str) -> Result<()>;
        fn remove_systemd_env(&self) -> Result<()>;
        fn restart_service(&self) -> Result<()>;
        fn get_pid(&self) -> Option<u32>;
        fn get_version(&self) -> Option<String>;
        fn get_ruleset_version(&self) -> Option<String>;
        fn reload_rules(&self, cmd_socket: &std::path::Path) -> Result<()>;
        fn enable_update_timer(&self) -> Result<()>;
        fn disable_update_timer(&self) -> Result<()>;
    }
}

fn make_tmp_rules_dir(label: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("pe_coord_test_{}_{}", label, std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn make_coord(mock: MockRuntime, rules_dir: PathBuf) -> SuricataCoordinator {
    SuricataCoordinator::new_with_runtime(
        Arc::new(mock),
        rules_dir,
        PathBuf::from("/tmp/eve.sock"),
        PathBuf::from("/tmp/suricata.sock"),
    )
}

#[test]
fn write_env_delegates_to_runtime() {
    let mut mock = MockRuntime::new();
    mock.expect_write_systemd_env()
        .with(eq("pe-test0"))
        .times(1)
        .returning(|_| Ok(()));

    // Coordinator should restart the service after writing the env
    mock.expect_restart_service().times(1).returning(|| Ok(()));

    let runtime: Arc<dyn SuricataRuntime> = Arc::new(mock);
    let coord = SuricataCoordinator::new_with_runtime(
        runtime,
        PathBuf::from("/tmp/rules"),
        PathBuf::from("/tmp/eve.json"),
        PathBuf::from("/tmp/sock"),
    );

    let res = coord.write_systemd_env("pe-test0");
    assert!(res.is_ok());
}

#[test]
fn remove_env_delegates_and_restarts() {
    let mut mock = MockRuntime::new();
    mock.expect_remove_systemd_env()
        .times(1)
        .returning(|| Ok(()));

    // Expect restart after removing env
    mock.expect_restart_service().times(1).returning(|| Ok(()));

    let runtime: Arc<dyn SuricataRuntime> = Arc::new(mock);
    let coord = SuricataCoordinator::new_with_runtime(
        runtime,
        PathBuf::from("/tmp/rules"),
        PathBuf::from("/tmp/eve.json"),
        PathBuf::from("/tmp/sock"),
    );

    let res = coord.remove_systemd_env();
    assert!(res.is_ok());
}

#[test]
fn test_write_rules_creates_file() {
    let rules_dir = make_tmp_rules_dir("write_rules");
    let mock = MockRuntime::new();
    let coord = make_coord(mock, rules_dir.clone());

    let rule = r#"alert tcp any any -> any any (msg:"test"; sid:1;)"#;
    coord
        .write_rules("test.rules", rule)
        .expect("write_rules failed");

    let path = rules_dir.join("test.rules");
    assert!(path.exists(), "rules file should exist");
    let content = std::fs::read_to_string(&path).unwrap();
    assert_eq!(content, rule);

    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_add_rule_appends() {
    let rules_dir = make_tmp_rules_dir("add_rule");
    let mock = MockRuntime::new();
    let coord = make_coord(mock, rules_dir.clone());

    let rule1 = r#"alert tcp any any -> any any (msg:"rule1"; sid:1;)"#;
    let rule2 = r#"alert tcp any any -> any any (msg:"rule2"; sid:2;)"#;
    coord.add_rule("a.rules", rule1).unwrap();
    coord.add_rule("a.rules", rule2).unwrap();

    let content = std::fs::read_to_string(rules_dir.join("a.rules")).unwrap();
    assert!(content.contains(rule1), "rule1 should be present");
    assert!(content.contains(rule2), "rule2 should be present");

    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_add_rule_rejects_comment() {
    let rules_dir = make_tmp_rules_dir("add_comment");
    let mock = MockRuntime::new();
    let coord = make_coord(mock, rules_dir.clone());

    let res = coord.add_rule("x.rules", "# comment");
    assert!(res.is_err(), "comment line should be rejected");

    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_add_rule_rejects_empty() {
    let rules_dir = make_tmp_rules_dir("add_empty");
    let mock = MockRuntime::new();
    let coord = make_coord(mock, rules_dir.clone());

    let res = coord.add_rule("x.rules", "   ");
    assert!(res.is_err(), "empty rule should be rejected");

    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_delete_rules_by_sid_removes_matching() {
    let rules_dir = make_tmp_rules_dir("delete_sid");
    let mock = MockRuntime::new();
    let coord = make_coord(mock, rules_dir.clone());

    let rules = concat!(
        "alert tcp any any -> any any (msg:\"r1\"; sid:1;)\n",
        "alert tcp any any -> any any (msg:\"r2\"; sid:2;)\n",
        "alert tcp any any -> any any (msg:\"r3\"; sid:3;)\n",
    );
    std::fs::write(rules_dir.join("rules.rules"), rules).unwrap();

    let removed = coord.delete_rules_by_sid("rules.rules", &[2]).unwrap();
    assert_eq!(removed, 1);

    let content = std::fs::read_to_string(rules_dir.join("rules.rules")).unwrap();
    assert!(!content.contains("sid:2;"), "sid:2 should be removed");
    assert!(content.contains("sid:1;"), "sid:1 should remain");
    assert!(content.contains("sid:3;"), "sid:3 should remain");

    let _ = std::fs::remove_dir_all(rules_dir);
}

/// Regression: `parse_sid` previously did a naive substring search for `sid:`,
/// which would match `sid:N` embedded inside a `content:"..."` value. This made
/// `delete_rules_by_sid` either delete the wrong rule or miss the intended one.
#[test]
fn test_delete_rules_by_sid_ignores_sid_inside_content_string() {
    let rules_dir = make_tmp_rules_dir("delete_sid_in_content");
    let mock = MockRuntime::new();
    let coord = make_coord(mock, rules_dir.clone());

    // Rule A's *content* contains the literal "sid:42", but its real SID is 100.
    // Rule B has SID 42. Asking to delete SID 42 must remove only B, not A.
    let rules = concat!(
        "alert tcp any any -> any any (msg:\"r1\"; content:\"sid:42\"; sid:100;)\n",
        "alert tcp any any -> any any (msg:\"r2\"; sid:42;)\n",
    );
    std::fs::write(rules_dir.join("rules.rules"), rules).unwrap();

    let removed = coord.delete_rules_by_sid("rules.rules", &[42]).unwrap();
    assert_eq!(
        removed, 1,
        "only the rule whose real SID is 42 should be removed"
    );

    let content = std::fs::read_to_string(rules_dir.join("rules.rules")).unwrap();
    assert!(
        content.contains("sid:100;"),
        "rule with real SID 100 must remain even though its content contains \"sid:42\""
    );
    assert!(
        !content.contains("(msg:\"r2\""),
        "rule r2 (real SID 42) should have been removed"
    );

    let _ = std::fs::remove_dir_all(rules_dir);
}

/// Regression: keywords like `ssid:` end in `sid:` and previously matched the
/// naive substring search. The rule's true `sid:` value must win.
#[test]
fn test_delete_rules_by_sid_not_confused_by_similar_keyword() {
    let rules_dir = make_tmp_rules_dir("delete_sid_ssid");
    let mock = MockRuntime::new();
    let coord = make_coord(mock, rules_dir.clone());

    // `ssid:7` looks like `sid:7` to a naive scanner. The real sid is 500.
    let rules = "alert tcp any any -> any any (msg:\"r\"; ssid:7; sid:500;)\n";
    std::fs::write(rules_dir.join("rules.rules"), rules).unwrap();

    // Deleting sid=7 should be a no-op.
    let removed = coord.delete_rules_by_sid("rules.rules", &[7]).unwrap();
    assert_eq!(
        removed, 0,
        "no rule actually has sid=7; ssid:7 must not match"
    );

    // Deleting sid=500 should remove the rule.
    let removed = coord.delete_rules_by_sid("rules.rules", &[500]).unwrap();
    assert_eq!(removed, 1);

    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_delete_rule_file_removes_file() {
    let rules_dir = make_tmp_rules_dir("delete_file");
    let mock = MockRuntime::new();
    let coord = make_coord(mock, rules_dir.clone());

    std::fs::write(
        rules_dir.join("to_delete.rules"),
        "alert tcp any any -> any any (msg:\"x\"; sid:1;)\n",
    )
    .unwrap();
    coord.delete_rule_file("to_delete.rules").unwrap();

    assert!(
        !rules_dir.join("to_delete.rules").exists(),
        "file should be deleted"
    );

    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_delete_all_custom_rules() {
    let rules_dir = make_tmp_rules_dir("delete_all");
    let mock = MockRuntime::new();
    let coord = make_coord(mock, rules_dir.clone());

    std::fs::write(
        rules_dir.join("a.rules"),
        "alert tcp any any -> any any (msg:\"a\"; sid:1;)\n",
    )
    .unwrap();
    std::fs::write(
        rules_dir.join("b.rules"),
        "alert tcp any any -> any any (msg:\"b\"; sid:2;)\n",
    )
    .unwrap();

    let count = coord.delete_all_custom_rules().unwrap();
    assert_eq!(count, 2);
    assert!(!rules_dir.join("a.rules").exists());
    assert!(!rules_dir.join("b.rules").exists());

    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_list_custom_rules_sorted() {
    let rules_dir = make_tmp_rules_dir("list_rules");
    let mock = MockRuntime::new();
    let coord = make_coord(mock, rules_dir.clone());

    std::fs::write(
        rules_dir.join("b.rules"),
        "alert tcp any any -> any any (msg:\"b\"; sid:2;)\n",
    )
    .unwrap();
    std::fs::write(
        rules_dir.join("a.rules"),
        concat!(
            "alert tcp any any -> any any (msg:\"a1\"; sid:1;)\n",
            "alert tcp any any -> any any (msg:\"a2\"; sid:3;)\n",
        ),
    )
    .unwrap();

    let list = coord.list_custom_rules();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].0, "a.rules", "should be sorted alphabetically");
    assert_eq!(list[1].0, "b.rules");
    assert_eq!(list[0].1.len(), 2, "a.rules should have 2 rules");
    assert_eq!(list[1].1.len(), 1, "b.rules should have 1 rule");

    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_get_status_running() {
    let rules_dir = make_tmp_rules_dir("status_running");
    let mut mock = MockRuntime::new();
    mock.expect_is_running().times(1).returning(|| true);
    mock.expect_get_pid().times(1).returning(|| Some(42));
    mock.expect_get_version()
        .times(1)
        .returning(|| Some("7.0.3".to_string()));

    let coord = make_coord(mock, rules_dir.clone());
    let status = coord.get_status();
    assert!(status.running);
    assert_eq!(status.pid, Some(42));
    assert_eq!(status.version, Some("7.0.3".to_string()));

    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_get_status_not_running() {
    let rules_dir = make_tmp_rules_dir("status_not_running");
    let mut mock = MockRuntime::new();
    mock.expect_is_running().times(1).returning(|| false);
    // get_pid should NOT be called when not running
    mock.expect_get_version().times(1).returning(|| None);

    let coord = make_coord(mock, rules_dir.clone());
    let status = coord.get_status();
    assert!(!status.running);
    assert_eq!(status.pid, None);
    assert_eq!(status.version, None);

    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_reload_rules_delegates() {
    let rules_dir = make_tmp_rules_dir("reload_rules");
    let mut mock = MockRuntime::new();
    mock.expect_reload_rules()
        .with(mockall::predicate::always())
        .times(1)
        .returning(|_| Ok(()));

    let coord = make_coord(mock, rules_dir.clone());
    let res = coord.reload_rules();
    assert!(res.is_ok());

    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_is_running_delegates() {
    let rules_dir = make_tmp_rules_dir("is_running");
    let mut mock = MockRuntime::new();
    mock.expect_is_running().times(1).returning(|| true);

    let coord = make_coord(mock, rules_dir.clone());
    assert!(coord.is_running());
    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_is_running_false() {
    let rules_dir = make_tmp_rules_dir("is_running_false");
    let mut mock = MockRuntime::new();
    mock.expect_is_running().times(1).returning(|| false);

    let coord = make_coord(mock, rules_dir.clone());
    assert!(!coord.is_running());
    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_apply_config_writes_env_and_restarts() {
    let rules_dir = make_tmp_rules_dir("apply_config");
    let mut mock = MockRuntime::new();
    mock.expect_write_systemd_env()
        .with(eq("pe-inspect1"))
        .times(1)
        .returning(|_| Ok(()));
    mock.expect_restart_service().times(1).returning(|| Ok(()));

    let coord = make_coord(mock, rules_dir.clone());
    assert!(coord.apply_config("pe-inspect1").is_ok());
    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_apply_config_restart_failure_is_ok() {
    // apply_config should succeed even when restart fails (logs a warning)
    let rules_dir = make_tmp_rules_dir("apply_config_restart_fail");
    let mut mock = MockRuntime::new();
    mock.expect_write_systemd_env()
        .times(1)
        .returning(|_| Ok(()));
    mock.expect_restart_service()
        .times(1)
        .returning(|| Err(anyhow::anyhow!("systemctl not found")));

    let coord = make_coord(mock, rules_dir.clone());
    assert!(coord.apply_config("pe-inspect1").is_ok());
    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_apply_config_write_env_fails_returns_err() {
    let rules_dir = make_tmp_rules_dir("apply_config_env_fail");
    let mut mock = MockRuntime::new();
    mock.expect_write_systemd_env()
        .times(1)
        .returning(|_| Err(anyhow::anyhow!("permission denied")));
    // restart_service should NOT be called if write fails
    let coord = make_coord(mock, rules_dir.clone());
    assert!(coord.apply_config("pe-inspect1").is_err());
    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_remove_config_removes_env_and_restarts() {
    let rules_dir = make_tmp_rules_dir("remove_config");
    let mut mock = MockRuntime::new();
    mock.expect_remove_systemd_env()
        .times(1)
        .returning(|| Ok(()));
    mock.expect_restart_service().times(1).returning(|| Ok(()));

    let coord = make_coord(mock, rules_dir.clone());
    assert!(coord.remove_config().is_ok());
    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_remove_config_restart_failure_is_ok() {
    let rules_dir = make_tmp_rules_dir("remove_config_restart_fail");
    let mut mock = MockRuntime::new();
    mock.expect_remove_systemd_env()
        .times(1)
        .returning(|| Ok(()));
    mock.expect_restart_service()
        .times(1)
        .returning(|| Err(anyhow::anyhow!("systemctl not found")));

    let coord = make_coord(mock, rules_dir.clone());
    assert!(coord.remove_config().is_ok());
    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_start_delegates() {
    let rules_dir = make_tmp_rules_dir("start");
    let mut mock = MockRuntime::new();
    mock.expect_start().times(1).returning(|| Ok(()));

    let coord = make_coord(mock, rules_dir.clone());
    assert!(coord.start().is_ok());
    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_stop_delegates() {
    let rules_dir = make_tmp_rules_dir("stop");
    let mut mock = MockRuntime::new();
    mock.expect_stop().times(1).returning(|| Ok(()));

    let coord = make_coord(mock, rules_dir.clone());
    assert!(coord.stop().is_ok());
    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_suricata_version_delegates() {
    let rules_dir = make_tmp_rules_dir("version");
    let mut mock = MockRuntime::new();
    mock.expect_get_version()
        .times(1)
        .returning(|| Some("Suricata 7.0.3 RELEASE".to_string()));

    let coord = make_coord(mock, rules_dir.clone());
    assert_eq!(
        coord.suricata_version(),
        Some("Suricata 7.0.3 RELEASE".to_string())
    );
    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_suricata_version_none() {
    let rules_dir = make_tmp_rules_dir("version_none");
    let mut mock = MockRuntime::new();
    mock.expect_get_version().times(1).returning(|| None);

    let coord = make_coord(mock, rules_dir.clone());
    assert_eq!(coord.suricata_version(), None);
    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_ruleset_version_delegates() {
    let rules_dir = make_tmp_rules_dir("ruleset_version");
    let mut mock = MockRuntime::new();
    mock.expect_get_ruleset_version()
        .times(1)
        .returning(|| Some("2024-01-01".to_string()));

    let coord = make_coord(mock, rules_dir.clone());
    assert_eq!(coord.ruleset_version(), Some("2024-01-01".to_string()));
    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_eve_path_accessor() {
    let rules_dir = make_tmp_rules_dir("eve_path");
    let coord = make_coord(MockRuntime::new(), rules_dir.clone());
    assert_eq!(coord.eve_path(), &std::path::PathBuf::from("/tmp/eve.sock"));
    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_eve_socket_path_same_as_eve_path() {
    let rules_dir = make_tmp_rules_dir("eve_socket_path");
    let coord = make_coord(MockRuntime::new(), rules_dir.clone());
    assert_eq!(coord.eve_socket_path(), coord.eve_path());
    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_rules_dir_accessor() {
    let rules_dir = make_tmp_rules_dir("rules_dir");
    let coord = make_coord(MockRuntime::new(), rules_dir.clone());
    assert_eq!(coord.rules_dir(), &rules_dir);
    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_delete_rules_by_sid_nonexistent_file_errors() {
    let rules_dir = make_tmp_rules_dir("sid_no_file");
    let coord = make_coord(MockRuntime::new(), rules_dir.clone());
    let res = coord.delete_rules_by_sid("nonexistent.rules", &[1]);
    assert!(res.is_err());
    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_delete_rules_by_sid_multiple_sids() {
    let rules_dir = make_tmp_rules_dir("sid_multi");
    let coord = make_coord(MockRuntime::new(), rules_dir.clone());

    let rules = concat!(
        "alert tcp any any -> any any (msg:\"r1\"; sid:1;)\n",
        "alert tcp any any -> any any (msg:\"r2\"; sid:2;)\n",
        "alert tcp any any -> any any (msg:\"r3\"; sid:3;)\n",
        "# comment line\n",
    );
    std::fs::write(rules_dir.join("multi.rules"), rules).unwrap();

    let removed = coord.delete_rules_by_sid("multi.rules", &[1, 3]).unwrap();
    assert_eq!(removed, 2);

    let content = std::fs::read_to_string(rules_dir.join("multi.rules")).unwrap();
    assert!(!content.contains("sid:1;"));
    assert!(content.contains("sid:2;"));
    assert!(!content.contains("sid:3;"));
    assert!(content.contains("# comment line")); // comments preserved

    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_delete_rule_file_nonexistent_errors() {
    let rules_dir = make_tmp_rules_dir("delete_nonexistent");
    let coord = make_coord(MockRuntime::new(), rules_dir.clone());
    assert!(coord.delete_rule_file("no_such_file.rules").is_err());
    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_list_custom_rules_empty_dir() {
    let rules_dir = make_tmp_rules_dir("list_empty");
    let coord = make_coord(MockRuntime::new(), rules_dir.clone());
    assert!(coord.list_custom_rules().is_empty());
    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_list_custom_rules_ignores_non_rules_files() {
    let rules_dir = make_tmp_rules_dir("list_non_rules");
    let coord = make_coord(MockRuntime::new(), rules_dir.clone());
    std::fs::write(rules_dir.join("config.yaml"), "not a rules file").unwrap();
    std::fs::write(rules_dir.join("readme.txt"), "also not rules").unwrap();
    assert!(coord.list_custom_rules().is_empty());
    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_list_custom_rules_filters_blank_and_comment_lines() {
    let rules_dir = make_tmp_rules_dir("list_comments");
    let coord = make_coord(MockRuntime::new(), rules_dir.clone());
    let content = concat!(
        "# This is a comment\n",
        "\n",
        "   \n",
        "alert tcp any any -> any any (msg:\"real\"; sid:1;)\n",
    );
    std::fs::write(rules_dir.join("test.rules"), content).unwrap();

    let list = coord.list_custom_rules();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].1.len(), 1); // only the real rule line
    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_write_systemd_env_compat_delegates_and_restarts() {
    let rules_dir = make_tmp_rules_dir("write_env_compat");
    let mut mock = MockRuntime::new();
    mock.expect_write_systemd_env()
        .with(eq("pe-test0"))
        .times(1)
        .returning(|_| Ok(()));
    mock.expect_restart_service().times(1).returning(|| Ok(()));

    let coord = make_coord(mock, rules_dir.clone());
    assert!(coord.write_systemd_env("pe-test0").is_ok());
    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_remove_systemd_env_compat_delegates_and_restarts() {
    let rules_dir = make_tmp_rules_dir("remove_env_compat");
    let mut mock = MockRuntime::new();
    mock.expect_remove_systemd_env()
        .times(1)
        .returning(|| Ok(()));
    mock.expect_restart_service().times(1).returning(|| Ok(()));

    let coord = make_coord(mock, rules_dir.clone());
    assert!(coord.remove_systemd_env().is_ok());
    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn test_default_coord_uses_standard_paths() {
    // SuricataCoordinator::default() should not panic
    // We can't call it without SystemRuntime touching the real system,
    // but we can verify new_with_runtime sets up correctly.
    let rules_dir = make_tmp_rules_dir("default_paths");
    let coord = SuricataCoordinator::new_with_runtime(
        Arc::new(MockRuntime::new()),
        rules_dir.clone(),
        PathBuf::from("/run/policy-engine/eve.sock"),
        PathBuf::from("/var/run/suricata-command.socket"),
    );
    assert_eq!(
        coord.eve_path(),
        &PathBuf::from("/run/policy-engine/eve.sock")
    );
    let _ = std::fs::remove_dir_all(rules_dir);
}

#[test]
fn write_rules_digest_matches_input_bytes() {
    // Drift-detection contract with the fleet controller: write_rules must
    // store content byte-verbatim, and list_custom_rules_meta must hash the
    // raw file bytes — the controller hashes what it pushes and compares.
    // Any normalisation on either side would make the two digests oscillate
    // and re-push the ruleset on every snapshot.
    let rules_dir = make_tmp_rules_dir("digest");
    let coord = make_coord(MockRuntime::new(), rules_dir.clone());

    let content = "alert tcp any any -> any any (sid:1;)\n# a comment\n\nalert udp any any -> any any (sid:2;)\n";
    coord.write_rules("fleet-test.rules", content).unwrap();

    let metas = coord.list_custom_rules_meta();
    assert_eq!(metas.len(), 1);
    assert_eq!(metas[0].filename, "fleet-test.rules");

    use sha2::{Digest, Sha256};
    let expected = format!("{:x}", Sha256::digest(content.as_bytes()));
    assert_eq!(metas[0].sha256, expected, "sha256 must cover raw bytes");
    // Comment and blank lines are excluded from the parsed rule lines only.
    assert_eq!(metas[0].rules.len(), 2);

    // list_custom_rules stays consistent with the meta variant.
    let plain = coord.list_custom_rules();
    assert_eq!(plain[0].1, metas[0].rules);
    let _ = std::fs::remove_dir_all(rules_dir);
}
