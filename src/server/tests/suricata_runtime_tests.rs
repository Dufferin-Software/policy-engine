// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

use crate::server::suricata_runtime::{DefaultSuricataRuntime, SuricataRuntime};
use std::path::PathBuf;

fn make_tmp_root(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "policy_engine_test_{}_{}",
        name,
        std::process::id()
    ));
    // ensure clean
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Helper: create a SuricataRuntime in a temp root directory,
/// write the systemd env, and return (root_dir, runtime).
fn setup_written_env(label: &str) -> (PathBuf, DefaultSuricataRuntime) {
    let root = make_tmp_root(label);
    let rt = DefaultSuricataRuntime::new_with_root(&root);
    rt.write_systemd_env("pe-test1").expect("write failed");
    (root, rt)
}

#[test]
fn write_systemd_env_creates_files() {
    let root = make_tmp_root("write");
    let rt = DefaultSuricataRuntime::new_with_root(&root);

    rt.write_systemd_env("pe-test0")
        .expect("write_systemd_env failed");

    let policy = root.join("etc/suricata/policy-engine.yaml");
    let env = root.join("etc/suricata/suricata-policy-engine.env");
    let dropin = root.join("etc/systemd/system/suricata.service.d/policy-engine.conf");

    assert!(policy.exists(), "policy-engine.yaml should exist");
    assert!(env.exists(), "suricata env file should exist");
    assert!(dropin.exists(), "systemd drop-in should exist");

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn remove_systemd_env_removes_files() {
    let root = make_tmp_root("remove");
    let rt = DefaultSuricataRuntime::new_with_root(&root);

    // create first
    rt.write_systemd_env("pe-test0")
        .expect("write_systemd_env failed");

    // then remove
    rt.remove_systemd_env().expect("remove_systemd_env failed");

    let _policy = root.join("etc/suricata/policy-engine.yaml");
    let env = root.join("etc/suricata/suricata-policy-engine.env");
    let dropin = root.join("etc/systemd/system/suricata.service.d/policy-engine.conf");

    assert!(!env.exists(), "suricata env file should be removed");
    assert!(!dropin.exists(), "systemd drop-in should be removed");
    // policy file may still exist (we copied or created it) — it's acceptable.

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn remove_systemd_env_idempotent_when_files_absent() {
    let root = make_tmp_root("remove_idempotent");
    let rt = DefaultSuricataRuntime::new_with_root(&root);
    // Don't write first — removing non-existent files should be Ok
    assert!(rt.remove_systemd_env().is_ok());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_systemd_env_yaml_contains_iface() {
    let (root, _rt) = setup_written_env("yaml_iface");
    let yaml_path = root.join("etc/suricata/policy-engine.yaml");
    let content = std::fs::read_to_string(&yaml_path).unwrap();
    assert!(
        content.contains("pe-test1"),
        "YAML should mention the interface"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_systemd_env_yaml_has_eve_socket() {
    let (root, _rt) = setup_written_env("yaml_eve");
    let yaml_path = root.join("etc/suricata/policy-engine.yaml");
    let content = std::fs::read_to_string(&yaml_path).unwrap();
    assert!(
        content.contains("eve.sock"),
        "YAML should contain EVE socket path"
    );
    assert!(
        content.contains("unix_stream"),
        "YAML should use unix_stream filetype"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_systemd_env_yaml_has_af_packet_section() {
    let (root, _rt) = setup_written_env("yaml_afpkt");
    let yaml_path = root.join("etc/suricata/policy-engine.yaml");
    let content = std::fs::read_to_string(&yaml_path).unwrap();
    assert!(
        content.contains("af-packet"),
        "YAML should have af-packet section"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_systemd_env_yaml_enables_tpacket_v3() {
    let (root, _rt) = setup_written_env("yaml_tpv3");
    let yaml_path = root.join("etc/suricata/policy-engine.yaml");
    let content = std::fs::read_to_string(&yaml_path).unwrap();
    assert!(
        content.contains("tpacket-v3: yes"),
        "af-packet capture should use the v3 ring buffer"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_systemd_env_env_file_contains_iface() {
    let (root, _rt) = setup_written_env("env_iface");
    let env_path = root.join("etc/suricata/suricata-policy-engine.env");
    let content = std::fs::read_to_string(&env_path).unwrap();
    assert!(
        content.contains("pe-test1"),
        "Env file should mention interface"
    );
    assert!(
        content.contains("SURICATA_OPTS"),
        "Env file should set SURICATA_OPTS"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_systemd_env_dropin_references_env_file() {
    let (root, _rt) = setup_written_env("dropin_env_ref");
    let dropin_path = root.join("etc/systemd/system/suricata.service.d/policy-engine.conf");
    let content = std::fs::read_to_string(&dropin_path).unwrap();
    assert!(
        content.contains("EnvironmentFile"),
        "Drop-in should have EnvironmentFile directive"
    );
    assert!(
        content.contains("ExecStart"),
        "Drop-in should override ExecStart"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_then_remove_leaves_no_env_or_dropin() {
    let (root, rt) = setup_written_env("write_remove_cycle");
    rt.remove_systemd_env().unwrap();
    let env = root.join("etc/suricata/suricata-policy-engine.env");
    let dropin = root.join("etc/systemd/system/suricata.service.d/policy-engine.conf");
    assert!(!env.exists());
    assert!(!dropin.exists());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn get_ruleset_version_none_when_file_absent() {
    let root = make_tmp_root("ruleset_none");
    let rt = DefaultSuricataRuntime::new_with_root(&root);
    assert_eq!(rt.get_ruleset_version(), None);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn get_ruleset_version_reads_header_comment() {
    let root = make_tmp_root("ruleset_version");
    // Create the expected rules file with a version comment in the header
    let rules_dir = root.join("var/lib/suricata/rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let rules_path = rules_dir.join("suricata.rules");
    let content = "# updated 2024-01-15\nalert tcp any any -> any any (msg:\"test\"; sid:1;)\n";
    std::fs::write(&rules_path, content).unwrap();

    let rt = DefaultSuricataRuntime::new_with_root(&root);
    let version = rt.get_ruleset_version();
    assert!(version.is_some(), "Should find version from header comment");
    let v = version.unwrap();
    assert!(
        v.contains("2024-01-15"),
        "Version should contain the date: {}",
        v
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn get_ruleset_version_no_version_comment_returns_none() {
    let root = make_tmp_root("ruleset_no_version");
    let rules_dir = root.join("var/lib/suricata/rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let rules_path = rules_dir.join("suricata.rules");
    // File exists but first 10 lines have no version/date/updated keyword
    let content = "# This is just a rules file\nalert tcp any any -> any any (msg:\"x\"; sid:1;)\n";
    std::fs::write(&rules_path, content).unwrap();

    let rt = DefaultSuricataRuntime::new_with_root(&root);
    // None since no line with version/date/updated in first 10 lines
    let version = rt.get_ruleset_version();
    assert!(version.is_none());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_systemd_env_multiple_ifaces_overwrites() {
    let root = make_tmp_root("overwrite");
    let rt = DefaultSuricataRuntime::new_with_root(&root);

    rt.write_systemd_env("pe-first").unwrap();
    let path = root.join("etc/suricata/policy-engine.yaml");
    let first_content = std::fs::read_to_string(&path).unwrap();
    assert!(first_content.contains("pe-first"));

    rt.write_systemd_env("pe-second").unwrap();
    let second_content = std::fs::read_to_string(&path).unwrap();
    assert!(second_content.contains("pe-second"));
    assert!(!second_content.contains("pe-first"));

    let _ = std::fs::remove_dir_all(root);
}

// ── YAML content ─────────────────────────────────────────────────────────────

#[test]
fn write_systemd_env_yaml_has_yaml_header() {
    let (root, _rt) = setup_written_env("yaml_header");
    let content = std::fs::read_to_string(root.join("etc/suricata/policy-engine.yaml")).unwrap();
    assert!(
        content.contains("%YAML 1.1"),
        "YAML should start with %YAML 1.1 header"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_systemd_env_yaml_has_unix_command_section() {
    let (root, _rt) = setup_written_env("yaml_unix_cmd");
    let content = std::fs::read_to_string(root.join("etc/suricata/policy-engine.yaml")).unwrap();
    assert!(
        content.contains("unix-command"),
        "YAML should have unix-command section"
    );
    assert!(
        content.contains("suricata-command.socket"),
        "YAML should reference command socket"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_systemd_env_yaml_has_rule_files_section() {
    let (root, _rt) = setup_written_env("yaml_rules");
    let content = std::fs::read_to_string(root.join("etc/suricata/policy-engine.yaml")).unwrap();
    assert!(
        content.contains("rule-files"),
        "YAML should have rule-files section"
    );
    assert!(
        content.contains("suricata.rules"),
        "YAML should reference suricata.rules"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_systemd_env_yaml_has_app_layer_tls() {
    let (root, _rt) = setup_written_env("yaml_app_layer");
    let content = std::fs::read_to_string(root.join("etc/suricata/policy-engine.yaml")).unwrap();
    assert!(
        content.contains("app-layer"),
        "YAML should have app-layer section"
    );
    assert!(content.contains("tls"), "YAML should enable TLS app layer");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_systemd_env_yaml_has_eve_log_output() {
    let (root, _rt) = setup_written_env("yaml_eve_out");
    let content = std::fs::read_to_string(root.join("etc/suricata/policy-engine.yaml")).unwrap();
    assert!(
        content.contains("eve-log"),
        "YAML should configure eve-log output"
    );
    assert!(
        content.contains("unix_stream"),
        "EVE output should use unix_stream filetype"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_systemd_env_yaml_has_default_rule_path() {
    let (root, _rt) = setup_written_env("yaml_rule_path");
    let content = std::fs::read_to_string(root.join("etc/suricata/policy-engine.yaml")).unwrap();
    assert!(
        content.contains("default-rule-path"),
        "YAML should set default-rule-path"
    );
    assert!(
        content.contains("/var/lib/suricata/rules"),
        "YAML should point to suricata rules dir"
    );
    let _ = std::fs::remove_dir_all(root);
}

// ── Env file content ──────────────────────────────────────────────────────────

#[test]
fn write_systemd_env_env_file_has_config_path() {
    let (root, _rt) = setup_written_env("env_config_path");
    let content =
        std::fs::read_to_string(root.join("etc/suricata/suricata-policy-engine.env")).unwrap();
    // The -c flag followed by the config path
    assert!(content.contains("-c "), "Env file should pass -c flag");
    assert!(
        content.contains("policy-engine.yaml"),
        "Env file should reference the YAML config"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_systemd_env_env_file_has_pidfile() {
    let (root, _rt) = setup_written_env("env_pidfile");
    let content =
        std::fs::read_to_string(root.join("etc/suricata/suricata-policy-engine.env")).unwrap();
    assert!(content.contains("pidfile"), "Env file should set pidfile");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_systemd_env_env_file_has_daemonize_flag() {
    let (root, _rt) = setup_written_env("env_daemon");
    let content =
        std::fs::read_to_string(root.join("etc/suricata/suricata-policy-engine.env")).unwrap();
    // -D flag makes Suricata daemonize
    assert!(
        content.contains("-D"),
        "Env file should include -D (daemonize) flag"
    );
    let _ = std::fs::remove_dir_all(root);
}

// ── Drop-in content ───────────────────────────────────────────────────────────

#[test]
fn write_systemd_env_dropin_has_restart_on_failure() {
    let (root, _rt) = setup_written_env("dropin_restart");
    let content = std::fs::read_to_string(
        root.join("etc/systemd/system/suricata.service.d/policy-engine.conf"),
    )
    .unwrap();
    assert!(
        content.contains("Restart=on-failure"),
        "Drop-in should set Restart=on-failure"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_systemd_env_dropin_has_description() {
    let (root, _rt) = setup_written_env("dropin_description");
    let content = std::fs::read_to_string(
        root.join("etc/systemd/system/suricata.service.d/policy-engine.conf"),
    )
    .unwrap();
    assert!(
        content.contains("Description="),
        "Drop-in should have a Description field"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_systemd_env_dropin_clears_exec_start_before_setting() {
    let (root, _rt) = setup_written_env("dropin_execstart");
    let content = std::fs::read_to_string(
        root.join("etc/systemd/system/suricata.service.d/policy-engine.conf"),
    )
    .unwrap();
    // The empty ExecStart= must appear before the real one to clear inherited value.
    let first_pos = content
        .find("ExecStart=\n")
        .expect("should have blank ExecStart=");
    let second_pos = content
        .rfind("ExecStart=")
        .expect("should have second ExecStart=");
    assert!(
        first_pos < second_pos,
        "blank ExecStart= must appear before the real one"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_systemd_env_dropin_has_wants_policy_engine() {
    let (root, _rt) = setup_written_env("dropin_wants");
    let content = std::fs::read_to_string(
        root.join("etc/systemd/system/suricata.service.d/policy-engine.conf"),
    )
    .unwrap();
    assert!(
        content.contains("Wants=policy-engine.service"),
        "Drop-in should declare Wants= on policy-engine"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_systemd_env_dropin_has_after_policy_engine() {
    let (root, _rt) = setup_written_env("dropin_after");
    let content = std::fs::read_to_string(
        root.join("etc/systemd/system/suricata.service.d/policy-engine.conf"),
    )
    .unwrap();
    assert!(
        content.contains("After=policy-engine.service"),
        "Drop-in should order After= policy-engine"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_systemd_env_dropin_gates_on_engine_eve_socket() {
    let (root, _rt) = setup_written_env("dropin_condition");
    let content = std::fs::read_to_string(
        root.join("etc/systemd/system/suricata.service.d/policy-engine.conf"),
    )
    .unwrap();
    assert!(
        content.contains("ConditionPathExists=/run/policy-engine/eve.sock"),
        "Drop-in should skip Suricata starts while policy-engine is down"
    );
    let _ = std::fs::remove_dir_all(root);
}

// ── get_ruleset_version edge-cases ────────────────────────────────────────────

#[test]
fn get_ruleset_version_finds_version_keyword() {
    let root = make_tmp_root("rv_version_kw");
    let dir = root.join("var/lib/suricata/rules");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("suricata.rules"),
        "# suricata-update version 20240315\n",
    )
    .unwrap();
    let rt = DefaultSuricataRuntime::new_with_root(&root);
    let v = rt.get_ruleset_version().expect("should find version line");
    assert!(v.contains("20240315"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn get_ruleset_version_finds_date_keyword() {
    let root = make_tmp_root("rv_date_kw");
    let dir = root.join("var/lib/suricata/rules");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("suricata.rules"), "# date 2024-06-01\n").unwrap();
    let rt = DefaultSuricataRuntime::new_with_root(&root);
    let v = rt.get_ruleset_version().expect("should find date line");
    assert!(v.contains("2024-06-01"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn get_ruleset_version_finds_updated_keyword() {
    let root = make_tmp_root("rv_updated_kw");
    let dir = root.join("var/lib/suricata/rules");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("suricata.rules"), "# last updated 2024-09-10\n").unwrap();
    let rt = DefaultSuricataRuntime::new_with_root(&root);
    let v = rt.get_ruleset_version().expect("should find updated line");
    assert!(v.contains("2024-09-10"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn get_ruleset_version_only_scans_first_10_lines() {
    let root = make_tmp_root("rv_10_lines");
    let dir = root.join("var/lib/suricata/rules");
    std::fs::create_dir_all(&dir).unwrap();
    // Put the version comment on line 11 — should NOT be found.
    let mut content = String::new();
    for i in 1..=10 {
        content.push_str(&format!("# comment {}\n", i));
    }
    content.push_str("# version 2024-12-01\n");
    std::fs::write(dir.join("suricata.rules"), content).unwrap();
    let rt = DefaultSuricataRuntime::new_with_root(&root);
    assert_eq!(
        rt.get_ruleset_version(),
        None,
        "version beyond line 10 should not be found"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn get_ruleset_version_empty_file_returns_none() {
    let root = make_tmp_root("rv_empty");
    let dir = root.join("var/lib/suricata/rules");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("suricata.rules"), "").unwrap();
    let rt = DefaultSuricataRuntime::new_with_root(&root);
    assert_eq!(rt.get_ruleset_version(), None);
    let _ = std::fs::remove_dir_all(root);
}
