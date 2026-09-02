// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

use super::super::veth_manager::{MockVethOps, VethManager};
use mockall::predicate::eq;
use std::sync::Arc;

#[test]
fn test_create_pair_when_not_exists() {
    let mut ops = MockVethOps::new();
    ops.expect_interface_exists().returning(|_| false);
    ops.expect_create_pair().returning(|_, _| Ok(()));
    ops.expect_bring_up().times(2).returning(|_| Ok(()));

    let mut mgr = VethManager::new_with_ops(Arc::new(ops));
    assert!(mgr.create_pair().is_ok());
    assert!(mgr.is_created());
}

#[test]
fn test_create_pair_when_already_exists() {
    let mut ops = MockVethOps::new();
    // Interface already up — create_pair should skip create and bring_up
    ops.expect_interface_exists().returning(|_| true);
    // create_pair and bring_up should NOT be called

    let mut mgr = VethManager::new_with_ops(Arc::new(ops));
    assert!(mgr.create_pair().is_ok());
    assert!(mgr.is_created());
}

#[test]
fn test_destroy_pair() {
    let mut ops = MockVethOps::new();
    ops.expect_destroy_pair().returning(|_| Ok(()));

    let mut mgr = VethManager::new_with_ops(Arc::new(ops));
    assert!(mgr.destroy_pair().is_ok());
    assert!(!mgr.is_created());
}

#[test]
fn test_get_ifindex() {
    let mut ops = MockVethOps::new();
    ops.expect_get_ifindex().returning(|_| Ok(42));

    let mgr = VethManager::new_with_ops(Arc::new(ops));
    assert_eq!(mgr.get_ifindex().unwrap(), 42);
}

#[test]
fn test_is_up_delegates() {
    let mut ops = MockVethOps::new();
    ops.expect_interface_exists().returning(|_| true);

    let mgr = VethManager::new_with_ops(Arc::new(ops));
    assert!(mgr.is_up());
}

#[test]
fn test_is_up_false() {
    let mut ops = MockVethOps::new();
    ops.expect_interface_exists().returning(|_| false);

    let mgr = VethManager::new_with_ops(Arc::new(ops));
    assert!(!mgr.is_up());
}

#[test]
fn test_veth_name_is_pe_inspect0() {
    let ops = MockVethOps::new();
    let mgr = VethManager::new_with_ops(Arc::new(ops));
    assert_eq!(mgr.veth_name(), "pe-inspect0");
}

#[test]
fn test_peer_name_is_pe_inspect1() {
    let ops = MockVethOps::new();
    let mgr = VethManager::new_with_ops(Arc::new(ops));
    assert_eq!(mgr.peer_name(), "pe-inspect1");
}

#[test]
fn test_is_created_initially_false() {
    let ops = MockVethOps::new();
    let mgr = VethManager::new_with_ops(Arc::new(ops));
    assert!(!mgr.is_created());
}

#[test]
fn test_bring_up_calls_both_interfaces() {
    let mut ops = MockVethOps::new();
    // bring_up should be called for both pe-inspect0 and pe-inspect1
    ops.expect_bring_up().times(2).returning(|_| Ok(()));

    let mgr = VethManager::new_with_ops(Arc::new(ops));
    assert!(mgr.bring_up().is_ok());
}

#[test]
fn test_bring_up_fails_on_first_error() {
    let mut ops = MockVethOps::new();
    ops.expect_bring_up()
        .times(1)
        .returning(|_| Err(anyhow::anyhow!("ip command failed")));

    let mgr = VethManager::new_with_ops(Arc::new(ops));
    assert!(mgr.bring_up().is_err());
}

#[test]
fn test_create_pair_calls_create_and_bring_up_when_not_exists() {
    let mut ops = MockVethOps::new();
    ops.expect_interface_exists().returning(|_| false);
    ops.expect_create_pair().times(1).returning(|_, _| Ok(()));
    ops.expect_bring_up().times(2).returning(|_| Ok(()));

    let mut mgr = VethManager::new_with_ops(Arc::new(ops));
    assert!(mgr.create_pair().is_ok());
    assert!(mgr.is_created());
}

#[test]
fn test_create_pair_fails_propagates_error() {
    let mut ops = MockVethOps::new();
    ops.expect_interface_exists().returning(|_| false);
    ops.expect_create_pair()
        .times(1)
        .returning(|_, _| Err(anyhow::anyhow!("veth create failed")));

    let mut mgr = VethManager::new_with_ops(Arc::new(ops));
    assert!(mgr.create_pair().is_err());
    assert!(!mgr.is_created());
}

#[test]
fn test_destroy_pair_sets_created_false() {
    let mut ops = MockVethOps::new();
    ops.expect_interface_exists().returning(|_| false);
    ops.expect_create_pair().returning(|_, _| Ok(()));
    ops.expect_bring_up().returning(|_| Ok(()));
    ops.expect_destroy_pair().returning(|_| Ok(()));

    let mut mgr = VethManager::new_with_ops(Arc::new(ops));
    mgr.create_pair().unwrap();
    assert!(mgr.is_created());
    mgr.destroy_pair().unwrap();
    assert!(!mgr.is_created());
}

#[test]
fn test_destroy_pair_error_propagates() {
    let mut ops = MockVethOps::new();
    ops.expect_destroy_pair()
        .returning(|_| Err(anyhow::anyhow!("destroy failed")));

    let mut mgr = VethManager::new_with_ops(Arc::new(ops));
    assert!(mgr.destroy_pair().is_err());
}

#[test]
fn test_get_ifindex_error() {
    let mut ops = MockVethOps::new();
    ops.expect_get_ifindex()
        .returning(|_| Err(anyhow::anyhow!("interface not found")));

    let mgr = VethManager::new_with_ops(Arc::new(ops));
    assert!(mgr.get_ifindex().is_err());
}

#[test]
fn test_drop_when_not_created_no_panic() {
    let ops = MockVethOps::new();
    let mgr = VethManager::new_with_ops(Arc::new(ops));
    drop(mgr); // should not panic
}

#[test]
fn test_drop_when_created_no_panic() {
    let mut ops = MockVethOps::new();
    ops.expect_interface_exists().returning(|_| false);
    ops.expect_create_pair().returning(|_, _| Ok(()));
    ops.expect_bring_up().returning(|_| Ok(()));

    let mut mgr = VethManager::new_with_ops(Arc::new(ops));
    mgr.create_pair().unwrap();
    drop(mgr); // should not panic (just logs debug message)
}

// ── Interface name correctness ────────────────────────────────────────────────

#[test]
fn test_create_pair_passes_correct_names_to_ops() {
    let mut ops = MockVethOps::new();
    ops.expect_interface_exists().returning(|_| false);
    // create_pair must be called with exactly (pe-inspect0, pe-inspect1)
    ops.expect_create_pair()
        .with(eq("pe-inspect0"), eq("pe-inspect1"))
        .times(1)
        .returning(|_, _| Ok(()));
    ops.expect_bring_up().returning(|_| Ok(()));

    let mut mgr = VethManager::new_with_ops(Arc::new(ops));
    mgr.create_pair().unwrap();
}

#[test]
fn test_destroy_pair_passes_correct_name() {
    let mut ops = MockVethOps::new();
    // destroy must be called with pe-inspect0 (our side, deleting it removes the pair)
    ops.expect_destroy_pair()
        .with(eq("pe-inspect0"))
        .times(1)
        .returning(|_| Ok(()));

    let mut mgr = VethManager::new_with_ops(Arc::new(ops));
    mgr.destroy_pair().unwrap();
}

#[test]
fn test_get_ifindex_queries_pe_inspect0() {
    let mut ops = MockVethOps::new();
    ops.expect_get_ifindex()
        .with(eq("pe-inspect0"))
        .returning(|_| Ok(7));

    let mgr = VethManager::new_with_ops(Arc::new(ops));
    assert_eq!(mgr.get_ifindex().unwrap(), 7);
}

#[test]
fn test_is_up_checks_pe_inspect0() {
    let mut ops = MockVethOps::new();
    ops.expect_interface_exists()
        .with(eq("pe-inspect0"))
        .returning(|_| true);

    let mgr = VethManager::new_with_ops(Arc::new(ops));
    assert!(mgr.is_up());
}

#[test]
fn test_bring_up_calls_pe_inspect0_then_pe_inspect1() {
    let mut ops = MockVethOps::new();
    // Both interfaces must be brought up by name.
    ops.expect_bring_up()
        .with(eq("pe-inspect0"))
        .times(1)
        .returning(|_| Ok(()));
    ops.expect_bring_up()
        .with(eq("pe-inspect1"))
        .times(1)
        .returning(|_| Ok(()));

    let mgr = VethManager::new_with_ops(Arc::new(ops));
    mgr.bring_up().unwrap();
}

// ── is_created lifecycle ──────────────────────────────────────────────────────

#[test]
fn test_is_created_true_after_create_when_already_exists() {
    let mut ops = MockVethOps::new();
    // Simulate existing pair — no create_pair or bring_up should be called.
    ops.expect_interface_exists().returning(|_| true);

    let mut mgr = VethManager::new_with_ops(Arc::new(ops));
    mgr.create_pair().unwrap();
    assert!(mgr.is_created());
}

#[test]
fn test_is_created_false_after_create_then_destroy() {
    let mut ops = MockVethOps::new();
    ops.expect_interface_exists().returning(|_| false);
    ops.expect_create_pair().returning(|_, _| Ok(()));
    ops.expect_bring_up().returning(|_| Ok(()));
    ops.expect_destroy_pair().returning(|_| Ok(()));

    let mut mgr = VethManager::new_with_ops(Arc::new(ops));
    mgr.create_pair().unwrap();
    assert!(mgr.is_created());
    mgr.destroy_pair().unwrap();
    assert!(!mgr.is_created());
}

#[test]
fn test_create_pair_bring_up_failure_propagates() {
    let mut ops = MockVethOps::new();
    ops.expect_interface_exists().returning(|_| false);
    ops.expect_create_pair().returning(|_, _| Ok(()));
    ops.expect_bring_up()
        .times(1)
        .returning(|_| Err(anyhow::anyhow!("ip link set failed")));

    let mut mgr = VethManager::new_with_ops(Arc::new(ops));
    assert!(mgr.create_pair().is_err());
    // created flag should NOT be set on failure
    assert!(!mgr.is_created());
}
