// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Tests for the flow verdict cache primitive without the Suricata feature.
//!
//! Phase 1 of the QUIC SNI work promotes the flow verdict cache to the base
//! feature set so future inspectors (QUIC SNI today, others later) can write
//! verdicts even in builds compiled without `suricata`.  These tests exercise
//! the trait surface via the mock BPF adaptor to confirm the cache is reachable
//! in non-Suricata builds.

use crate::traits::{BpfOperations, MockBpfOperations};
use crate::types::*;

fn make_key(saddr: [u8; 4], daddr: [u8; 4], sport: u16, dport: u16) -> FlowVerdictKey {
    let mut key = FlowVerdictKey::default();
    key.saddr[..4].copy_from_slice(&saddr);
    key.daddr[..4].copy_from_slice(&daddr);
    key.sport = sport;
    key.dport = dport;
    key.protocol = libc::IPPROTO_UDP as u8;
    key.af = AF_INET;
    key
}

fn make_drop_verdict() -> FlowVerdict {
    FlowVerdict {
        action: PolicyAction::Drop as u32,
        _pad: 0,
        timestamp_ns: 1,
        expires_ns: 0,
        packets: 0,
        bytes: 0,
        last_seen_ns: 0,
        rule_id: 0,
    }
}

#[test]
fn update_verdict_dispatches_to_correct_direction() {
    let mut mock = MockBpfOperations::new();
    mock.expect_update_flow_verdict()
        .withf(|_, _, dir| *dir == Direction::Ingress)
        .times(1)
        .returning(|_, _, _| Ok(()));
    mock.expect_update_flow_verdict()
        .withf(|_, _, dir| *dir == Direction::Egress)
        .times(1)
        .returning(|_, _, _| Ok(()));

    let key = make_key([10, 0, 0, 1], [10, 0, 0, 2], 12345, 443);
    let verdict = make_drop_verdict();
    mock.update_flow_verdict(&key, &verdict, Direction::Ingress)
        .unwrap();
    mock.update_flow_verdict(&key, &verdict, Direction::Egress)
        .unwrap();
}

#[test]
fn list_and_delete_round_trip() {
    let mut mock = MockBpfOperations::new();
    let key = make_key([10, 0, 0, 1], [10, 0, 0, 2], 12345, 443);
    let verdict = make_drop_verdict();
    let listed = vec![(key, verdict)];
    mock.expect_list_flow_verdicts()
        .returning(move |_| Ok(listed.clone()));
    mock.expect_delete_flow_verdict()
        .times(1)
        .returning(|_, _| Ok(()));

    let entries = mock.list_flow_verdicts(Direction::Ingress).unwrap();
    assert_eq!(entries.len(), 1);
    for (k, _) in entries {
        mock.delete_flow_verdict(&k, Direction::Ingress).unwrap();
    }
}

#[test]
fn count_reflects_active_verdicts() {
    let mut mock = MockBpfOperations::new();
    mock.expect_get_flow_verdict_count().returning(|_| Ok(42));
    assert_eq!(mock.get_flow_verdict_count(Direction::Ingress).unwrap(), 42);
}
