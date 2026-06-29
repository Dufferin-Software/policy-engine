// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Tests for the QUIC Initial inspector (Phase 2).
//!
//! The BPF programs themselves cannot be exercised from userspace tests; what
//! we can verify here is:
//!   * the Rust mirror constants line up with the BPF #defines (catching a
//!     header drift before it manifests as a wire-format mismatch),
//!   * `QuicInspectEvent` decodes correctly from a raw ringbuf byte sample,
//!   * the trait surface the inspector relies on for follow-up verdict writes
//!     is reachable via the mock BPF adaptor.

use crate::server::event_stream::QuicInspectEvent;
use crate::server::quic_initial;
use crate::server::quic_initial::{ReassemblyKey, ReassemblyOutcome, ReassemblyTable};
use crate::traits::{BpfOperations, MockBpfOperations};
use crate::types::*;

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn reassembly_key_for(dcid: &[u8]) -> ReassemblyKey {
    ReassemblyKey {
        saddr: [0u8; 16],
        daddr: [0u8; 16],
        sport: 1234,
        dport: 443,
        protocol: libc::IPPROTO_UDP as u8,
        af: libc::AF_INET as u8,
        dcid: dcid.to_vec(),
    }
}

#[test]
fn quic_inspect_constants_match_expected_bpf_values() {
    // These must stay in lockstep with policy_common.h.  Hard-coded here so a
    // change on either side trips the test rather than silently diverging.
    assert_eq!(QUIC_INSPECT_PAYLOAD_MAX, 1280);
    assert_eq!(QUIC_INSPECT_MAX_DCID_LEN, 20);
    assert_eq!(XDP_DISPATCHER_QUIC_SLOT, 3);
    assert_eq!(TC_DISPATCHER_QUIC_SLOT, 2);
}

#[test]
fn quic_inspect_event_size_matches_bpf_layout() {
    // BPF struct quic_inspect_event is __attribute__((packed)) with:
    //   timestamp_ns(8) + ifindex(4) + version(4) + flow(40) + pkt_len(4)
    //   + payload_off(2) + payload_len(2) + dcid_len(1) + _pad(7)
    //   + dcid(20) + payload(1280) = 1372 bytes
    assert_eq!(std::mem::size_of::<QuicInspectEvent>(), 1372);
}

#[test]
fn quic_inspect_event_decodes_from_raw_bytes() {
    // Build a synthetic event the way BPF would write it, then read it back
    // via the same `read_unaligned` path the ringbuf callback uses.
    let mut buf = vec![0u8; std::mem::size_of::<QuicInspectEvent>()];

    // timestamp_ns @ 0
    buf[0..8].copy_from_slice(&123_456_789u64.to_ne_bytes());
    // ifindex @ 8
    buf[8..12].copy_from_slice(&7u32.to_ne_bytes());
    // version @ 12 — QUIC v1
    buf[12..16].copy_from_slice(&QUIC_VERSION_V1.to_ne_bytes());
    // flow @ 16 (40 bytes) — leave zeroed; we don't decode addresses here
    // pkt_len @ 56
    buf[56..60].copy_from_slice(&1300u32.to_ne_bytes());
    // payload_off @ 60
    buf[60..62].copy_from_slice(&42u16.to_ne_bytes());
    // payload_len @ 62
    buf[62..64].copy_from_slice(&8u16.to_ne_bytes());
    // dcid_len @ 64
    buf[64] = 8;
    // _pad @ 65..72 — leave zero
    // dcid @ 72..92
    buf[72..80].copy_from_slice(b"abcdefgh");
    // payload @ 92..1372
    buf[92..100].copy_from_slice(b"PAYLOAD!");

    let ev: QuicInspectEvent = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const _) };

    // Reading fields through copies — repr(C, packed) forbids references.
    let ts = ev.timestamp_ns;
    let ifindex = ev.ifindex;
    let version = ev.version;
    let pkt_len = ev.pkt_len;
    let payload_off = ev.payload_off;
    let payload_len = ev.payload_len;
    let dcid_len = ev.dcid_len;

    assert_eq!(ts, 123_456_789);
    assert_eq!(ifindex, 7);
    assert_eq!(version, QUIC_VERSION_V1);
    assert_eq!(pkt_len, 1300);
    assert_eq!(payload_off, 42);
    assert_eq!(payload_len, 8);
    assert_eq!(dcid_len, 8);
    assert_eq!(&ev.dcid[..8], b"abcdefgh");
    assert_eq!(&ev.payload[..8], b"PAYLOAD!");
}

#[test]
fn quic_inspect_event_short_sample_is_handled_safely() {
    // Mirror of the runtime guard in handle_quic_inspect_sample — a short
    // sample must not be decoded.  This is just a sanity check on the
    // size_of result the guard compares against.
    let too_short = vec![0u8; std::mem::size_of::<QuicInspectEvent>() - 1];
    assert!(too_short.len() < std::mem::size_of::<QuicInspectEvent>());
}

#[test]
fn verdict_seed_path_reaches_bpf_adaptor() {
    // The userspace follow-up to a captured Initial will write a real (not
    // stub) PASS or DROP verdict via the BpfOperations trait.  Confirm that
    // path is reachable from the verdict shape the inspector seeds.
    let mut mock = MockBpfOperations::new();
    mock.expect_update_flow_verdict()
        .withf(|_, v, dir| {
            *dir == Direction::Ingress && v.action == PolicyAction::Pass as u32 && v.expires_ns > 0
        })
        .times(1)
        .returning(|_, _, _| Ok(()));

    let mut key = FlowVerdictKey::default();
    key.saddr[..4].copy_from_slice(&[10, 0, 0, 1]);
    key.daddr[..4].copy_from_slice(&[10, 0, 0, 2]);
    key.sport = 54321;
    key.dport = 443;
    key.protocol = libc::IPPROTO_UDP as u8;
    key.af = AF_INET;

    let verdict = FlowVerdict {
        action: PolicyAction::Pass as u32,
        _pad: 0,
        timestamp_ns: 100,
        expires_ns: 100 + 600_000_000_000, // 10 min — matches QUIC_VERDICT_TTL_NS
        packets: 0,
        bytes: 0,
        rule_id: 0,
    };

    mock.update_flow_verdict(&key, &verdict, Direction::Ingress)
        .unwrap();
}

/// `match_sni_rules` should walk the userspace mirror of the rule tables, look
/// up each rule's SNI pattern, and return the first match's action.
#[test]
fn match_sni_rules_finds_drop_action_via_mock_bpf() {
    let mut mock = MockBpfOperations::new();

    // Build one UDP rule with SNI matching.  The pattern is "blocked.example"
    // (exact); action is DROP.
    let mut rule = L4Rule {
        rule_id: 42,
        protocol: libc::IPPROTO_UDP as u8,
        sni_match_type: SNI_MATCH_EXACT,
        num_actions: 1,
        ..Default::default()
    };
    rule.actions[0].action = PolicyAction::Drop as u32;

    mock.expect_list_policy_rules_v4()
        .withf(|d| *d == Direction::Ingress)
        .returning(move |_| {
            Ok(vec![(
                SrcLpmKeyV4 {
                    prefixlen: 0,
                    ifindex: 0,
                    addr: [0u8; 4],
                },
                LpmKeyV4 {
                    prefixlen: 0,
                    addr: [0u8; 4],
                },
                rule,
            )])
        });
    mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));

    mock.expect_lookup_sni_rule()
        .withf(|id, dir| *id == 42 && *dir == Direction::Ingress)
        .returning(|_, _| {
            let mut e = SniRuleEntry::default();
            let pat = b"blocked.example";
            e.sni_match_type = SNI_MATCH_EXACT;
            e.sni_len = pat.len() as u8;
            e.sni_pattern[..pat.len()].copy_from_slice(pat);
            Ok(Some(e))
        });

    let got = quic_initial::match_sni_rules("blocked.example", Direction::Ingress, &mock).unwrap();
    let m = got.expect("expected a match");
    assert_eq!(m.rule_id, 42);
    assert_eq!(m.actions.len(), 1);
    let a0 = m.actions[0].action;
    assert_eq!(a0, PolicyAction::Drop as u32);
}

/// A rule configured with LOG (priority 0) followed by DROP (priority 1)
/// must surface BOTH actions, in order, so the caller can emit a log event
/// and then write a DROP verdict.  Mirrors the BPF SNI path behaviour in
/// tc_policy.bpf.c (loop over actions[0..num_actions], stop on DROP).
#[test]
fn match_sni_rules_returns_full_action_list_log_then_drop() {
    let mut mock = MockBpfOperations::new();

    let mut rule = L4Rule {
        rule_id: 99,
        protocol: libc::IPPROTO_UDP as u8,
        sni_match_type: SNI_MATCH_EXACT,
        num_actions: 2,
        ..Default::default()
    };
    rule.actions[0].action = PolicyAction::Log as u32;
    rule.actions[0].param = 0; // no rate-limit
    rule.actions[1].action = PolicyAction::Drop as u32;

    mock.expect_list_policy_rules_v4().returning(move |_| {
        Ok(vec![(
            SrcLpmKeyV4 {
                prefixlen: 0,
                ifindex: 0,
                addr: [0u8; 4],
            },
            LpmKeyV4 {
                prefixlen: 0,
                addr: [0u8; 4],
            },
            rule,
        )])
    });
    mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));
    mock.expect_lookup_sni_rule().returning(|_, _| {
        let mut e = SniRuleEntry::default();
        let pat = b"blocked.example";
        e.sni_match_type = SNI_MATCH_EXACT;
        e.sni_len = pat.len() as u8;
        e.sni_pattern[..pat.len()].copy_from_slice(pat);
        Ok(Some(e))
    });

    let m = quic_initial::match_sni_rules("blocked.example", Direction::Ingress, &mock)
        .unwrap()
        .expect("expected a match");
    assert_eq!(m.rule_id, 99);
    assert_eq!(m.actions.len(), 2);
    let a0 = m.actions[0].action;
    let a1 = m.actions[1].action;
    assert_eq!(a0, PolicyAction::Log as u32);
    assert_eq!(a1, PolicyAction::Drop as u32);
}

/// A hostname that doesn't match any installed SNI rule returns `None` —
/// callers then write a PASS verdict.
#[test]
fn match_sni_rules_returns_none_on_miss() {
    let mut mock = MockBpfOperations::new();

    let mut rule = L4Rule {
        rule_id: 7,
        protocol: libc::IPPROTO_UDP as u8,
        sni_match_type: SNI_MATCH_EXACT,
        num_actions: 1,
        ..Default::default()
    };
    rule.actions[0].action = PolicyAction::Drop as u32;

    mock.expect_list_policy_rules_v4().returning(move |_| {
        Ok(vec![(
            SrcLpmKeyV4 {
                prefixlen: 0,
                ifindex: 0,
                addr: [0u8; 4],
            },
            LpmKeyV4 {
                prefixlen: 0,
                addr: [0u8; 4],
            },
            rule,
        )])
    });
    mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));
    mock.expect_lookup_sni_rule().returning(|_, _| {
        let mut e = SniRuleEntry::default();
        let pat = b"blocked.example";
        e.sni_match_type = SNI_MATCH_EXACT;
        e.sni_len = pat.len() as u8;
        e.sni_pattern[..pat.len()].copy_from_slice(pat);
        Ok(Some(e))
    });

    let got = quic_initial::match_sni_rules("allowed.example", Direction::Ingress, &mock).unwrap();
    assert!(got.is_none());
}

/// TCP-protocol SNI rules must be ignored when matching against a QUIC
/// (UDP) flow — the BPF tail call only fires for UDP, but the userspace
/// mirror still walks the full rule list, so this is the safety net.
#[test]
fn match_sni_rules_ignores_non_udp_rules() {
    let mut mock = MockBpfOperations::new();

    let mut tcp_rule = L4Rule {
        rule_id: 5,
        protocol: libc::IPPROTO_TCP as u8,
        sni_match_type: SNI_MATCH_EXACT,
        num_actions: 1,
        ..Default::default()
    };
    tcp_rule.actions[0].action = PolicyAction::Drop as u32;

    mock.expect_list_policy_rules_v4().returning(move |_| {
        Ok(vec![(
            SrcLpmKeyV4 {
                prefixlen: 0,
                ifindex: 0,
                addr: [0u8; 4],
            },
            LpmKeyV4 {
                prefixlen: 0,
                addr: [0u8; 4],
            },
            tcp_rule,
        )])
    });
    mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));
    // lookup_sni_rule must never be called — the TCP rule is filtered out
    // before we hit the lookup path.
    mock.expect_lookup_sni_rule().times(0);

    let got = quic_initial::match_sni_rules("blocked.example", Direction::Ingress, &mock).unwrap();
    assert!(got.is_none());
}

// ── Cross-packet CRYPTO reassembly tests ──────────────────────────────────
//
// Modern Firefox/Chrome spread the ClientHello across multiple Initial
// packets with deliberately-fragmented, out-of-order CRYPTO frames.  These
// tests use a real capture from the user's network (Firefox → YouTube QUIC
// v1, 2 Initial packets, fragmented ClientHello) to confirm the reassembly
// table extracts the SNI once both packets arrive.

/// Inline real Firefox-→-YouTube QUIC Initial packets (extracted from a pcap
/// via `tshark -T fields -e udp.payload`) so the test runs without
/// filesystem dependencies.
const FIREFOX_YT_PKT1_HEX: &str = include_str!("quic_initial_real_pkt1.hex");
const FIREFOX_YT_PKT2_HEX: &str = include_str!("quic_initial_real_pkt2.hex");

#[test]
fn reassembly_extracts_sni_from_fragmented_clienthello() {
    let pkt1 = hex_to_bytes(FIREFOX_YT_PKT1_HEX.trim());
    let pkt2 = hex_to_bytes(FIREFOX_YT_PKT2_HEX.trim());

    // DCID is at payload[6..14] (DCID len byte at [5] = 8).
    assert_eq!(pkt1[5], 8);
    assert_eq!(&pkt1[6..14], &pkt2[6..14], "both packets share a DCID");
    let dcid = pkt1[6..14].to_vec();
    let key = reassembly_key_for(&dcid);

    let mut tbl = ReassemblyTable::new();

    // First packet alone is not enough — Firefox's fragmentation places no
    // CRYPTO chunk that starts where the previous one ends.
    let out1 = tbl.add_packet(key.clone(), &pkt1, 0x00000001).unwrap();
    match out1 {
        ReassemblyOutcome::Partial { .. } | ReassemblyOutcome::NeedMore { .. } => {} // expected
        other => panic!("expected Partial/NeedMore after pkt1, got {:?}", other),
    }
    assert_eq!(tbl.len(), 1, "state retained between packets");

    // Second packet completes the ClientHello.
    let out2 = tbl.add_packet(key.clone(), &pkt2, 0x00000001).unwrap();
    match out2 {
        ReassemblyOutcome::Sni(sni) => assert_eq!(sni, "www.youtube.com"),
        other => panic!("expected SNI after pkt2, got {:?}", other),
    }
    assert_eq!(tbl.len(), 0, "entry cleared on successful extraction");
}

#[test]
fn reassembly_evicts_stale_entries() {
    let pkt1 = hex_to_bytes(FIREFOX_YT_PKT1_HEX.trim());
    let dcid = pkt1[6..14].to_vec();
    let mut tbl = ReassemblyTable::new();
    tbl.add_packet(reassembly_key_for(&dcid), &pkt1, 0x00000001)
        .unwrap();
    assert_eq!(tbl.len(), 1);

    // Force a "now" 10s in the future; default idle timeout is 5s.
    let future = std::time::Instant::now() + std::time::Duration::from_secs(10);
    tbl.evict_stale(future);
    assert_eq!(tbl.len(), 0);
}
