// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Flow verdict cache eviction.
//!
//! The flow verdict cache (`flow_verdict_cache` / `tc_flow_verdict_cache`) is a
//! plain BPF HASH map: it does not auto-expire entries. The dataplane treats an
//! expired hit as a miss and re-evaluates, but the stale entry lingers until
//! userspace deletes it. [`FlowVerdictManager`] is that evictor — a single
//! periodic sweep that removes expired entries in every build, because SNI/QUIC
//! matching populates the cache even without the IPS (`suricata`) feature.

use anyhow::Result;
use log::info;
use std::time::Duration;

use crate::types::*;

use super::policy_service::PolicyService;

#[cfg(feature = "suricata")]
use super::eve_consumer::SuricataAlert;
#[cfg(feature = "suricata")]
use std::net::{IpAddr, Ipv4Addr};

/// Current `CLOCK_MONOTONIC` time in nanoseconds.
///
/// Must match the clock `bpf_ktime_get_ns()` uses, so that `expires_ns` values
/// written from BPF compare correctly here. Using wall-clock time
/// (`SystemTime`) would be a bug: the two clocks have unrelated epochs.
pub fn monotonic_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid out-pointer; CLOCK_MONOTONIC never fails on Linux.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Convert a Suricata alert to a flow verdict key. Suricata-only: the IPS
/// enforcement loop uses it to install DROP verdicts from EVE alerts.
#[cfg(feature = "suricata")]
#[allow(clippy::field_reassign_with_default)]
pub fn alert_to_flow_verdict_key(alert: &SuricataAlert) -> Result<FlowVerdictKey> {
    let src_ip: IpAddr = alert
        .src_ip
        .parse()
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let dst_ip: IpAddr = alert
        .dest_ip
        .parse()
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

    let mut key = FlowVerdictKey::default();
    key.sport = alert.src_port;
    key.dport = alert.dest_port;

    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            key.af = AF_INET;
            key.saddr[..4].copy_from_slice(&src.octets());
            key.daddr[..4].copy_from_slice(&dst.octets());
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            key.af = AF_INET6;
            key.saddr.copy_from_slice(&src.octets());
            key.daddr.copy_from_slice(&dst.octets());
        }
        _ => {
            // Mixed AF - default to v4
            key.af = AF_INET;
        }
    }

    key.protocol = match alert.proto.to_lowercase().as_str() {
        "tcp" => libc::IPPROTO_TCP as u8,
        "udp" => libc::IPPROTO_UDP as u8,
        "icmp" => libc::IPPROTO_ICMP as u8,
        // Suricata's EVE proto string for ICMPv6.
        "ipv6-icmp" | "icmpv6" => libc::IPPROTO_ICMPV6 as u8,
        _ => 0,
    };

    Ok(key)
}

/// Turn one Suricata EVE alert into DROP flow verdicts (IPS mode only).
///
/// Returns `true` when at least one verdict was installed — i.e. the flow is
/// now blocked and the alert should be reported with `action: "blocked"`.
/// Suricata is never inline (it sees mirrored traffic), so its own EVE action
/// field always says "allowed"; only this enforcement path knows whether the
/// flow was actually dropped. In IDS mode, or when the alert carries no
/// usable flow key, nothing is installed and `false` is returned.
#[cfg(feature = "suricata")]
pub fn enforce_alert(
    service: &mut PolicyService,
    alert: &SuricataAlert,
    verdict_ttl_ns: u64,
) -> bool {
    if alert.alert.is_none() {
        return false;
    }
    let Ok(key) = alert_to_flow_verdict_key(alert) else {
        return false;
    };
    let is_ips = service
        .get_inspect_config(Direction::Ingress)
        .map(|c| InspectMode::from(c.mode) == InspectMode::Ips)
        .unwrap_or(false);
    if !is_ips {
        return false;
    }

    let now_ns = monotonic_now_ns();
    let verdict = FlowVerdict {
        action: PolicyAction::Drop as u32,
        _pad: 0,
        timestamp_ns: now_ns,
        expires_ns: now_ns + verdict_ttl_ns,
        packets: 0,
        bytes: 0,
        rule_id: 0,
    };
    // The verdict cache is scoped per-interface (flow_verdict_key.ifindex),
    // but a Suricata alert carries no ifindex. Install the DROP on every
    // attached interface for the matching direction so the flow is blocked
    // wherever it ingresses/egresses. The interface set is tiny and stale
    // entries are LRU-reclaimed, so the spray is cheap.
    let interfaces = service.get_interfaces();
    // Ingress key blocks the server→client direction; the reversed key
    // blocks client→server on egress.
    let mut egress_key = key;
    egress_key.saddr.copy_from_slice(&key.daddr);
    egress_key.daddr.copy_from_slice(&key.saddr);
    egress_key.sport = key.dport;
    egress_key.dport = key.sport;
    let mut installed = false;
    for iface in &interfaces {
        let ifindex = iface.ifindex as u32;
        if iface.direction.eq_ignore_ascii_case("ingress") {
            let mut k = key;
            k.ifindex = ifindex;
            if service
                .update_flow_verdict(&k, &verdict, Direction::Ingress)
                .is_ok()
            {
                installed = true;
            }
        } else if iface.direction.eq_ignore_ascii_case("egress") {
            let mut k = egress_key;
            k.ifindex = ifindex;
            if service
                .update_flow_verdict(&k, &verdict, Direction::Egress)
                .is_ok()
            {
                installed = true;
            }
        }
    }
    installed
}

/// Periodic evictor for expired flow verdict cache entries.
///
/// Holds only the sweep cadence; it operates on the shared [`PolicyService`]
/// passed to [`cleanup_expired`](Self::cleanup_expired), so it shares the same
/// BPF handles the rest of the engine uses rather than owning a second one.
pub struct FlowVerdictManager {
    cleanup_interval: Duration,
}

impl Default for FlowVerdictManager {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowVerdictManager {
    /// Create a manager with the default 30 s sweep interval.
    pub fn new() -> Self {
        Self {
            cleanup_interval: Duration::from_secs(30),
        }
    }

    /// Override the sweep interval.
    pub fn with_cleanup_interval(mut self, interval: Duration) -> Self {
        self.cleanup_interval = interval;
        self
    }

    /// How often the background sweep should run.
    pub fn cleanup_interval(&self) -> Duration {
        self.cleanup_interval
    }

    /// Evict every expired verdict from both directions, returning how many were
    /// removed. An `expires_ns` of 0 means "never expires" and is left in place.
    pub fn cleanup_expired(&self, service: &mut PolicyService) -> Result<u64> {
        let now_ns = monotonic_now_ns();
        let mut removed = 0u64;

        for direction in [Direction::Ingress, Direction::Egress] {
            let verdicts = match service.list_flow_verdicts(direction) {
                Ok(v) => v,
                Err(_) => continue,
            };
            for (key, verdict) in verdicts {
                if verdict.expires_ns > 0 && now_ns >= verdict.expires_ns {
                    service.delete_flow_verdict(&key, direction).ok();
                    removed += 1;
                }
            }
        }

        if removed > 0 {
            info!("Evicted {} expired flow verdicts", removed);
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::MockBpfOperations;

    #[cfg(feature = "suricata")]
    fn make_alert(
        src_ip: &str,
        dest_ip: &str,
        src_port: u16,
        dest_port: u16,
        proto: &str,
    ) -> SuricataAlert {
        SuricataAlert {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            src_ip: src_ip.to_string(),
            dest_ip: dest_ip.to_string(),
            src_port,
            dest_port,
            icmp_type: None,
            icmp_code: None,
            proto: proto.to_string(),
            event_type: "alert".to_string(),
            alert: None,
        }
    }

    fn make_service(mock: MockBpfOperations) -> PolicyService {
        PolicyService::new(Box::new(mock))
    }

    #[cfg(feature = "suricata")]
    fn make_full_alert() -> SuricataAlert {
        let mut alert = make_alert("10.0.0.1", "192.168.1.1", 12345, 80, "TCP");
        alert.alert = Some(super::super::eve_consumer::AlertInfo {
            action: "allowed".to_string(),
            signature_id: 2001,
            signature: "ET SCAN".to_string(),
            category: "Attempted Recon".to_string(),
            severity: 2,
        });
        alert
    }

    #[cfg(feature = "suricata")]
    fn inspect_config(mode: InspectMode) -> InspectConfig {
        InspectConfig {
            mode: mode as u32,
            mirror_ifindex: 0,
            _pad: [0; 2],
        }
    }

    #[cfg(feature = "suricata")]
    fn attachment(ifindex: i32, direction: &str) -> crate::shared_types::InterfaceAttachment {
        crate::shared_types::InterfaceAttachment {
            interface: format!("eth{ifindex}"),
            ifindex,
            mode: "native".to_string(),
            direction: direction.to_string(),
        }
    }

    // ── alert_to_flow_verdict_key ─────────────────────────────────────────

    #[cfg(feature = "suricata")]
    #[test]
    fn key_ipv4_tcp() {
        let alert = make_alert("10.0.0.1", "192.168.1.1", 12345, 80, "TCP");
        let key = alert_to_flow_verdict_key(&alert).unwrap();
        let sport = key.sport;
        let dport = key.dport;
        let af = key.af;
        let proto = key.protocol;
        let saddr = key.saddr;
        let daddr = key.daddr;
        assert_eq!(sport, 12345);
        assert_eq!(dport, 80);
        assert_eq!(af, AF_INET);
        assert_eq!(proto, libc::IPPROTO_TCP as u8);
        assert_eq!(&saddr[..4], &[10, 0, 0, 1]);
        assert_eq!(&daddr[..4], &[192, 168, 1, 1]);
    }

    #[cfg(feature = "suricata")]
    #[test]
    fn key_ipv4_udp() {
        let alert = make_alert("10.0.0.1", "8.8.8.8", 1234, 53, "UDP");
        let key = alert_to_flow_verdict_key(&alert).unwrap();
        let proto = key.protocol;
        let af = key.af;
        assert_eq!(proto, libc::IPPROTO_UDP as u8);
        assert_eq!(af, AF_INET);
    }

    #[cfg(feature = "suricata")]
    #[test]
    fn key_ipv4_icmp() {
        let alert = make_alert("10.0.0.1", "10.0.0.2", 0, 0, "ICMP");
        let key = alert_to_flow_verdict_key(&alert).unwrap();
        let proto = key.protocol;
        assert_eq!(proto, libc::IPPROTO_ICMP as u8);
    }

    #[cfg(feature = "suricata")]
    #[test]
    fn key_ipv6_icmpv6() {
        let alert = make_alert("fd00::1", "fd00::2", 128, 0, "IPv6-ICMP");
        let key = alert_to_flow_verdict_key(&alert).unwrap();
        let proto = key.protocol;
        let af = key.af;
        assert_eq!(proto, libc::IPPROTO_ICMPV6 as u8);
        assert_eq!(af, AF_INET6);
    }

    #[cfg(feature = "suricata")]
    #[test]
    fn key_unknown_proto_is_zero() {
        let alert = make_alert("10.0.0.1", "10.0.0.2", 0, 0, "IGMP");
        let key = alert_to_flow_verdict_key(&alert).unwrap();
        let proto = key.protocol;
        assert_eq!(proto, 0);
    }

    #[cfg(feature = "suricata")]
    #[test]
    fn key_proto_case_insensitive() {
        let alert = make_alert("10.0.0.1", "10.0.0.2", 0, 0, "tcp");
        let key = alert_to_flow_verdict_key(&alert).unwrap();
        let proto = key.protocol;
        assert_eq!(proto, libc::IPPROTO_TCP as u8);
    }

    #[cfg(feature = "suricata")]
    #[test]
    fn key_ipv6() {
        let alert = make_alert("2001:db8::1", "2001:db8::2", 12345, 443, "TCP");
        let key = alert_to_flow_verdict_key(&alert).unwrap();
        let af = key.af;
        assert_eq!(af, AF_INET6);
    }

    #[cfg(feature = "suricata")]
    #[test]
    fn key_invalid_src_ip_falls_back_to_unspecified() {
        let alert = make_alert("not-an-ip", "192.168.1.1", 0, 0, "TCP");
        let key = alert_to_flow_verdict_key(&alert).unwrap();
        let af = key.af;
        let saddr = key.saddr;
        assert_eq!(af, AF_INET);
        assert_eq!(&saddr[..4], &[0, 0, 0, 0]);
    }

    // ── enforce_alert ─────────────────────────────────────────────────────

    #[cfg(feature = "suricata")]
    #[test]
    fn enforce_ips_installs_verdicts_and_reports_blocked() {
        let mut mock = MockBpfOperations::new();
        mock.expect_get_inspect_config()
            .returning(|_| Ok(inspect_config(InspectMode::Ips)));
        mock.expect_get_attached_interfaces()
            .returning(|| vec![attachment(2, "ingress"), attachment(3, "egress")]);
        // Ingress: alert 5-tuple as-is on ifindex 2; egress: reversed on 3.
        mock.expect_update_flow_verdict()
            .withf(|key, verdict, direction| {
                let (sport, dport, ifindex) = (key.sport, key.dport, key.ifindex);
                let action = verdict.action;
                action == PolicyAction::Drop as u32
                    && match direction {
                        Direction::Ingress => sport == 12345 && dport == 80 && ifindex == 2,
                        Direction::Egress => sport == 80 && dport == 12345 && ifindex == 3,
                    }
            })
            .times(2)
            .returning(|_, _, _| Ok(()));

        let mut service = make_service(mock);
        assert!(enforce_alert(&mut service, &make_full_alert(), 1_000_000));
    }

    #[cfg(feature = "suricata")]
    #[test]
    fn enforce_ids_mode_installs_nothing() {
        let mut mock = MockBpfOperations::new();
        mock.expect_get_inspect_config()
            .returning(|_| Ok(inspect_config(InspectMode::Ids)));
        // update_flow_verdict must NOT be called.

        let mut service = make_service(mock);
        assert!(!enforce_alert(&mut service, &make_full_alert(), 1_000_000));
    }

    #[cfg(feature = "suricata")]
    #[test]
    fn enforce_without_alert_info_is_noop() {
        // No mock expectations: an EVE record without an `alert` object must
        // not even query the inspect config.
        let mut service = make_service(MockBpfOperations::new());
        let alert = make_alert("10.0.0.1", "192.168.1.1", 12345, 80, "TCP");
        assert!(!enforce_alert(&mut service, &alert, 1_000_000));
    }

    #[cfg(feature = "suricata")]
    #[test]
    fn enforce_ips_without_interfaces_reports_allowed() {
        let mut mock = MockBpfOperations::new();
        mock.expect_get_inspect_config()
            .returning(|_| Ok(inspect_config(InspectMode::Ips)));
        mock.expect_get_attached_interfaces().returning(Vec::new);

        let mut service = make_service(mock);
        assert!(!enforce_alert(&mut service, &make_full_alert(), 1_000_000));
    }

    #[cfg(feature = "suricata")]
    #[test]
    fn enforce_ips_verdict_write_failure_reports_allowed() {
        let mut mock = MockBpfOperations::new();
        mock.expect_get_inspect_config()
            .returning(|_| Ok(inspect_config(InspectMode::Ips)));
        mock.expect_get_attached_interfaces()
            .returning(|| vec![attachment(2, "ingress")]);
        mock.expect_update_flow_verdict()
            .returning(|_, _, _| Err(anyhow::anyhow!("map full")));

        let mut service = make_service(mock);
        assert!(!enforce_alert(&mut service, &make_full_alert(), 1_000_000));
    }

    #[cfg(feature = "suricata")]
    #[test]
    fn key_invalid_dst_ip_falls_back_to_unspecified() {
        let alert = make_alert("10.0.0.1", "bad-ip", 0, 0, "TCP");
        let key = alert_to_flow_verdict_key(&alert).unwrap();
        let daddr = key.daddr;
        assert_eq!(daddr[..4], [0, 0, 0, 0]);
    }

    #[cfg(feature = "suricata")]
    #[test]
    fn key_mixed_af_defaults_to_v4() {
        let alert = make_alert("10.0.0.1", "2001:db8::1", 0, 0, "TCP");
        let key = alert_to_flow_verdict_key(&alert).unwrap();
        let af = key.af;
        assert_eq!(af, AF_INET);
    }

    // ── monotonic clock ──────────────────────────────────────────────────

    #[test]
    fn monotonic_now_ns_returns_nonzero() {
        assert!(
            monotonic_now_ns() > 0,
            "CLOCK_MONOTONIC should return a nonzero value"
        );
    }

    #[test]
    fn monotonic_now_ns_increases_over_time() {
        let t1 = monotonic_now_ns();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let t2 = monotonic_now_ns();
        assert!(t2 > t1, "monotonic clock must be non-decreasing");
    }

    // ── FlowVerdictManager construction ──────────────────────────────────

    #[test]
    fn new_sets_default_interval() {
        let mgr = FlowVerdictManager::new();
        assert_eq!(mgr.cleanup_interval(), Duration::from_secs(30));
    }

    #[test]
    fn with_cleanup_interval_overrides() {
        let mgr = FlowVerdictManager::new().with_cleanup_interval(Duration::from_secs(5));
        assert_eq!(mgr.cleanup_interval(), Duration::from_secs(5));
    }

    // ── cleanup_expired ───────────────────────────────────────────────────

    #[test]
    fn cleanup_removes_expired_entries_both_directions() {
        let mut mock = MockBpfOperations::new();
        let key = FlowVerdictKey::default();
        // expires_ns well in the past relative to CLOCK_MONOTONIC now.
        let verdict = FlowVerdict {
            expires_ns: 1,
            ..Default::default()
        };
        mock.expect_list_flow_verdicts()
            .times(2)
            .returning(move |_| Ok(vec![(key, verdict)]));
        mock.expect_delete_flow_verdict()
            .times(2)
            .returning(|_, _| Ok(()));

        let mut service = make_service(mock);
        let mgr = FlowVerdictManager::new();
        assert_eq!(mgr.cleanup_expired(&mut service).unwrap(), 2);
    }

    #[test]
    fn cleanup_keeps_fresh_entries() {
        let mut mock = MockBpfOperations::new();
        let key = FlowVerdictKey::default();
        // Far enough in the future that CLOCK_MONOTONIC now is below it.
        let verdict = FlowVerdict {
            expires_ns: monotonic_now_ns() + 3_600_000_000_000,
            ..Default::default()
        };
        mock.expect_list_flow_verdicts()
            .times(2)
            .returning(move |_| Ok(vec![(key, verdict)]));
        // delete must NOT be called.

        let mut service = make_service(mock);
        let mgr = FlowVerdictManager::new();
        assert_eq!(mgr.cleanup_expired(&mut service).unwrap(), 0);
    }

    #[test]
    fn cleanup_never_removes_zero_expiry() {
        let mut mock = MockBpfOperations::new();
        let key = FlowVerdictKey::default();
        let verdict = FlowVerdict {
            expires_ns: 0, // never expires
            ..Default::default()
        };
        mock.expect_list_flow_verdicts()
            .times(2)
            .returning(move |_| Ok(vec![(key, verdict)]));

        let mut service = make_service(mock);
        let mgr = FlowVerdictManager::new();
        assert_eq!(mgr.cleanup_expired(&mut service).unwrap(), 0);
    }

    #[test]
    fn cleanup_skips_direction_on_list_error() {
        let mut mock = MockBpfOperations::new();
        mock.expect_list_flow_verdicts()
            .times(2)
            .returning(|_| Err(anyhow::anyhow!("map error")));

        let mut service = make_service(mock);
        let mgr = FlowVerdictManager::new();
        assert_eq!(mgr.cleanup_expired(&mut service).unwrap(), 0);
    }

    #[test]
    fn cleanup_empty_lists_return_zero() {
        let mut mock = MockBpfOperations::new();
        mock.expect_list_flow_verdicts()
            .times(2)
            .returning(|_| Ok(vec![]));

        let mut service = make_service(mock);
        let mgr = FlowVerdictManager::new();
        assert_eq!(mgr.cleanup_expired(&mut service).unwrap(), 0);
    }
}
