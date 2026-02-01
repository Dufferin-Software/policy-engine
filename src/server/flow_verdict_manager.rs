// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Flow verdict cache manager
//!
//! Manages the lifecycle of flow verdict entries in the BPF map,
//! including applying verdicts from Suricata alerts and cleaning up expired entries.

use anyhow::Result;
use log::{debug, info};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::traits::BpfOperations;
use crate::types::*;

use super::eve_consumer::SuricataAlert;

/// Convert a Suricata alert to a flow verdict key (usable without FlowVerdictManager instance)
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
        _ => 0,
    };

    Ok(key)
}

/// Manages the flow verdict cache
pub struct FlowVerdictManager {
    bpf_ops: Arc<Mutex<Box<dyn BpfOperations>>>,
    verdict_ttl: Duration,
    cleanup_interval: Duration,
}

impl FlowVerdictManager {
    /// Create a new flow verdict manager
    pub fn new(bpf_ops: Arc<Mutex<Box<dyn BpfOperations>>>) -> Self {
        Self {
            bpf_ops,
            verdict_ttl: Duration::from_secs(300),
            cleanup_interval: Duration::from_secs(30),
        }
    }

    /// Set the verdict TTL
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.verdict_ttl = ttl;
        self
    }

    /// Apply a DROP verdict for a flow (from Suricata alert)
    pub fn apply_drop_verdict(&self, alert: &SuricataAlert) -> Result<()> {
        let key = self.alert_to_verdict_key(alert)?;
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let verdict = FlowVerdict {
            action: PolicyAction::Drop as u32,
            _pad: 0,
            timestamp_ns: now_ns,
            expires_ns: now_ns + self.verdict_ttl.as_nanos() as u64,
            packets: 0,
            bytes: 0,
        };

        let mut bpf = self.bpf_ops.lock().unwrap();
        // Apply to ingress by default (most common for IPS)
        bpf.update_flow_verdict(&key, &verdict, Direction::Ingress)?;

        debug!(
            "Applied DROP verdict for flow {}:{} -> {}:{}",
            alert.src_ip, alert.src_port, alert.dest_ip, alert.dest_port
        );
        Ok(())
    }

    /// Clean up expired verdicts
    pub fn cleanup_expired(&self) -> Result<u64> {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let mut removed = 0u64;

        for direction in [Direction::Ingress, Direction::Egress] {
            let verdicts = {
                let bpf = self.bpf_ops.lock().unwrap();
                match bpf.list_flow_verdicts(direction) {
                    Ok(v) => v,
                    Err(_) => continue,
                }
            };

            let mut bpf = self.bpf_ops.lock().unwrap();
            for (key, verdict) in verdicts {
                let expires = verdict.expires_ns;
                if expires > 0 && now_ns >= expires {
                    bpf.delete_flow_verdict(&key, direction).ok();
                    removed += 1;
                }
            }
        }

        if removed > 0 {
            info!("Cleaned up {} expired flow verdicts", removed);
        }

        Ok(removed)
    }

    /// Get the cleanup interval
    pub fn cleanup_interval(&self) -> Duration {
        self.cleanup_interval
    }

    /// Convert a Suricata alert to a flow verdict key
    fn alert_to_verdict_key(&self, alert: &SuricataAlert) -> Result<FlowVerdictKey> {
        alert_to_flow_verdict_key(alert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::MockBpfOperations;

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
            proto: proto.to_string(),
            event_type: "alert".to_string(),
            alert: None,
        }
    }

    fn make_mgr(mock: MockBpfOperations) -> FlowVerdictManager {
        let bpf_ops: Arc<Mutex<Box<dyn BpfOperations>>> = Arc::new(Mutex::new(Box::new(mock)));
        FlowVerdictManager::new(bpf_ops)
    }

    // ── alert_to_flow_verdict_key ─────────────────────────────────────────

    #[test]
    fn key_ipv4_tcp() {
        let alert = make_alert("10.0.0.1", "192.168.1.1", 12345, 80, "TCP");
        let key = alert_to_flow_verdict_key(&alert).unwrap();
        // Copy packed fields to locals before asserting
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

    #[test]
    fn key_ipv4_udp() {
        let alert = make_alert("10.0.0.1", "8.8.8.8", 1234, 53, "UDP");
        let key = alert_to_flow_verdict_key(&alert).unwrap();
        let proto = key.protocol;
        let af = key.af;
        assert_eq!(proto, libc::IPPROTO_UDP as u8);
        assert_eq!(af, AF_INET);
    }

    #[test]
    fn key_ipv4_icmp() {
        let alert = make_alert("10.0.0.1", "10.0.0.2", 0, 0, "ICMP");
        let key = alert_to_flow_verdict_key(&alert).unwrap();
        let proto = key.protocol;
        assert_eq!(proto, libc::IPPROTO_ICMP as u8);
    }

    #[test]
    fn key_unknown_proto_is_zero() {
        let alert = make_alert("10.0.0.1", "10.0.0.2", 0, 0, "IGMP");
        let key = alert_to_flow_verdict_key(&alert).unwrap();
        let proto = key.protocol;
        assert_eq!(proto, 0);
    }

    #[test]
    fn key_proto_case_insensitive() {
        let alert = make_alert("10.0.0.1", "10.0.0.2", 0, 0, "tcp");
        let key = alert_to_flow_verdict_key(&alert).unwrap();
        let proto = key.protocol;
        assert_eq!(proto, libc::IPPROTO_TCP as u8);
    }

    #[test]
    fn key_ipv6() {
        let alert = make_alert("2001:db8::1", "2001:db8::2", 12345, 443, "TCP");
        let key = alert_to_flow_verdict_key(&alert).unwrap();
        let af = key.af;
        assert_eq!(af, AF_INET6);
    }

    #[test]
    fn key_invalid_src_ip_falls_back_to_unspecified() {
        let alert = make_alert("not-an-ip", "192.168.1.1", 0, 0, "TCP");
        let key = alert_to_flow_verdict_key(&alert).unwrap();
        let af = key.af;
        let saddr = key.saddr;
        assert_eq!(af, AF_INET);
        assert_eq!(&saddr[..4], &[0, 0, 0, 0]);
    }

    #[test]
    fn key_invalid_dst_ip_falls_back_to_unspecified() {
        let alert = make_alert("10.0.0.1", "bad-ip", 0, 0, "TCP");
        let key = alert_to_flow_verdict_key(&alert).unwrap();
        let daddr = key.daddr;
        assert_eq!(daddr[..4], [0, 0, 0, 0]);
    }

    #[test]
    fn key_mixed_af_defaults_to_v4() {
        let alert = make_alert("10.0.0.1", "2001:db8::1", 0, 0, "TCP");
        let key = alert_to_flow_verdict_key(&alert).unwrap();
        let af = key.af;
        assert_eq!(af, AF_INET);
    }

    // ── FlowVerdictManager construction ──────────────────────────────────

    #[test]
    fn new_sets_defaults() {
        let mgr = make_mgr(MockBpfOperations::new());
        assert_eq!(mgr.verdict_ttl, Duration::from_secs(300));
        assert_eq!(mgr.cleanup_interval, Duration::from_secs(30));
    }

    #[test]
    fn with_ttl_overrides_ttl() {
        let mgr = make_mgr(MockBpfOperations::new()).with_ttl(Duration::from_secs(60));
        assert_eq!(mgr.verdict_ttl, Duration::from_secs(60));
    }

    #[test]
    fn cleanup_interval_accessor() {
        let mgr = make_mgr(MockBpfOperations::new());
        assert_eq!(mgr.cleanup_interval(), Duration::from_secs(30));
    }

    // ── apply_drop_verdict ────────────────────────────────────────────────

    #[test]
    fn apply_drop_verdict_success() {
        let mut mock = MockBpfOperations::new();
        mock.expect_update_flow_verdict()
            .times(1)
            .returning(|_, _, _| Ok(()));
        let mgr = make_mgr(mock);

        let alert = make_alert("10.0.0.1", "192.168.1.1", 1234, 80, "TCP");
        assert!(mgr.apply_drop_verdict(&alert).is_ok());
    }

    #[test]
    fn apply_drop_verdict_bpf_error_propagates() {
        let mut mock = MockBpfOperations::new();
        mock.expect_update_flow_verdict()
            .times(1)
            .returning(|_, _, _| Err(anyhow::anyhow!("BPF write error")));
        let mgr = make_mgr(mock);

        let alert = make_alert("10.0.0.1", "192.168.1.1", 1234, 80, "TCP");
        assert!(mgr.apply_drop_verdict(&alert).is_err());
    }

    #[test]
    fn apply_drop_verdict_uses_ingress_direction() {
        let mut mock = MockBpfOperations::new();
        mock.expect_update_flow_verdict()
            .withf(|_, _, dir| *dir == Direction::Ingress)
            .times(1)
            .returning(|_, _, _| Ok(()));
        let mgr = make_mgr(mock);

        let alert = make_alert("10.0.0.1", "10.0.0.2", 0, 0, "TCP");
        assert!(mgr.apply_drop_verdict(&alert).is_ok());
    }

    // ── cleanup_expired ───────────────────────────────────────────────────

    #[test]
    fn cleanup_expired_removes_expired_entries() {
        let mut mock = MockBpfOperations::new();

        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let key = FlowVerdictKey::default();
        let verdict = FlowVerdict {
            expires_ns: now_ns - 1_000_000_000, // 1 second ago — expired
            ..Default::default()
        };

        mock.expect_list_flow_verdicts()
            .times(2)
            .returning(move |_| Ok(vec![(key, verdict)]));
        mock.expect_delete_flow_verdict()
            .times(2)
            .returning(|_, _| Ok(()));

        let mgr = make_mgr(mock);
        let removed = mgr.cleanup_expired().unwrap();
        assert_eq!(removed, 2); // one per direction
    }

    #[test]
    fn cleanup_expired_keeps_fresh_entries() {
        let mut mock = MockBpfOperations::new();

        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let key = FlowVerdictKey::default();
        let verdict = FlowVerdict {
            expires_ns: now_ns + 60_000_000_000, // 1 minute in future
            ..Default::default()
        };

        mock.expect_list_flow_verdicts()
            .times(2)
            .returning(move |_| Ok(vec![(key, verdict)]));
        // delete should NOT be called

        let mgr = make_mgr(mock);
        let removed = mgr.cleanup_expired().unwrap();
        assert_eq!(removed, 0);
    }

    #[test]
    fn cleanup_expired_zero_expires_never_removed() {
        let mut mock = MockBpfOperations::new();
        let key = FlowVerdictKey::default();
        let verdict = FlowVerdict {
            expires_ns: 0, // zero means never expire
            ..Default::default()
        };
        mock.expect_list_flow_verdicts()
            .times(2)
            .returning(move |_| Ok(vec![(key, verdict)]));

        let mgr = make_mgr(mock);
        let removed = mgr.cleanup_expired().unwrap();
        assert_eq!(removed, 0);
    }

    #[test]
    fn cleanup_expired_list_error_skips_direction() {
        let mut mock = MockBpfOperations::new();
        mock.expect_list_flow_verdicts()
            .times(2)
            .returning(|_| Err(anyhow::anyhow!("map error")));

        let mgr = make_mgr(mock);
        let result = mgr.cleanup_expired();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn cleanup_expired_empty_lists_return_zero() {
        let mut mock = MockBpfOperations::new();
        mock.expect_list_flow_verdicts()
            .times(2)
            .returning(|_| Ok(vec![]));

        let mgr = make_mgr(mock);
        assert_eq!(mgr.cleanup_expired().unwrap(), 0);
    }
}
