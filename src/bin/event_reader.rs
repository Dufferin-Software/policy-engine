// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use anyhow::{Context, Result};
use clap::Parser;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapHandle;
use libbpf_rs::RingBufferBuilder;
use log::debug;
use log::{info, warn};
use policy_engine::PolicyAction;
use policy_engine::Protocol;
use policy_engine::BPF_PIN_PATH;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

// Generated skeletons
#[path = "../bpf/.output/xdp_policy.skel.rs"]
mod xdp_policy_skel;
use xdp_policy_skel::*;

#[path = "../bpf/.output/tc_policy.skel.rs"]
mod tc_policy_skel;
use tc_policy_skel::*;

// Map names exposed by BPF programs
pub const MAP_EVENTS: &str = "events";
pub const MAP_TC_EVENTS: &str = "tc_events";

/// Simple CLI for the event reader
#[derive(Parser, Debug)]
#[command(name = "bpf-events-reader")]
struct Opt {
    /// Listen for XDP events
    #[arg(long, default_value_t = true)]
    xdp: bool,

    /// Listen for TC events
    #[arg(long, default_value_t = true)]
    tc: bool,

    /// Output events as JSON
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[repr(C)]
#[derive(serde::Serialize, Debug, Clone, Copy)]
pub struct FlowKey {
    pub saddr6: [u32; 4], /* union: saddr4 at index 0 when AF_INET */
    pub daddr6: [u32; 4],
    pub sport: u16,
    pub dport: u16,
    pub protocol: u8,
    pub af: u8,
    pub pad: u16,
}

// Helper module for serializing large byte arrays
mod sni_serialization {
    use serde::ser::{Serialize, Serializer};

    pub fn serialize_sni<S>(sni: &[u8; 128], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as a string using only up to the specified length
        let sni_str = String::from_utf8_lossy(sni);
        sni_str.serialize(serializer)
    }
}

#[repr(C)]
#[derive(serde::Serialize, Debug, Clone, Copy)]
pub struct PolicyEvent {
    pub timestamp_ns: u64,
    pub rule_id: u64,
    pub action: u32,
    pub ifindex: u32,
    pub flow: FlowKey,
    pub pkt_len: u32,
    pub verdict: u32,
    #[serde(serialize_with = "sni_serialization::serialize_sni")]
    pub sni: [u8; 128], /* SNI value if rule matched with SNI inspection */
    pub sni_len: u8, /* Length of SNI string (0 if no SNI) */
    #[serde(skip)]
    pub _sni_pad: [u8; 7], /* Alignment padding */
}

impl std::fmt::Display for FlowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.af as i32 {
            2 => {
                // IPv4 stored in saddr6[0]/daddr6[0]
                let s = Ipv4Addr::from(self.saddr6[0].to_le_bytes());
                let d = Ipv4Addr::from(self.daddr6[0].to_le_bytes());
                let protocol: Protocol = self.protocol.into();
                write!(
                    f,
                    "{}:{} -> {}:{} proto={}",
                    s, self.sport, d, self.dport, protocol
                )
            }
            10 => {
                // IPv6 composed from four u32 words
                let mut s_bytes = [0u8; 16];
                let mut d_bytes = [0u8; 16];
                for i in 0..4 {
                    s_bytes[i * 4..(i + 1) * 4].copy_from_slice(&self.saddr6[i].to_le_bytes());
                    d_bytes[i * 4..(i + 1) * 4].copy_from_slice(&self.daddr6[i].to_le_bytes());
                }
                let s = Ipv6Addr::from(s_bytes);
                let d = Ipv6Addr::from(d_bytes);
                let protocol: Protocol = self.protocol.into();
                write!(
                    f,
                    "{}:{} -> {}:{} proto={}",
                    s, self.sport, d, self.dport, protocol
                )
            }
            _ => write!(
                f,
                "af={} raw_s={:?} raw_d={:?} sport={} dport={} proto={}",
                self.af, self.saddr6, self.daddr6, self.sport, self.dport, self.protocol
            ),
        }
    }
}

impl std::fmt::Display for PolicyEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let action: PolicyAction = self.action.into();
        let verdict: PolicyAction = self.verdict.into();

        write!(
            f,
            "ts={} rule={} action={} ifindex={} pkt_len={} verdict={} flow={}",
            self.timestamp_ns, self.rule_id, action, self.ifindex, self.pkt_len, verdict, self.flow
        )
    }
}

fn reuse_pinned_xdp(open: &mut OpenXdpPolicySkel) -> Result<()> {
    let pin_path = BPF_PIN_PATH;
    let map_path = format!("{}/{}", pin_path, MAP_EVENTS);
    if std::path::Path::new(&map_path).exists() {
        open.maps
            .events
            .reuse_pinned_map(&map_path)
            .context(format!("Failed to reuse pinned XDP map: {}", map_path))?;
        debug!("Reused pinned XDP map: {}", MAP_EVENTS);
        Ok(())
    } else {
        anyhow::bail!("Pinned XDP map not found at {}", map_path);
    }
}

fn reuse_pinned_tc(open: &mut OpenTcPolicySkel) -> Result<()> {
    let pin_path = BPF_PIN_PATH;
    let map_path = format!("{}/{}", pin_path, MAP_TC_EVENTS);
    if std::path::Path::new(&map_path).exists() {
        open.maps
            .tc_events
            .reuse_pinned_map(&map_path)
            .context(format!("Failed to reuse pinned TC map: {}", map_path))?;
        debug!("Reused pinned TC map: {}", MAP_TC_EVENTS);
        Ok(())
    } else {
        anyhow::bail!("Pinned TC map not found at {}", map_path);
    }
}

fn print_event(ev: &PolicyEvent, json: bool) {
    if json {
        if let Ok(s) = serde_json::to_string(ev) {
            println!("{}", s);
        }
    } else {
        println!("{ev}");
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    fn make_flow_key_ipv4(
        saddr: [u8; 4],
        daddr: [u8; 4],
        sport: u16,
        dport: u16,
        proto: u8,
    ) -> FlowKey {
        let mut saddr6 = [0u32; 4];
        let mut daddr6 = [0u32; 4];
        saddr6[0] = u32::from_le_bytes(saddr);
        daddr6[0] = u32::from_le_bytes(daddr);
        FlowKey {
            saddr6,
            daddr6,
            sport,
            dport,
            protocol: proto,
            af: 2,
            pad: 0,
        }
    }

    fn make_flow_key_ipv6(
        saddr: [u8; 16],
        daddr: [u8; 16],
        sport: u16,
        dport: u16,
        proto: u8,
    ) -> FlowKey {
        let mut saddr6 = [0u32; 4];
        let mut daddr6 = [0u32; 4];
        for i in 0..4 {
            saddr6[i] = u32::from_le_bytes(saddr[i * 4..(i + 1) * 4].try_into().unwrap());
            daddr6[i] = u32::from_le_bytes(daddr[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        FlowKey {
            saddr6,
            daddr6,
            sport,
            dport,
            protocol: proto,
            af: 10,
            pad: 0,
        }
    }

    fn make_event(flow: FlowKey) -> PolicyEvent {
        PolicyEvent {
            timestamp_ns: 1_000_000_000,
            rule_id: 42,
            action: 1,
            ifindex: 3,
            flow,
            pkt_len: 64,
            verdict: 1,
            sni: [0u8; 128],
            sni_len: 0,
            _sni_pad: [0u8; 7],
        }
    }

    #[test]
    fn flow_key_display_ipv4_addresses() {
        let key = make_flow_key_ipv4([10, 0, 0, 1], [192, 168, 1, 1], 1234, 80, 6);
        let s = format!("{}", key);
        assert!(s.contains("10.0.0.1"), "src IP missing: {}", s);
        assert!(s.contains("192.168.1.1"), "dst IP missing: {}", s);
        assert!(s.contains("1234"), "sport missing: {}", s);
        assert!(s.contains("80"), "dport missing: {}", s);
        assert!(s.contains("TCP"), "proto missing: {}", s);
    }

    #[test]
    fn flow_key_display_ipv4_udp() {
        let key = make_flow_key_ipv4([172, 16, 0, 1], [8, 8, 8, 8], 5353, 53, 17);
        let s = format!("{}", key);
        assert!(s.contains("172.16.0.1"), "src: {}", s);
        assert!(s.contains("8.8.8.8"), "dst: {}", s);
        assert!(s.contains("UDP"), "proto: {}", s);
    }

    #[test]
    fn flow_key_display_ipv6_loopback() {
        let mut saddr = [0u8; 16];
        saddr[15] = 1; // ::1
        let mut daddr = [0u8; 16];
        daddr[15] = 1;
        let key = make_flow_key_ipv6(saddr, daddr, 4321, 443, 6);
        let s = format!("{}", key);
        assert!(s.contains("::1"), "IPv6 loopback missing: {}", s);
        assert!(s.contains("4321"), "sport missing: {}", s);
        assert!(s.contains("443"), "dport missing: {}", s);
    }

    #[test]
    fn flow_key_display_unknown_af() {
        let key = FlowKey {
            saddr6: [1, 2, 3, 4],
            daddr6: [5, 6, 7, 8],
            sport: 9,
            dport: 10,
            protocol: 17,
            af: 99,
            pad: 0,
        };
        let s = format!("{}", key);
        assert!(s.contains("af=99"), "AF missing: {}", s);
        assert!(s.contains("sport=9"), "sport missing: {}", s);
        assert!(s.contains("dport=10"), "dport missing: {}", s);
    }

    #[test]
    fn policy_event_display_fields() {
        let key = make_flow_key_ipv4([10, 0, 0, 1], [192, 168, 1, 1], 1234, 80, 6);
        let ev = make_event(key);
        let s = format!("{}", ev);
        assert!(s.contains("rule=42"), "rule_id missing: {}", s);
        assert!(s.contains("ifindex=3"), "ifindex missing: {}", s);
        assert!(s.contains("pkt_len=64"), "pkt_len missing: {}", s);
        assert!(s.contains("ts=1000000000"), "timestamp missing: {}", s);
    }

    #[test]
    fn policy_event_json_serialization() {
        let key = make_flow_key_ipv4([10, 0, 0, 1], [192, 168, 1, 1], 1234, 80, 6);
        let ev = make_event(key);
        let json = serde_json::to_string(&ev).expect("serialization should succeed");
        assert!(json.contains("\"rule_id\":42"), "rule_id missing: {}", json);
        assert!(json.contains("\"ifindex\":3"), "ifindex missing: {}", json);
        assert!(json.contains("\"sni\""), "SNI field missing: {}", json);
    }

    #[test]
    fn sni_serialization_empty_bytes() {
        let key = make_flow_key_ipv4([10, 0, 0, 1], [10, 0, 0, 2], 0, 0, 6);
        let ev = make_event(key);
        let json = serde_json::to_string(&ev).unwrap();
        // Empty SNI: all-null bytes serialize as the lossy replacement
        assert!(
            json.contains("\"sni\""),
            "SNI key must appear in JSON: {}",
            json
        );
    }

    #[test]
    fn sni_serialization_with_hostname() {
        let key = make_flow_key_ipv4([10, 0, 0, 1], [10, 0, 0, 2], 443, 443, 6);
        let mut ev = make_event(key);
        let hostname = b"example.com";
        ev.sni[..hostname.len()].copy_from_slice(hostname);
        ev.sni_len = hostname.len() as u8;
        let json = serde_json::to_string(&ev).unwrap();
        assert!(
            json.contains("example.com"),
            "hostname missing from JSON: {}",
            json
        );
    }

    #[test]
    fn sni_pad_field_is_skipped_in_json() {
        let key = make_flow_key_ipv4([10, 0, 0, 1], [10, 0, 0, 2], 0, 0, 6);
        let ev = make_event(key);
        let json = serde_json::to_string(&ev).unwrap();
        assert!(
            !json.contains("_sni_pad"),
            "_sni_pad should be skipped: {}",
            json
        );
    }

    #[test]
    fn print_event_text_does_not_panic() {
        let key = make_flow_key_ipv4([10, 0, 0, 1], [192, 168, 1, 1], 1234, 80, 6);
        let ev = make_event(key);
        print_event(&ev, false);
    }

    #[test]
    fn print_event_json_does_not_panic() {
        let key = make_flow_key_ipv4([10, 0, 0, 1], [192, 168, 1, 1], 1234, 80, 6);
        let ev = make_event(key);
        print_event(&ev, true);
    }
}

fn main() -> Result<()> {
    env_logger::init();
    let opt = Opt::parse();

    // Ctrl-C handler
    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })?;
    }

    // Open XDP skeleton
    let xdp_builder = XdpPolicySkelBuilder::default();
    let xdp_obj_storage: &'static mut MaybeUninit<libbpf_rs::OpenObject> =
        Box::leak(Box::new(MaybeUninit::uninit()));
    let mut xdp_open = xdp_builder
        .open(xdp_obj_storage)
        .context("Failed to open XDP skeleton")?;
    reuse_pinned_xdp(&mut xdp_open)?;

    // Open TC skeleton
    let tc_builder = TcPolicySkelBuilder::default();
    let tc_obj_storage: &'static mut MaybeUninit<libbpf_rs::OpenObject> =
        Box::leak(Box::new(MaybeUninit::uninit()));
    let mut tc_open = tc_builder
        .open(tc_obj_storage)
        .context("Failed to open TC skeleton")?;
    reuse_pinned_tc(&mut tc_open)?;

    // Build ringbuffer using available maps. Prefer loaded maps, otherwise
    // open pinned maps and keep MapHandle values alive in `map_handles`.
    let mut rb_builder = RingBufferBuilder::new();
    // capture the json flag by value so callbacks are 'static
    let json_out = opt.json;
    let mut map_handles: Vec<MapHandle> = Vec::new();

    // Collect pinned maps first so we can push both handles without
    // invalidating references later. Record indices for pinned maps.
    let mut xdp_handle_idx: Option<usize> = None;
    let mut tc_handle_idx: Option<usize> = None;

    if opt.xdp {
        let pin_path = BPF_PIN_PATH;
        let map_path = format!("{}/{}", pin_path, MAP_EVENTS);
        if std::path::Path::new(&map_path).exists() {
            let mh =
                MapHandle::from_pinned_path(&map_path).context("failed to open pinned XDP map")?;
            map_handles.push(mh);
            xdp_handle_idx = Some(map_handles.len() - 1);
        } else {
            warn!("XDP events map not available (not loaded and not pinned)");
        }
    }

    if opt.tc {
        let pin_path = BPF_PIN_PATH;
        let map_path = format!("{}/{}", pin_path, MAP_TC_EVENTS);
        if std::path::Path::new(&map_path).exists() {
            let mh =
                MapHandle::from_pinned_path(&map_path).context("failed to open pinned TC map")?;
            map_handles.push(mh);
            tc_handle_idx = Some(map_handles.len() - 1);
        } else {
            warn!("TC events map not available (not loaded and not pinned)");
        }
    }

    // Now add callbacks using either loaded maps or the pinned MapHandles we collected.
    if opt.xdp {
        if let Some(idx) = xdp_handle_idx {
            let last = &map_handles[idx];
            rb_builder.add(last, move |data: &[u8]| {
                if data.len() >= std::mem::size_of::<PolicyEvent>() {
                    let ev: PolicyEvent =
                        unsafe { std::ptr::read_unaligned(data.as_ptr() as *const _) };
                    print_event(&ev, json_out);
                } else {
                    warn!("Short XDP event sample: {} bytes", data.len());
                }
                0
            })?;
        }
    }

    if opt.tc {
        if let Some(idx) = tc_handle_idx {
            let last = &map_handles[idx];
            rb_builder.add(last, move |data: &[u8]| {
                if data.len() >= std::mem::size_of::<PolicyEvent>() {
                    let ev: PolicyEvent =
                        unsafe { std::ptr::read_unaligned(data.as_ptr() as *const _) };
                    print_event(&ev, json_out);
                } else {
                    warn!("Short TC event sample: {} bytes", data.len());
                }
                0
            })?;
        }
    }

    let ringbuf = rb_builder.build().context("Failed to build ring buffer")?;

    info!("Listening for BPF events (xdp={}, tc={})", opt.xdp, opt.tc);

    while running.load(Ordering::SeqCst) {
        if let Err(e) = ringbuf.poll(Duration::from_millis(500)) {
            warn!("ringbuf poll error: {}", e);
        }
    }

    info!("Shutting down bpf-events-reader");
    Ok(())
}
