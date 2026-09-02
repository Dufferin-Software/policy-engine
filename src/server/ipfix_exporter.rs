// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! IPFIX flow export (RFC 7011).
//!
//! The `IpfixExporter` scans the XDP and TC flow cache BPF maps, exports
//! flows that have exceeded their idle or active timeout as IPFIX UDP
//! datagrams to a configured collector, then deletes the entries from the maps.
//!
//! Two templates are used:
//!   - Template 256 (IPv4): 46-byte records
//!   - Template 257 (IPv6): 70-byte records
//!
//! Templates are re-sent every 100 data records or every 60 seconds.

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use log::{debug, warn};

use crate::traits::BpfOperations;
use crate::types::{Direction, FlowCacheEntry, FlowExportConfig, FlowKey};

// IPFIX template IDs — user-defined templates start at 256 (RFC 7011 §3.4.1)
const TEMPLATE_ID_V4: u16 = 256;
const TEMPLATE_ID_V6: u16 = 257;

// IPFIX set IDs (RFC 7011 §3.3.2)
const SET_ID_TEMPLATE: u16 = 2;

// Conservative max payload size to avoid UDP fragmentation
const MAX_IPFIX_PAYLOAD: usize = 1400;

// IPFIX version number
const IPFIX_VERSION: u16 = 10;

// Fixed record sizes derived from the template field layout
const RECORD_SIZE_V4: usize = 4 + 4 + 2 + 2 + 1 + 1 + 8 + 8 + 8 + 8; // 46 bytes
const RECORD_SIZE_V6: usize = 16 + 16 + 2 + 2 + 1 + 1 + 8 + 8 + 8 + 8; // 70 bytes

// Address families (must match BPF AF_INET / AF_INET6 values)
const AF_INET: u8 = 2;

pub struct IpfixExporter {
    collector_addr: SocketAddr,
    idle_timeout_ns: u64,
    active_timeout_ns: u64,
    observation_domain_id: u32,
    sequence_num: u32,
    last_template_send: Instant,
    records_since_template: u32,
    pub flows_exported_total: u64,
}

impl IpfixExporter {
    pub fn new(config: &FlowExportConfig) -> Result<Self> {
        let addr_str = format!("{}:{}", config.collector_host, config.collector_port);
        let collector_addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| anyhow!("Invalid collector address '{}': {}", addr_str, e))?;

        Ok(Self {
            collector_addr,
            idle_timeout_ns: config.idle_timeout_s as u64 * 1_000_000_000,
            active_timeout_ns: config.active_timeout_s as u64 * 1_000_000_000,
            observation_domain_id: 1,
            sequence_num: 0,
            // Force template send on the first export pass
            last_template_send: Instant::now() - Duration::from_secs(120),
            records_since_template: 0,
            flows_exported_total: 0,
        })
    }

    /// Scan both flow cache maps, export aged-out flows as IPFIX, delete them.
    /// Returns the number of flows exported.
    pub fn export_aged_flows(
        &mut self,
        bpf_ops: &mut dyn BpfOperations,
        socket: &UdpSocket,
    ) -> Result<u64> {
        // Capture clock references once for the whole scan pass so that all
        // flow timestamps within one pass are converted consistently.
        let now_mono_ns = monotonic_now_ns();
        let now_wall_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Collect aged entries from both directions
        let mut aged: Vec<(FlowKey, FlowCacheEntry, Direction)> = Vec::new();
        for direction in [Direction::Ingress, Direction::Egress] {
            match bpf_ops.list_flow_cache_entries(direction) {
                Ok(entries) => {
                    for (key, entry) in entries {
                        let idle_ns = now_mono_ns.saturating_sub(entry.last_seen_ns);
                        let active_ns = entry.last_seen_ns.saturating_sub(entry.first_seen_ns);
                        if idle_ns >= self.idle_timeout_ns || active_ns >= self.active_timeout_ns {
                            aged.push((key, entry, direction));
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "IPFIX: failed to list flow cache entries ({:?}): {}",
                        direction, e
                    );
                }
            }
        }

        if aged.is_empty() {
            return Ok(0);
        }

        let force_template = self.records_since_template >= 100
            || self.last_template_send.elapsed() >= Duration::from_secs(60);

        // Partition by address family for separate templates
        let mut v4: Vec<(FlowKey, FlowCacheEntry, Direction)> = Vec::new();
        let mut v6: Vec<(FlowKey, FlowCacheEntry, Direction)> = Vec::new();
        for item in &aged {
            if item.0.af == AF_INET {
                v4.push(*item);
            } else {
                v6.push(*item);
            }
        }

        if !v4.is_empty() {
            self.send_batches(
                socket,
                &v4,
                TEMPLATE_ID_V4,
                RECORD_SIZE_V4,
                force_template,
                now_mono_ns,
                now_wall_ms,
            );
        }
        if !v6.is_empty() {
            self.send_batches(
                socket,
                &v6,
                TEMPLATE_ID_V6,
                RECORD_SIZE_V6,
                force_template,
                now_mono_ns,
                now_wall_ms,
            );
        }

        if force_template {
            self.last_template_send = Instant::now();
            self.records_since_template = 0;
        }

        // Delete exported entries from the BPF maps (best-effort)
        let count = aged.len() as u64;
        for (key, _, dir) in &aged {
            if let Err(e) = bpf_ops.delete_flow_cache_entry(key, *dir) {
                debug!("IPFIX: failed to delete flow cache entry: {}", e);
            }
        }

        self.flows_exported_total += count;
        Ok(count)
    }

    /// Send a slice of flow records to the collector in UDP-sized batches.
    #[allow(clippy::too_many_arguments)]
    fn send_batches(
        &mut self,
        socket: &UdpSocket,
        flows: &[(FlowKey, FlowCacheEntry, Direction)],
        template_id: u16,
        record_size: usize,
        include_template: bool,
        now_mono_ns: u64,
        now_wall_ms: u64,
    ) {
        // Header sizes: IPFIX message header (16) + set header (4)
        const MSG_HDR: usize = 16;
        const SET_HDR: usize = 4;
        let template_payload = if include_template {
            build_template_set(template_id)
        } else {
            Vec::new()
        };

        // How many data records fit in a single datagram alongside the template
        let header_overhead = MSG_HDR + template_payload.len() + SET_HDR;
        let max_records_per_msg = (MAX_IPFIX_PAYLOAD.saturating_sub(header_overhead)) / record_size;
        let max_records_per_msg = max_records_per_msg.max(1);

        let mut first = true;
        for chunk in flows.chunks(max_records_per_msg) {
            let incl_tmpl = include_template && first;
            first = false;

            let msg = self.encode_ipfix_message(
                chunk,
                template_id,
                record_size,
                incl_tmpl,
                now_mono_ns,
                now_wall_ms,
            );

            if let Err(e) = socket.send_to(&msg, self.collector_addr) {
                warn!("IPFIX: UDP send failed to {}: {}", self.collector_addr, e);
            } else {
                self.records_since_template += chunk.len() as u32;
                self.sequence_num = self.sequence_num.wrapping_add(1);
            }
        }
    }

    /// Encode a single IPFIX message (header + optional template set + data set).
    fn encode_ipfix_message(
        &self,
        flows: &[(FlowKey, FlowCacheEntry, Direction)],
        template_id: u16,
        record_size: usize,
        include_template: bool,
        now_mono_ns: u64,
        now_wall_ms: u64,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1400);

        // Build body first so we know the total length
        let mut body: Vec<u8> = Vec::new();

        if include_template {
            let tmpl = build_template_set(template_id);
            body.extend_from_slice(&tmpl);
        }

        // Data set: set header + records
        let data_set_len = 4 + flows.len() * record_size;
        body.extend_from_slice(&template_id.to_be_bytes()); // set ID = template ID
        body.extend_from_slice(&(data_set_len as u16).to_be_bytes());
        for (key, entry, dir) in flows {
            encode_data_record(
                &mut body,
                key,
                entry,
                dir,
                template_id,
                now_mono_ns,
                now_wall_ms,
            );
        }

        // IPFIX message header (16 bytes)
        let total_len = 16 + body.len();
        buf.extend_from_slice(&IPFIX_VERSION.to_be_bytes());
        buf.extend_from_slice(&(total_len as u16).to_be_bytes());
        // export_time: Unix seconds (u32)
        let export_time_s = (now_wall_ms / 1000) as u32;
        buf.extend_from_slice(&export_time_s.to_be_bytes());
        buf.extend_from_slice(&self.sequence_num.to_be_bytes());
        buf.extend_from_slice(&self.observation_domain_id.to_be_bytes());
        buf.extend_from_slice(&body);
        buf
    }
}

/// Build an IPFIX template set for the given template ID.
///
/// Template 256 (IPv4) fields:
///   IE 8  (sourceIPv4Address,          4 B)
///   IE 12 (destinationIPv4Address,     4 B)
///   IE 7  (sourceTransportPort,        2 B)
///   IE 11 (destinationTransportPort,   2 B)
///   IE 4  (protocolIdentifier,         1 B)
///   IE 61 (flowDirection,              1 B)
///   IE 152 (flowStartMilliseconds,     8 B)
///   IE 153 (flowEndMilliseconds,       8 B)
///   IE 2  (packetDeltaCount,           8 B)
///   IE 1  (octetDeltaCount,            8 B)
///
/// Template 257 (IPv6) is identical but uses IE 27/28 (16 B each).
fn build_template_set(template_id: u16) -> Vec<u8> {
    let is_v6 = template_id == TEMPLATE_ID_V6;
    let addr_ie_src: u16 = if is_v6 { 27 } else { 8 };
    let addr_ie_dst: u16 = if is_v6 { 28 } else { 12 };
    let addr_len: u16 = if is_v6 { 16 } else { 4 };

    // Fields: (ie_number, field_length) × 10
    let fields: [(u16, u16); 10] = [
        (addr_ie_src, addr_len),
        (addr_ie_dst, addr_len),
        (7, 2),   // sourceTransportPort
        (11, 2),  // destinationTransportPort
        (4, 1),   // protocolIdentifier
        (61, 1),  // flowDirection (0=ingress, 1=egress)
        (152, 8), // flowStartMilliseconds
        (153, 8), // flowEndMilliseconds
        (2, 8),   // packetDeltaCount
        (1, 8),   // octetDeltaCount
    ];

    // Template record body: template ID (2) + field count (2) + fields (4 each)
    let tmpl_record_len = 4 + fields.len() * 4;
    // Set: set_id (2) + set_len (2) + template record
    let set_len = 4 + tmpl_record_len;

    let mut buf = Vec::with_capacity(set_len);
    buf.extend_from_slice(&SET_ID_TEMPLATE.to_be_bytes());
    buf.extend_from_slice(&(set_len as u16).to_be_bytes());
    buf.extend_from_slice(&template_id.to_be_bytes());
    buf.extend_from_slice(&(fields.len() as u16).to_be_bytes());
    for (ie, len) in &fields {
        buf.extend_from_slice(&ie.to_be_bytes());
        buf.extend_from_slice(&len.to_be_bytes());
    }
    buf
}

/// Encode a single data record into `buf` in the order matching the template.
fn encode_data_record(
    buf: &mut Vec<u8>,
    key: &FlowKey,
    entry: &FlowCacheEntry,
    dir: &Direction,
    template_id: u16,
    now_mono_ns: u64,
    now_wall_ms: u64,
) {
    if template_id == TEMPLATE_ID_V4 {
        // saddr/daddr are copied verbatim from iph->saddr (network byte order __be32).
        // On a little-endian host, reading those bytes as u32 reverses them, so we
        // must use to_ne_bytes() (= to_le_bytes() on x86) to recover the original
        // network-byte-order byte sequence for the IPFIX record.
        buf.extend_from_slice(&key.saddr[0].to_ne_bytes());
        buf.extend_from_slice(&key.daddr[0].to_ne_bytes());
    } else {
        // IPv6: each u32 word holds 4 address bytes in network byte order, same as v4.
        for w in &key.saddr {
            buf.extend_from_slice(&w.to_ne_bytes());
        }
        for w in &key.daddr {
            buf.extend_from_slice(&w.to_ne_bytes());
        }
    }
    buf.extend_from_slice(&key.sport.to_be_bytes());
    buf.extend_from_slice(&key.dport.to_be_bytes());
    buf.push(key.protocol);
    buf.push(match dir {
        Direction::Ingress => 0,
        Direction::Egress => 1,
    });

    let start_ms = mono_ns_to_wall_ms(entry.first_seen_ns, now_mono_ns, now_wall_ms);
    let end_ms = mono_ns_to_wall_ms(entry.last_seen_ns, now_mono_ns, now_wall_ms);
    buf.extend_from_slice(&start_ms.to_be_bytes());
    buf.extend_from_slice(&end_ms.to_be_bytes());
    buf.extend_from_slice(&entry.packets.to_be_bytes());
    buf.extend_from_slice(&entry.bytes.to_be_bytes());
}

/// Convert a BPF CLOCK_MONOTONIC nanosecond timestamp to a Unix millisecond
/// wall-clock timestamp.  Both `now_mono_ns` and `now_wall_ms` must have been
/// captured at the same moment at the start of the scan pass.
fn mono_ns_to_wall_ms(ts_mono_ns: u64, now_mono_ns: u64, now_wall_ms: u64) -> u64 {
    if ts_mono_ns >= now_mono_ns {
        return now_wall_ms;
    }
    let elapsed_ms = (now_mono_ns - ts_mono_ns) / 1_000_000;
    now_wall_ms.saturating_sub(elapsed_ms)
}

/// Read the current CLOCK_MONOTONIC time in nanoseconds.
/// Matches the clock used by `bpf_ktime_get_ns()` in the BPF programs.
fn monotonic_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

// ── unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_set_v4_length() {
        let tmpl = build_template_set(TEMPLATE_ID_V4);
        // set_id(2) + set_len(2) + tmpl_id(2) + field_count(2) + 10×(ie(2)+len(2))
        assert_eq!(tmpl.len(), 4 + 4 + 10 * 4);
        // set ID must be 2
        let set_id = u16::from_be_bytes([tmpl[0], tmpl[1]]);
        assert_eq!(set_id, SET_ID_TEMPLATE);
        // embedded template ID
        let tid = u16::from_be_bytes([tmpl[4], tmpl[5]]);
        assert_eq!(tid, TEMPLATE_ID_V4);
        // field count
        let fc = u16::from_be_bytes([tmpl[6], tmpl[7]]);
        assert_eq!(fc, 10);
    }

    #[test]
    fn test_template_set_v6_length() {
        let tmpl = build_template_set(TEMPLATE_ID_V6);
        assert_eq!(tmpl.len(), 4 + 4 + 10 * 4);
        let tid = u16::from_be_bytes([tmpl[4], tmpl[5]]);
        assert_eq!(tid, TEMPLATE_ID_V6);
    }

    #[test]
    fn test_v4_record_size() {
        let mut buf = Vec::new();
        let key = FlowKey {
            saddr: [0x0a_00_00_01, 0, 0, 0],
            daddr: [0x0a_00_00_02, 0, 0, 0],
            sport: 12345,
            dport: 80,
            protocol: 6,
            af: 2,
            flags: 0,
        };
        let entry = FlowCacheEntry {
            first_seen_ns: 1_000_000_000,
            last_seen_ns: 2_000_000_000,
            packets: 100,
            bytes: 50000,
            rule_id: 1,
            action: 1,
            _pad: 0,
        };
        encode_data_record(
            &mut buf,
            &key,
            &entry,
            &Direction::Ingress,
            TEMPLATE_ID_V4,
            3_000_000_000,
            3000,
        );
        assert_eq!(buf.len(), RECORD_SIZE_V4);
        // protocol byte at offset 4+4+2+2 = 12
        assert_eq!(buf[12], 6);
        // flow direction byte at offset 13: Ingress = 0
        assert_eq!(buf[13], 0);
        // packet count at offset 4+4+2+2+1+1+8+8 = 30
        let packets = u64::from_be_bytes(buf[30..38].try_into().unwrap());
        assert_eq!(packets, 100);
        // byte count
        let bytes = u64::from_be_bytes(buf[38..46].try_into().unwrap());
        assert_eq!(bytes, 50000);
    }

    #[test]
    fn test_v6_record_size() {
        let mut buf = Vec::new();
        let key = FlowKey {
            saddr: [0x20010db8, 0, 0, 1],
            daddr: [0x20010db8, 0, 0, 2],
            sport: 443,
            dport: 54321,
            protocol: 6,
            af: 10,
            flags: 0,
        };
        let entry = FlowCacheEntry::default();
        encode_data_record(
            &mut buf,
            &key,
            &entry,
            &Direction::Egress,
            TEMPLATE_ID_V6,
            0,
            0,
        );
        assert_eq!(buf.len(), RECORD_SIZE_V6);
        // protocol byte at offset 16+16+2+2 = 36
        assert_eq!(buf[36], 6);
        // flow direction byte at offset 37: Egress = 1
        assert_eq!(buf[37], 1);
    }

    #[test]
    fn test_v4_record_ip_byte_order() {
        // BPF copies iph->saddr (__be32) directly into flow_key.saddr4.
        // On a little-endian host, reading those 4 network-byte-order bytes as u32
        // byte-swaps the value.  For 10.20.30.40 (0x0A141E28 in network order):
        //   memory bytes: [0x0A, 0x14, 0x1E, 0x28]
        //   as LE u32:    0x281E140A
        // The encoder must emit [0x0A, 0x14, 0x1E, 0x28] in the IPFIX record.
        // Using to_be_bytes() would wrongly emit [0x28, 0x1E, 0x14, 0x0A] (40.30.20.10).
        let src_le = u32::from_be(0x0A141E28_u32); // 10.20.30.40 as LE u32
        let dst_le = u32::from_be(0x0A141E01_u32); // 10.20.30.1  as LE u32
        let key = FlowKey {
            saddr: [src_le, 0, 0, 0],
            daddr: [dst_le, 0, 0, 0],
            sport: 12345,
            dport: 80,
            protocol: 6,
            af: AF_INET,
            flags: 0,
        };
        let entry = FlowCacheEntry::default();
        let mut buf = Vec::new();
        encode_data_record(
            &mut buf,
            &key,
            &entry,
            &Direction::Ingress,
            TEMPLATE_ID_V4,
            0,
            0,
        );
        assert_eq!(
            &buf[0..4],
            &[0x0A, 0x14, 0x1E, 0x28],
            "src IP byte order wrong (10.20.30.40)"
        );
        assert_eq!(
            &buf[4..8],
            &[0x0A, 0x14, 0x1E, 0x01],
            "dst IP byte order wrong (10.20.30.1)"
        );
    }

    #[test]
    fn test_v6_record_ip_byte_order() {
        // IPv6 2001:0db8::1 — bytes: [20,01,0d,b8, 00,00,00,00, 00,00,00,00, 00,00,00,01]
        // BPF memcpy puts these into saddr6[4] words; on LE host each word is byte-swapped.
        // saddr6[0] = [20,01,0d,b8] as LE u32 = 0xB80D0120
        // saddr6[3] = [00,00,00,01] as LE u32 = 0x01000000
        // The encoder must emit the original bytes in network order.
        let saddr: [u32; 4] = [
            u32::from_be(0x20010db8),
            u32::from_be(0x00000000),
            u32::from_be(0x00000000),
            u32::from_be(0x00000001),
        ];
        let daddr: [u32; 4] = [
            u32::from_be(0x20010db8),
            u32::from_be(0x00000000),
            u32::from_be(0x00000000),
            u32::from_be(0x00000002),
        ];
        let key = FlowKey {
            saddr,
            daddr,
            sport: 443,
            dport: 54321,
            protocol: 6,
            af: 10,
            flags: 0,
        };
        let entry = FlowCacheEntry::default();
        let mut buf = Vec::new();
        encode_data_record(
            &mut buf,
            &key,
            &entry,
            &Direction::Egress,
            TEMPLATE_ID_V6,
            0,
            0,
        );
        // First 16 bytes = src 2001:db8::1 in network byte order
        assert_eq!(
            &buf[0..16],
            &[
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01
            ],
            "IPv6 src byte order wrong"
        );
        // Next 16 bytes = dst 2001:db8::2
        assert_eq!(
            &buf[16..32],
            &[
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x02
            ],
            "IPv6 dst byte order wrong"
        );
    }

    #[test]
    fn test_mono_ns_to_wall_ms_conversion() {
        let now_mono: u64 = 10_000_000_000; // 10 seconds
        let now_wall: u64 = 1_700_000_000_000; // arbitrary epoch ms
                                               // A flow that started 5 seconds ago (5s = 5_000_000_000 ns)
        let ts = 5_000_000_000u64;
        let result = mono_ns_to_wall_ms(ts, now_mono, now_wall);
        assert_eq!(result, now_wall - 5000); // 5000 ms earlier
    }

    #[test]
    fn test_mono_ns_future_clamp() {
        // ts in the "future" relative to now_mono — clamp to now
        let result = mono_ns_to_wall_ms(9999, 1000, 42000);
        assert_eq!(result, 42000);
    }

    #[test]
    fn test_ipfix_message_header() {
        let exporter = IpfixExporter {
            collector_addr: "127.0.0.1:4739".parse().unwrap(),
            idle_timeout_ns: 15_000_000_000,
            active_timeout_ns: 60_000_000_000,
            observation_domain_id: 1,
            sequence_num: 42,
            last_template_send: Instant::now(),
            records_since_template: 0,
            flows_exported_total: 0,
        };
        let msg =
            exporter.encode_ipfix_message(&[], TEMPLATE_ID_V4, RECORD_SIZE_V4, false, 0, 1000);
        // With no records and no template, message is header (16) + empty data set header (4)
        assert_eq!(msg.len(), 20);
        let version = u16::from_be_bytes([msg[0], msg[1]]);
        assert_eq!(version, IPFIX_VERSION);
        let seq = u32::from_be_bytes([msg[8], msg[9], msg[10], msg[11]]);
        assert_eq!(seq, 42);
    }
}
