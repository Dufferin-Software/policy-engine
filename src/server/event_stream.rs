// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! BPF ring buffer event streaming over WebSocket
//!
//! Polls pinned BPF ring buffer maps for policy events and broadcasts them
//! to connected WebSocket clients.

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Context;
use libc;
use std::sync::Arc;
use std::time::Duration;

fn resolve_ifindex(index: u32) -> Option<String> {
    let mut buf = vec![0u8; libc::IF_NAMESIZE];
    let ret = unsafe { libc::if_indextoname(index, buf.as_mut_ptr() as *mut libc::c_char) };
    if ret.is_null() {
        return None;
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8(buf[..len].to_vec()).ok()
}

use actix_web::{web, HttpRequest, HttpResponse};
use libbpf_rs::{MapHandle, RingBufferBuilder};
use log::{info, warn};
use serde::Serialize;
use tokio::sync::{broadcast, mpsc, watch, Mutex};
use tokio::time::interval;

use crate::config::AffinityPlan;
use crate::paths::BPF_PIN_PATH;
use crate::server::policy_service::PolicyService;
use crate::server::quic_initial;
use crate::types::{
    Direction, FlowVerdict, FlowVerdictKey, PolicyAction as PolicyActionEnum, AF_INET,
};
use crate::{PolicyAction, Protocol};

/// PASS/DROP verdict TTL written after a successful Initial SNI extraction.
/// 10 minutes — a QUIC/SNI verdict is keyed by the 5-tuple but decided by the
/// SNI hostname (not part of the key), so a reused 5-tuple can carry a different
/// hostname; a bounded TTL caps that staleness (rule-change flushing does not
/// cover it). Kept in sync with SNI_VERDICT_TTL_NS in
/// src/bpf/include/policy_common.h.
const QUIC_VERDICT_TTL_NS: u64 = 600_000_000_000;

const MAP_EVENTS: &str = "events";
const MAP_TC_EVENTS: &str = "tc_events";
const MAP_QUIC_INSPECT_EVENTS: &str = "quic_inspect_events";
const MAP_TC_QUIC_INSPECT_EVENTS: &str = "tc_quic_inspect_events";

use crate::types::{QUIC_INSPECT_MAX_DCID_LEN, QUIC_INSPECT_PAYLOAD_MAX};

/// Layout-compatible mirror of `struct quic_inspect_event` in policy_common.h.
/// Emitted by xdp_quic_initial_inspect / tc_quic_initial_inspect when a packet
/// passes the cheap QUIC long-header pre-checks; userspace will later derive
/// Initial keys and extract the ClientHello SNI.  For Phase 2 the consumer
/// just logs the event — decryption lands in a follow-up phase.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct QuicInspectEvent {
    pub timestamp_ns: u64,
    pub ifindex: u32,
    pub version: u32,
    pub flow: FlowKey,
    pub pkt_len: u32,
    pub payload_off: u16,
    pub payload_len: u16,
    pub dcid_len: u8,
    pub _pad: [u8; 7],
    pub dcid: [u8; QUIC_INSPECT_MAX_DCID_LEN],
    pub payload: [u8; QUIC_INSPECT_PAYLOAD_MAX],
}

unsafe impl Send for QuicInspectEvent {}
unsafe impl Sync for QuicInspectEvent {}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FlowKey {
    pub saddr6: [u32; 4],
    pub daddr6: [u32; 4],
    pub sport: u16,
    pub dport: u16,
    pub protocol: u8,
    pub af: u8,
    pub flags: u16, // FLOW_FLAG_* bitmask
}

/// Bit flag: packet is a non-first IP fragment
pub const FLOW_FLAG_FRAGMENT: u16 = 1 << 0;
/// Bit flag: packet is QUIC (UDP payload with QUIC long or short header)
pub const FLOW_FLAG_QUIC: u16 = 1 << 1;
/// Bit flag: QUIC long-header with version == 0x00000001 (RFC 9000)
pub const FLOW_FLAG_QUIC_V1: u16 = 1 << 2;
/// Bit flag: QUIC long-header with version == 0x6b3343cf (RFC 9369)
pub const FLOW_FLAG_QUIC_V2: u16 = 1 << 3;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PolicyEvent {
    pub timestamp_ns: u64,
    pub rule_id: u64,
    pub action: u32,
    pub ifindex: u32,
    pub flow: FlowKey,
    pub pkt_len: u32,
    pub verdict: u32,
    pub sni: [u8; 128],    /* SNI value if rule matched with SNI inspection */
    pub sni_len: u8,       /* Length of SNI string (0 if no SNI) */
    pub _sni_pad: [u8; 7], /* Alignment padding */
}

// SAFETY: PolicyEvent is a plain-old-data repr(C) struct with no pointers.
unsafe impl Send for PolicyEvent {}
unsafe impl Sync for PolicyEvent {}

/// JSON-serializable representation of a policy event for the frontend.
#[derive(Serialize, Clone, Debug)]
struct EventJson {
    timestamp_ns: u64,
    rule_id: u64,
    action: String,
    ifindex: u32,
    interface_name: Option<String>,
    src: String,
    dst: String,
    sport: u16,
    dport: u16,
    protocol: String,
    af: u8,
    pkt_len: u32,
    verdict: String,
    direction: String,
    fragment: bool,
    sni: Option<String>, /* SNI value if captured from SNI inspection rule */
    quic_version: Option<String>, /* "v1", "v2", or "any" when QUIC-flagged */
}

impl EventJson {
    fn from_event(ev: &PolicyEvent, direction: &str) -> Self {
        let (src, dst) = format_addrs(&ev.flow);
        let action: PolicyAction = ev.action.into();
        let verdict: PolicyAction = ev.verdict.into();
        let protocol: Protocol = ev.flow.protocol.into();

        /* Parse SNI from event if available */
        let sni = if ev.sni_len > 0 && (ev.sni_len as usize) <= ev.sni.len() {
            String::from_utf8_lossy(&ev.sni[..ev.sni_len as usize])
                .into_owned()
                .into()
        } else {
            None
        };

        let quic_version = if (ev.flow.flags & FLOW_FLAG_QUIC) != 0 {
            if (ev.flow.flags & FLOW_FLAG_QUIC_V1) != 0 {
                Some("v1".to_string())
            } else if (ev.flow.flags & FLOW_FLAG_QUIC_V2) != 0 {
                Some("v2".to_string())
            } else {
                Some("any".to_string())
            }
        } else {
            None
        };

        let interface_name = resolve_ifindex(ev.ifindex);

        EventJson {
            timestamp_ns: ev.timestamp_ns,
            rule_id: ev.rule_id,
            action: format!("{}", action),
            ifindex: ev.ifindex,
            interface_name,
            src,
            dst,
            sport: ev.flow.sport,
            dport: ev.flow.dport,
            protocol: format!("{}", protocol),
            af: ev.flow.af,
            pkt_len: ev.pkt_len,
            verdict: format!("{}", verdict),
            direction: direction.to_string(),
            fragment: (ev.flow.flags & FLOW_FLAG_FRAGMENT) != 0,
            sni,
            quic_version,
        }
    }
}

fn format_addrs(flow: &FlowKey) -> (String, String) {
    match flow.af as i32 {
        2 => {
            let s = Ipv4Addr::from(flow.saddr6[0].to_le_bytes());
            let d = Ipv4Addr::from(flow.daddr6[0].to_le_bytes());
            (s.to_string(), d.to_string())
        }
        10 => {
            let mut s_bytes = [0u8; 16];
            let mut d_bytes = [0u8; 16];
            for i in 0..4 {
                s_bytes[i * 4..(i + 1) * 4].copy_from_slice(&flow.saddr6[i].to_le_bytes());
                d_bytes[i * 4..(i + 1) * 4].copy_from_slice(&flow.daddr6[i].to_le_bytes());
            }
            let s = Ipv6Addr::from(s_bytes);
            let d = Ipv6Addr::from(d_bytes);
            (s.to_string(), d.to_string())
        }
        _ => (format!("{:?}", flow.saddr6), format!("{:?}", flow.daddr6)),
    }
}

/// Tagged event with direction info for the broadcast channel.
#[derive(Clone, Debug)]
pub struct TaggedEvent {
    pub event: PolicyEvent,
    pub direction: String,
}

/// Start the BPF ring buffer polling task. Returns a broadcast sender that
/// WebSocket handlers subscribe to.
///
/// The polling thread is pinned to `affinity.event_cpus` (unless disabled).
/// A separate tokio task consumes QUIC Initial samples and writes flow
/// verdicts via `service` after SNI extraction.
pub fn start_event_stream(
    affinity: Arc<AffinityPlan>,
    service: Arc<Mutex<PolicyService>>,
) -> broadcast::Sender<TaggedEvent> {
    let (tx, _) = broadcast::channel::<TaggedEvent>(1024);
    let tx_clone = tx.clone();

    // QUIC Initial events are decoded by a tokio task — the ringbuf callback
    // (running on the dedicated affinity-pinned thread) only forwards the
    // captured bytes to avoid blocking on a tokio Mutex.
    let (quic_tx, quic_rx) = mpsc::unbounded_channel::<QuicInspectSample>();
    tokio::spawn(quic_inspect_consumer(quic_rx, service, tx.clone()));

    std::thread::spawn(move || {
        if !affinity.disabled {
            super::cpu_affinity::pin_thread_to_cpus(&affinity.event_cpus);
        }
        poll_ring_buffers(tx_clone, quic_tx);
    });

    tx
}

/// Raw QUIC Initial sample shipped from the ringbuf thread to the consumer
/// task.  The payload is a small (≤1280 B) `Vec<u8>` rather than the full
/// `QuicInspectEvent` to avoid copying the ~1.3 kB padding the BPF struct
/// reserves.
#[derive(Debug)]
struct QuicInspectSample {
    direction: Direction,
    flow: FlowKey,
    version: u32,
    ifindex: u32,
    dcid: Vec<u8>,
    payload: Vec<u8>,
}

/// Compute the offset from CLOCK_MONOTONIC (used by bpf_ktime_get_ns) to
/// CLOCK_REALTIME (Unix epoch). Adding this to a BPF ktime_get_ns value
/// converts it to nanoseconds since the Unix epoch.
fn monotonic_to_realtime_offset() -> i64 {
    let mut realtime = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut monotonic = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut realtime);
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut monotonic);
    }
    let rt = realtime.tv_sec * 1_000_000_000 + realtime.tv_nsec;
    let mono = monotonic.tv_sec * 1_000_000_000 + monotonic.tv_nsec;
    rt - mono
}

fn poll_ring_buffers(
    tx: broadcast::Sender<TaggedEvent>,
    quic_tx: mpsc::UnboundedSender<QuicInspectSample>,
) {
    // Compute once at startup; drift is negligible for display purposes.
    let clock_offset: i64 = monotonic_to_realtime_offset();

    loop {
        match try_open_ring_buffer(&tx, clock_offset, &quic_tx) {
            Ok(ringbuf) => {
                info!("BPF event ring buffer opened, polling for events");
                loop {
                    if let Err(e) = ringbuf.poll(Duration::from_millis(100)) {
                        warn!("ringbuf poll error: {}", e);
                        break;
                    }
                }
                warn!("Ring buffer poll loop exited, will retry in 5s");
                std::thread::sleep(Duration::from_secs(5));
            }
            Err(e) => {
                // Maps not pinned yet (programs not loaded). Retry quickly so
                // the ring buffer opens within ~1s of the first attach call.
                warn!(
                    "Could not open BPF event ring buffers: {}. Retrying in 1s",
                    e
                );
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

fn try_open_ring_buffer(
    tx: &broadcast::Sender<TaggedEvent>,
    clock_offset: i64,
    quic_tx: &mpsc::UnboundedSender<QuicInspectSample>,
) -> anyhow::Result<libbpf_rs::RingBuffer<'static>> {
    // We need to keep the MapHandles alive for the lifetime of the ring buffer.
    // Leak them since this runs for the server's lifetime.
    let map_handles: &'static mut Vec<MapHandle> = Box::leak(Box::new(Vec::new()));

    // Record which indices correspond to which direction.
    let mut xdp_idx: Option<usize> = None;
    let mut tc_idx: Option<usize> = None;

    let xdp_path = format!("{}/{}", BPF_PIN_PATH, MAP_EVENTS);
    if std::path::Path::new(&xdp_path).exists() {
        let mh = MapHandle::from_pinned_path(&xdp_path)?;
        map_handles.push(mh);
        xdp_idx = Some(map_handles.len() - 1);
        info!("Opened XDP events ring buffer map");
    } else {
        warn!("XDP events map not found at {}", xdp_path);
    }

    let tc_path = format!("{}/{}", BPF_PIN_PATH, MAP_TC_EVENTS);
    if std::path::Path::new(&tc_path).exists() {
        let mh = MapHandle::from_pinned_path(&tc_path)?;
        map_handles.push(mh);
        tc_idx = Some(map_handles.len() - 1);
        info!("Opened TC events ring buffer map");
    } else {
        warn!("TC events map not found at {}", tc_path);
    }

    // QUIC Initial inspection ringbufs (XDP ingress + TC egress).
    // Phase 2: stub consumer that just logs.  Decryption / SNI extraction is
    // wired up in a follow-up phase.  Open before any rb_builder.add calls so
    // the mutable push doesn't overlap with later immutable handle borrows.
    let mut quic_slots: Vec<(&'static str, usize)> = Vec::new();
    for (label, name) in [
        ("XDP", MAP_QUIC_INSPECT_EVENTS),
        ("TC", MAP_TC_QUIC_INSPECT_EVENTS),
    ] {
        let path = format!("{}/{}", BPF_PIN_PATH, name);
        if !std::path::Path::new(&path).exists() {
            warn!("{} QUIC inspect map not found at {}", label, path);
            continue;
        }
        let mh = MapHandle::from_pinned_path(&path)?;
        map_handles.push(mh);
        quic_slots.push((label, map_handles.len() - 1));
        info!("Opened {} QUIC inspect ring buffer map", label);
    }

    if map_handles.is_empty() {
        anyhow::bail!("No event ring buffer maps found");
    }

    // Now add callbacks — all handles are collected so no more mutable borrows.
    let mut rb_builder = RingBufferBuilder::new();

    if let Some(idx) = xdp_idx {
        let tx_xdp = tx.clone();
        rb_builder.add(&map_handles[idx], move |data: &[u8]| {
            if data.len() >= std::mem::size_of::<PolicyEvent>() {
                let mut ev: PolicyEvent =
                    unsafe { std::ptr::read_unaligned(data.as_ptr() as *const _) };
                // Convert CLOCK_MONOTONIC (bpf_ktime_get_ns) to CLOCK_REALTIME
                ev.timestamp_ns = (ev.timestamp_ns as i64 + clock_offset) as u64;
                let subs = tx_xdp.receiver_count();
                info!(
                    "XDP ringbuf event: rule_id={} action={} verdict={} (subscribers={})",
                    ev.rule_id, ev.action, ev.verdict, subs
                );
                let _ = tx_xdp.send(TaggedEvent {
                    event: ev,
                    direction: "INGRESS".to_string(),
                });
            } else {
                warn!("XDP ringbuf: short sample {} bytes", data.len());
            }
            0
        })?;
    }

    if let Some(idx) = tc_idx {
        let tx_tc = tx.clone();
        rb_builder.add(&map_handles[idx], move |data: &[u8]| {
            if data.len() >= std::mem::size_of::<PolicyEvent>() {
                let mut ev: PolicyEvent =
                    unsafe { std::ptr::read_unaligned(data.as_ptr() as *const _) };
                // Convert CLOCK_MONOTONIC (bpf_ktime_get_ns) to CLOCK_REALTIME
                ev.timestamp_ns = (ev.timestamp_ns as i64 + clock_offset) as u64;
                let subs = tx_tc.receiver_count();
                info!(
                    "TC ringbuf event: rule_id={} action={} verdict={} (subscribers={})",
                    ev.rule_id, ev.action, ev.verdict, subs
                );
                let _ = tx_tc.send(TaggedEvent {
                    event: ev,
                    direction: "EGRESS".to_string(),
                });
            } else {
                warn!("TC ringbuf: short sample {} bytes", data.len());
            }
            0
        })?;
    }

    for (label, idx) in quic_slots {
        let quic_tx = quic_tx.clone();
        let direction = if label == "XDP" {
            Direction::Ingress
        } else {
            Direction::Egress
        };
        rb_builder.add(&map_handles[idx], move |data: &[u8]| {
            forward_quic_inspect_sample(label, direction, &quic_tx, data);
            0
        })?;
    }

    let ringbuf = rb_builder.build()?;
    Ok(ringbuf)
}

/// Forward a captured QUIC Initial sample from the ringbuf thread to the
/// async consumer task.  Performs only the bare minimum decode here so the
/// ringbuf polling loop stays fast.
fn forward_quic_inspect_sample(
    label: &str,
    direction: Direction,
    quic_tx: &mpsc::UnboundedSender<QuicInspectSample>,
    data: &[u8],
) {
    if data.len() < std::mem::size_of::<QuicInspectEvent>() {
        warn!(
            "{} quic_inspect ringbuf: short sample {} bytes (need {})",
            label,
            data.len(),
            std::mem::size_of::<QuicInspectEvent>()
        );
        return;
    }
    let ev: QuicInspectEvent = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const _) };
    // Reads from packed struct fields require copying into locals first.
    let version = ev.version;
    let dcid_len = ev.dcid_len as usize;
    let payload_len = ev.payload_len as usize;

    if dcid_len == 0 || dcid_len > QUIC_INSPECT_MAX_DCID_LEN || payload_len < 6 + dcid_len {
        warn!(
            "{} quic_inspect: implausible dcid_len={} payload_len={}, skipping",
            label, dcid_len, payload_len
        );
        return;
    }

    let payload = ev.payload[..payload_len.min(ev.payload.len())].to_vec();
    let dcid = payload[6..6 + dcid_len].to_vec();
    let ifindex = ev.ifindex;
    let sample = QuicInspectSample {
        direction,
        flow: ev.flow,
        version,
        ifindex,
        dcid,
        payload,
    };
    if quic_tx.send(sample).is_err() {
        warn!(
            "{} quic_inspect: consumer task gone, dropping sample",
            label
        );
    }
}

/// Async consumer for QUIC Initial samples.  Decrypts each Initial, accumulates
/// CRYPTO chunks into a per-flow reassembly buffer, extracts the SNI once the
/// ClientHello is whole, matches against the userspace mirror of the policy
/// rules, and writes a PASS/DROP verdict into flow_verdict_cache via
/// BpfOperations.
async fn quic_inspect_consumer(
    mut rx: mpsc::UnboundedReceiver<QuicInspectSample>,
    service: Arc<Mutex<PolicyService>>,
    tx: broadcast::Sender<TaggedEvent>,
) {
    let mut reasm = quic_initial::ReassemblyTable::new();
    // Per-rule rate limiter for LOG actions, mirroring `rule_stats.last_log_ns`
    // used by the BPF SNI path.  Keys are rule ids; values are the monotonic
    // ns timestamp of the last emitted log event.
    let mut last_log_ns: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
    let mut evict_tick = tokio::time::interval(std::time::Duration::from_secs(2));
    evict_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;
            maybe_sample = rx.recv() => {
                let Some(sample) = maybe_sample else { break };
                if let Err(e) = process_quic_sample(&sample, &service, &mut reasm, &tx, &mut last_log_ns).await {
                    // Decryption can legitimately fail (corrupted Initial, server-
                    // sent Initial reaching us by mistake, future version).
                    warn!(
                        "quic_inspect: dropped sample (dir={:?}, version=0x{:08x}): {:#}",
                        sample.direction, sample.version, e
                    );
                }
            }
            _ = evict_tick.tick() => {
                let before = reasm.len();
                reasm.evict_stale(std::time::Instant::now());
                let after = reasm.len();
                if before != after {
                    log::debug!("quic_inspect: evicted {} stale reassemblies ({} active)",
                        before - after, after);
                }
            }
        }
    }
    info!("quic_inspect consumer task exiting (channel closed)");
}

fn reassembly_key_for(sample: &QuicInspectSample) -> quic_initial::ReassemblyKey {
    let mut saddr = [0u8; 16];
    let mut daddr = [0u8; 16];
    if sample.flow.af == AF_INET {
        saddr[..4].copy_from_slice(&sample.flow.saddr6[0].to_le_bytes());
        daddr[..4].copy_from_slice(&sample.flow.daddr6[0].to_le_bytes());
    } else {
        for i in 0..4 {
            saddr[i * 4..i * 4 + 4].copy_from_slice(&sample.flow.saddr6[i].to_le_bytes());
            daddr[i * 4..i * 4 + 4].copy_from_slice(&sample.flow.daddr6[i].to_le_bytes());
        }
    }
    quic_initial::ReassemblyKey {
        saddr,
        daddr,
        sport: sample.flow.sport,
        dport: sample.flow.dport,
        protocol: sample.flow.protocol,
        af: sample.flow.af,
        dcid: sample.dcid.clone(),
    }
}

async fn process_quic_sample(
    sample: &QuicInspectSample,
    service: &Arc<Mutex<PolicyService>>,
    reasm: &mut quic_initial::ReassemblyTable,
    tx: &broadcast::Sender<TaggedEvent>,
    last_log_ns: &mut std::collections::HashMap<u64, u64>,
) -> anyhow::Result<()> {
    let key = reassembly_key_for(sample);
    let outcome = reasm.add_packet(key, &sample.payload, sample.version)?;

    let (sni, write_verdict) = match outcome {
        quic_initial::ReassemblyOutcome::Sni(s) => (Some(s), true),
        // No SNI extension at all — there's no name to match, but the flow
        // is fully inspected so cache a PASS to short-circuit subsequent
        // packets.
        quic_initial::ReassemblyOutcome::NoSni => (None, true),
        // Bizarre / malformed: nothing more we can do for this flow.  Don't
        // cache a verdict — let the L4 path keep handling subsequent packets
        // normally (which is also PASS, since there's no other action).
        quic_initial::ReassemblyOutcome::NotClientHello => {
            log::debug!(
                "quic_inspect: dir={:?} contiguous prefix not a ClientHello",
                sample.direction
            );
            return Ok(());
        }
        quic_initial::ReassemblyOutcome::Partial { have, need } => {
            log::debug!(
                "quic_inspect: dir={:?} partial ClientHello ({}/{} bytes)",
                sample.direction,
                have,
                need
            );
            return Ok(());
        }
        quic_initial::ReassemblyOutcome::NeedMore { contiguous } => {
            log::debug!(
                "quic_inspect: dir={:?} awaiting more CRYPTO ({} bytes contiguous)",
                sample.direction,
                contiguous
            );
            return Ok(());
        }
    };

    let mut svc = service.lock().await;
    let bpf = svc.bpf_ops_mut();
    // Walk the matched rule's actions in priority order, mirroring the BPF
    // SNI path in tc_policy.bpf.c: LOG emits an event (rate-limited by the
    // per-action `param` ns), DROP is terminal and selects the verdict, PASS
    // is a no-op.  If no rule matched (or no SNI extension), the verdict is
    // PASS and no LOG events fire.
    let action = match sni.as_deref() {
        Some(name) => match quic_initial::match_sni_rules(name, sample.direction, bpf)? {
            Some(m) => {
                let now_ns = monotonic_now_ns();
                let mut final_action = PolicyActionEnum::Pass as u32;
                let mut log_actions: Vec<&crate::types::RuleAction> = Vec::new();
                for ra in &m.actions {
                    let a = ra.action;
                    if a == PolicyActionEnum::Drop as u32 {
                        final_action = a;
                        break;
                    } else if a == PolicyActionEnum::Log as u32 {
                        log_actions.push(ra);
                    }
                    // PASS / anything else: no-op, keep walking.
                }
                info!(
                    "quic_inspect: SNI={} matched rule_id={} action={}",
                    name,
                    m.rule_id,
                    PolicyAction::from(final_action)
                );
                for ra in log_actions {
                    let param = ra.param;
                    let allow = if param == 0 {
                        true
                    } else {
                        let last = last_log_ns.get(&m.rule_id).copied().unwrap_or(0);
                        now_ns.saturating_sub(last) >= param
                    };
                    if !allow {
                        continue;
                    }
                    last_log_ns.insert(m.rule_id, now_ns);
                    emit_quic_log_event(tx, sample, m.rule_id, final_action, name);
                }
                // Bump rule_stats so the operator-visible counters reflect
                // the QUIC SNI match the same way TCP SNI / L4 matches do.
                // Best-effort: a failure here doesn't change the verdict.
                if let Err(e) =
                    bpf.bump_rule_stats(m.rule_id, sample.direction, sample.payload.len() as u64)
                {
                    log::warn!(
                        "quic_inspect: bump_rule_stats(rule_id={}) failed: {:#}",
                        m.rule_id,
                        e
                    );
                }
                final_action
            }
            None => {
                log::debug!(
                    "quic_inspect: SNI={} no rule match, writing PASS verdict",
                    name
                );
                PolicyActionEnum::Pass as u32
            }
        },
        None => {
            log::debug!("quic_inspect: ClientHello has no SNI extension, writing PASS");
            PolicyActionEnum::Pass as u32
        }
    };

    if !write_verdict {
        return Ok(());
    }

    let vkey = flow_to_verdict_key(&sample.flow, sample.ifindex);
    let now_ns = monotonic_now_ns();
    let verdict = FlowVerdict {
        action,
        _pad: 0,
        timestamp_ns: now_ns,
        expires_ns: now_ns + QUIC_VERDICT_TTL_NS,
        packets: 0,
        bytes: 0,
        last_seen_ns: 0,
        rule_id: 0,
    };
    bpf.update_flow_verdict(&vkey, &verdict, sample.direction)
        .with_context(|| {
            format!(
                "writing {:?} verdict for {:?} flow (sport={}, dport={}, proto={}, af={})",
                PolicyAction::from(action),
                sample.direction,
                { vkey.sport },
                { vkey.dport },
                { vkey.protocol },
                { vkey.af },
            )
        })?;
    info!(
        "quic_inspect: wrote {:?} verdict for {:?} (SNI={})",
        PolicyAction::from(action),
        sample.direction,
        sni.as_deref().unwrap_or("<none>")
    );
    Ok(())
}

fn flow_to_verdict_key(flow: &FlowKey, ifindex: u32) -> FlowVerdictKey {
    let mut key = FlowVerdictKey::default();
    if flow.af == AF_INET {
        key.saddr[..4].copy_from_slice(&flow.saddr6[0].to_le_bytes());
        key.daddr[..4].copy_from_slice(&flow.daddr6[0].to_le_bytes());
    } else {
        for i in 0..4 {
            key.saddr[i * 4..(i + 1) * 4].copy_from_slice(&flow.saddr6[i].to_le_bytes());
            key.daddr[i * 4..(i + 1) * 4].copy_from_slice(&flow.daddr6[i].to_le_bytes());
        }
    }
    key.sport = flow.sport;
    key.dport = flow.dport;
    key.protocol = flow.protocol;
    key.af = flow.af;
    // Verdict cache is per-interface (see flow_verdict_key.ifindex in BPF). The
    // QUIC inspect sample carries the ifindex the dataplane observed this flow
    // on, which matches the cache key the XDP/TC fast path builds.
    key.ifindex = ifindex;
    key
}

fn monotonic_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

fn realtime_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

/// Mirror of the BPF SNI LOG ringbuf emission for the QUIC path.  Builds a
/// `PolicyEvent` with the matched rule id, the captured 5-tuple, the SNI,
/// and the final verdict the loop has decided so far, and broadcasts it to
/// any WebSocket subscribers.  Timestamp is realtime ns so it matches the
/// adjusted timestamps the kernel ringbuf path emits.
fn emit_quic_log_event(
    tx: &broadcast::Sender<TaggedEvent>,
    sample: &QuicInspectSample,
    rule_id: u64,
    final_action: u32,
    sni: &str,
) {
    let mut ev = PolicyEvent {
        timestamp_ns: realtime_now_ns(),
        rule_id,
        action: PolicyActionEnum::Log as u32,
        ifindex: sample.ifindex,
        flow: sample.flow,
        pkt_len: 0,
        verdict: final_action,
        sni: [0u8; 128],
        sni_len: 0,
        _sni_pad: [0u8; 7],
    };
    let bytes = sni.as_bytes();
    let n = bytes.len().min(ev.sni.len());
    ev.sni[..n].copy_from_slice(&bytes[..n]);
    ev.sni_len = n as u8;
    let direction = match sample.direction {
        Direction::Ingress => "INGRESS",
        Direction::Egress => "EGRESS",
    };
    let _ = tx.send(TaggedEvent {
        event: ev,
        direction: direction.to_string(),
    });
}

/// WebSocket handler for `/ws/events`.
pub async fn ws_events(
    req: HttpRequest,
    body: web::Payload,
    tx: web::Data<broadcast::Sender<TaggedEvent>>,
    shutdown: web::Data<Arc<watch::Sender<bool>>>,
) -> actix_web::Result<HttpResponse> {
    let (response, mut session, mut msg_stream) = actix_ws::handle(&req, body)?;

    let mut rx = tx.subscribe();
    // Each connection gets its own watch receiver so they track "seen" state
    // independently.  subscribe() always reflects the current sender value.
    let mut shutdown_rx = shutdown.subscribe();
    info!(
        "WebSocket client connected to /ws/events (subscribers={})",
        tx.receiver_count()
    );

    actix_rt::spawn(async move {
        use futures_util::StreamExt as _;
        // Track whether the read stream has ended.  Some WebSocket clients
        // (e.g. raw-socket implementations) may cause the actix-ws
        // MessageStream to return None immediately if the HTTP Payload is
        // considered exhausted.  We must keep sending events even when the
        // read stream ends — only a proper Close frame or a write error
        // should terminate the connection.
        let mut stream_open = true;
        // Server-initiated heartbeat: keeps the H1 write path active so the
        // actix dispatcher waker stays registered even for receive-only clients.
        let mut heartbeat = interval(Duration::from_secs(15));
        heartbeat.tick().await; // consume the immediate first tick
        loop {
            tokio::select! {
                // Incoming WebSocket frames: respond to pings, honour close.
                incoming = msg_stream.next(), if stream_open => {
                    match incoming {
                        Some(Ok(actix_ws::Message::Ping(bytes))) => {
                            if session.pong(&bytes).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(actix_ws::Message::Close(_))) => {
                            let _ = session.close(None).await;
                            break;
                        }
                        None => {
                            // Read stream ended — stop polling it but keep
                            // sending events.  This is common with raw-socket
                            // WebSocket clients that never send frames.
                            stream_open = false;
                        }
                        Some(_) => {} // text/binary/continuation/pong — ignore
                    }
                }
                // Server-initiated heartbeat ping.
                _ = heartbeat.tick() => {
                    if session.ping(b"").await.is_err() {
                        break;
                    }
                }
                // BPF events from the broadcast channel.
                result = rx.recv() => {
                    match result {
                        Ok(tagged) => {
                            let json = EventJson::from_event(&tagged.event, &tagged.direction);
                            match serde_json::to_string(&json) {
                                Ok(text) => {
                                    if session.text(text).await.is_err() {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to serialize event: {}", e);
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("WebSocket client lagged, skipped {} events", n);
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            let _ = session.close(None).await;
                            break;
                        }
                    }
                }
                // Server shutdown signal: send Close frame so clients know
                // why they were disconnected (rather than seeing a TCP RST).
                _ = shutdown_rx.changed() => {
                    let _ = session.close(Some(actix_ws::CloseReason {
                        code: actix_ws::CloseCode::Away,
                        description: Some("server shutting down".into()),
                    }))
                    .await;
                    break;
                }
            }
        }
    });

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PolicyAction;

    fn make_flow(
        af: u8,
        saddr0: u32,
        daddr0: u32,
        sport: u16,
        dport: u16,
        proto: u8,
        flags: u16,
    ) -> FlowKey {
        FlowKey {
            saddr6: [saddr0, 0, 0, 0],
            daddr6: [daddr0, 0, 0, 0],
            sport,
            dport,
            protocol: proto,
            af,
            flags,
        }
    }

    fn make_event(flow: FlowKey, action: PolicyAction, verdict: PolicyAction) -> PolicyEvent {
        PolicyEvent {
            timestamp_ns: 100_000,
            rule_id: 42,
            action: action as u32,
            ifindex: 3,
            flow,
            pkt_len: 200,
            verdict: verdict as u32,
            sni: [0u8; 128],
            sni_len: 0,
            _sni_pad: [0u8; 7],
        }
    }

    // ── format_addrs ────────────────────────────────────────────────────────

    #[test]
    fn format_addrs_ipv4() {
        let src_u32 = u32::from_le_bytes([10, 0, 0, 1]);
        let dst_u32 = u32::from_le_bytes([192, 168, 1, 1]);
        let flow = make_flow(2, src_u32, dst_u32, 1234, 80, 6, 0);
        let (src, dst) = format_addrs(&flow);
        assert_eq!(src, "10.0.0.1");
        assert_eq!(dst, "192.168.1.1");
    }

    #[test]
    fn format_addrs_ipv4_loopback() {
        let lo = u32::from_le_bytes([127, 0, 0, 1]);
        let flow = make_flow(2, lo, lo, 0, 0, 0, 0);
        let (src, dst) = format_addrs(&flow);
        assert_eq!(src, "127.0.0.1");
        assert_eq!(dst, "127.0.0.1");
    }

    #[test]
    fn format_addrs_ipv6_loopback() {
        let mut flow = FlowKey {
            saddr6: [0u32; 4],
            daddr6: [0u32; 4],
            sport: 0,
            dport: 0,
            protocol: 0,
            af: 10,
            flags: 0,
        };
        flow.saddr6[3] = u32::from_le_bytes([0, 0, 0, 1]);
        flow.daddr6[3] = u32::from_le_bytes([0, 0, 0, 1]);
        let (src, dst) = format_addrs(&flow);
        assert_eq!(src, "::1");
        assert_eq!(dst, "::1");
    }

    #[test]
    fn format_addrs_unknown_af_returns_debug_string() {
        let flow = make_flow(99, 0x01, 0x02, 0, 0, 0, 0);
        let (src, dst) = format_addrs(&flow);
        assert!(!src.is_empty());
        assert!(!dst.is_empty());
    }

    // ── EventJson::from_event ────────────────────────────────────────────────

    #[test]
    fn event_json_basic_fields() {
        let flow = make_flow(2, 0, 0, 1234, 80, libc::IPPROTO_TCP as u8, 0);
        let ev = make_event(flow, PolicyAction::Pass, PolicyAction::Pass);
        let json = EventJson::from_event(&ev, "INGRESS");
        assert_eq!(json.timestamp_ns, 100_000);
        assert_eq!(json.rule_id, 42);
        assert_eq!(json.action, "PASS");
        assert_eq!(json.verdict, "PASS");
        assert_eq!(json.direction, "INGRESS");
        assert_eq!(json.pkt_len, 200);
        assert_eq!(json.sport, 1234);
        assert_eq!(json.dport, 80);
        assert!(!json.fragment);
        assert!(json.sni.is_none());
    }

    #[test]
    fn event_json_drop_action() {
        let flow = make_flow(2, 0, 0, 0, 0, 6, 0);
        let ev = make_event(flow, PolicyAction::Drop, PolicyAction::Drop);
        let json = EventJson::from_event(&ev, "EGRESS");
        assert_eq!(json.action, "DROP");
        assert_eq!(json.verdict, "DROP");
        assert_eq!(json.direction, "EGRESS");
    }

    #[test]
    fn event_json_log_action() {
        let flow = make_flow(2, 0, 0, 0, 0, 6, 0);
        let ev = make_event(flow, PolicyAction::Log, PolicyAction::Pass);
        let json = EventJson::from_event(&ev, "INGRESS");
        assert_eq!(json.action, "LOG");
        assert_eq!(json.verdict, "PASS");
    }

    #[test]
    fn event_json_fragment_flag_set() {
        let flow = make_flow(2, 0, 0, 0, 0, 6, FLOW_FLAG_FRAGMENT);
        let ev = make_event(flow, PolicyAction::Pass, PolicyAction::Pass);
        let json = EventJson::from_event(&ev, "INGRESS");
        assert!(json.fragment);
    }

    #[test]
    fn event_json_fragment_flag_unset() {
        let flow = make_flow(2, 0, 0, 0, 0, 6, 0);
        let ev = make_event(flow, PolicyAction::Pass, PolicyAction::Pass);
        let json = EventJson::from_event(&ev, "INGRESS");
        assert!(!json.fragment);
    }

    #[test]
    fn event_json_sni_present() {
        let flow = make_flow(2, 0, 0, 0, 0, 6, 0);
        let mut ev = make_event(flow, PolicyAction::Pass, PolicyAction::Pass);
        let sni_bytes = b"example.com";
        ev.sni[..sni_bytes.len()].copy_from_slice(sni_bytes);
        ev.sni_len = sni_bytes.len() as u8;
        let json = EventJson::from_event(&ev, "INGRESS");
        assert_eq!(json.sni, Some("example.com".to_string()));
    }

    #[test]
    fn event_json_sni_zero_length_is_none() {
        let flow = make_flow(2, 0, 0, 0, 0, 6, 0);
        let ev = make_event(flow, PolicyAction::Pass, PolicyAction::Pass);
        let json = EventJson::from_event(&ev, "INGRESS");
        assert!(json.sni.is_none());
    }

    #[test]
    fn event_json_protocol_tcp() {
        let flow = make_flow(2, 0, 0, 0, 0, libc::IPPROTO_TCP as u8, 0);
        let ev = make_event(flow, PolicyAction::Pass, PolicyAction::Pass);
        let json = EventJson::from_event(&ev, "INGRESS");
        assert_eq!(json.protocol, "TCP");
    }

    #[test]
    fn event_json_protocol_udp() {
        let flow = make_flow(2, 0, 0, 0, 0, libc::IPPROTO_UDP as u8, 0);
        let ev = make_event(flow, PolicyAction::Pass, PolicyAction::Pass);
        let json = EventJson::from_event(&ev, "INGRESS");
        assert_eq!(json.protocol, "UDP");
    }

    #[test]
    fn event_json_af_field() {
        let flow = make_flow(2, 0, 0, 0, 0, 6, 0);
        let ev = make_event(flow, PolicyAction::Pass, PolicyAction::Pass);
        let json = EventJson::from_event(&ev, "INGRESS");
        assert_eq!(json.af, 2);
    }

    // ── TaggedEvent ──────────────────────────────────────────────────────────

    #[test]
    fn tagged_event_clone() {
        let flow = make_flow(2, 0, 0, 0, 0, 6, 0);
        let ev = make_event(flow, PolicyAction::Pass, PolicyAction::Pass);
        let tagged = TaggedEvent {
            event: ev,
            direction: "INGRESS".to_string(),
        };
        let cloned = tagged.clone();
        assert_eq!(cloned.direction, "INGRESS");
        assert_eq!(cloned.event.timestamp_ns, 100_000);
        assert_eq!(cloned.event.rule_id, 42);
    }

    // ── Constants ────────────────────────────────────────────────────────────

    #[test]
    fn flow_flag_fragment_is_bit_zero() {
        assert_eq!(FLOW_FLAG_FRAGMENT, 1);
    }

    // ── monotonic_to_realtime_offset ─────────────────────────────────────────

    #[test]
    fn monotonic_to_realtime_offset_is_positive() {
        // Realtime (Unix epoch) is always much larger than CLOCK_MONOTONIC
        // (system uptime), so the offset should be a large positive number.
        let offset = monotonic_to_realtime_offset();
        assert!(
            offset > 0,
            "realtime - monotonic should be positive (Unix epoch >> uptime), got {}",
            offset
        );
    }

    #[test]
    fn monotonic_to_realtime_offset_is_stable() {
        // Two consecutive calls should return nearly identical offsets
        // (within 1 second of drift).
        let a = monotonic_to_realtime_offset();
        let b = monotonic_to_realtime_offset();
        let diff = (a - b).abs();
        assert!(
            diff < 1_000_000_000,
            "offset should be stable between calls, delta={} ns",
            diff
        );
    }

    #[test]
    fn monotonic_to_realtime_offset_reasonable_magnitude() {
        // The Unix epoch started in 1970; uptime is at most decades.
        // The offset should be at least 50 years in nanoseconds.
        let fifty_years_ns: i64 = 50 * 365 * 24 * 3600 * 1_000_000_000_i64;
        let offset = monotonic_to_realtime_offset();
        assert!(
            offset > fifty_years_ns,
            "offset should be > 50 years in ns, got {}",
            offset
        );
    }

    // ── format_addrs edge-cases ───────────────────────────────────────────────

    #[test]
    fn format_addrs_ipv4_all_zeros() {
        let flow = make_flow(2, 0, 0, 0, 0, 6, 0);
        let (src, dst) = format_addrs(&flow);
        assert_eq!(src, "0.0.0.0");
        assert_eq!(dst, "0.0.0.0");
    }

    #[test]
    fn format_addrs_ipv4_broadcast() {
        let bcast = u32::from_le_bytes([255, 255, 255, 255]);
        let flow = make_flow(2, bcast, bcast, 0, 0, 6, 0);
        let (src, dst) = format_addrs(&flow);
        assert_eq!(src, "255.255.255.255");
        assert_eq!(dst, "255.255.255.255");
    }

    #[test]
    fn format_addrs_ipv6_all_zeros() {
        let flow = FlowKey {
            saddr6: [0u32; 4],
            daddr6: [0u32; 4],
            sport: 0,
            dport: 0,
            protocol: 0,
            af: 10,
            flags: 0,
        };
        let (src, dst) = format_addrs(&flow);
        assert_eq!(src, "::");
        assert_eq!(dst, "::");
    }

    #[test]
    fn format_addrs_ipv6_non_loopback() {
        // fe80::1 stored as 4 LE u32 words.
        // IPv6 bytes 0-3: [0xfe, 0x80, 0x00, 0x00] → saddr6[0] = u32::from_le_bytes([0xfe,0x80,0,0])
        // IPv6 bytes 12-15: [0x00, 0x00, 0x00, 0x01] → saddr6[3] = u32::from_le_bytes([0,0,0,1])
        let mut flow = FlowKey {
            saddr6: [0u32; 4],
            daddr6: [0u32; 4],
            sport: 0,
            dport: 0,
            protocol: 0,
            af: 10,
            flags: 0,
        };
        flow.saddr6[0] = u32::from_le_bytes([0xfe, 0x80, 0x00, 0x00]);
        flow.saddr6[3] = u32::from_le_bytes([0x00, 0x00, 0x00, 0x01]);
        let (src, _dst) = format_addrs(&flow);
        assert!(src.starts_with("fe80"), "expected fe80 prefix, got {}", src);
    }

    #[test]
    fn format_addrs_unknown_af_is_nonempty() {
        // AF=0 is not 2 or 10, falls through to debug format
        let flow = make_flow(0, 0xdeadbeef, 0xcafebabe, 0, 0, 0, 0);
        let (src, dst) = format_addrs(&flow);
        assert!(!src.is_empty());
        assert!(!dst.is_empty());
    }

    // ── EventJson: more actions ───────────────────────────────────────────────

    #[cfg(feature = "suricata")]
    #[test]
    fn event_json_inspect_action() {
        let flow = make_flow(2, 0, 0, 0, 0, 6, 0);
        let ev = make_event(flow, PolicyAction::Inspect, PolicyAction::Pass);
        let json = EventJson::from_event(&ev, "INGRESS");
        assert_eq!(json.action, "INSPECT");
        assert_eq!(json.verdict, "PASS");
    }

    #[test]
    fn event_json_tailcall_action() {
        let flow = make_flow(2, 0, 0, 0, 0, 6, 0);
        let ev = make_event(flow, PolicyAction::TailCall, PolicyAction::Pass);
        let json = EventJson::from_event(&ev, "EGRESS");
        assert_eq!(json.action, "TAILCALL");
    }

    #[test]
    fn event_json_protocol_icmp() {
        let flow = make_flow(2, 0, 0, 0, 0, libc::IPPROTO_ICMP as u8, 0);
        let ev = make_event(flow, PolicyAction::Pass, PolicyAction::Pass);
        let json = EventJson::from_event(&ev, "INGRESS");
        assert_eq!(json.protocol, "ICMP");
    }

    #[test]
    fn event_json_protocol_icmpv6() {
        let flow = make_flow(10, 0, 0, 0, 0, libc::IPPROTO_ICMPV6 as u8, 0);
        let ev = make_event(flow, PolicyAction::Pass, PolicyAction::Pass);
        let json = EventJson::from_event(&ev, "INGRESS");
        assert_eq!(json.protocol, "ICMPv6");
    }

    #[test]
    fn event_json_protocol_any() {
        let flow = make_flow(2, 0, 0, 0, 0, 0, 0);
        let ev = make_event(flow, PolicyAction::Pass, PolicyAction::Pass);
        let json = EventJson::from_event(&ev, "INGRESS");
        assert_eq!(json.protocol, "ANY");
    }

    #[test]
    fn event_json_protocol_unknown_numeric() {
        let flow = make_flow(2, 0, 0, 0, 0, 47, 0); // GRE
        let ev = make_event(flow, PolicyAction::Pass, PolicyAction::Pass);
        let json = EventJson::from_event(&ev, "INGRESS");
        assert_eq!(json.protocol, "47");
    }

    // ── EventJson: SNI edge-cases ─────────────────────────────────────────────

    #[test]
    fn event_json_sni_exactly_128_bytes() {
        let flow = make_flow(2, 0, 0, 0, 0, 6, 0);
        let mut ev = make_event(flow, PolicyAction::Pass, PolicyAction::Pass);
        // Fill all 128 bytes with 'a'
        ev.sni = [b'a'; 128];
        ev.sni_len = 128;
        let json = EventJson::from_event(&ev, "INGRESS");
        assert_eq!(json.sni, Some("a".repeat(128)));
    }

    #[test]
    fn event_json_sni_length_exceeds_array_is_none() {
        let flow = make_flow(2, 0, 0, 0, 0, 6, 0);
        let mut ev = make_event(flow, PolicyAction::Pass, PolicyAction::Pass);
        ev.sni_len = 200; // sni array is only 128 bytes
        let json = EventJson::from_event(&ev, "INGRESS");
        assert!(json.sni.is_none(), "sni_len > array size should yield None");
    }

    // ── EventJson: fragment flag combinations ─────────────────────────────────

    #[test]
    fn event_json_other_flags_not_fragment() {
        // Bit 1 set, bit 0 clear — should NOT be flagged as fragment
        let flow = make_flow(2, 0, 0, 0, 0, 6, 0x0002);
        let ev = make_event(flow, PolicyAction::Pass, PolicyAction::Pass);
        let json = EventJson::from_event(&ev, "INGRESS");
        assert!(!json.fragment);
    }

    #[test]
    fn event_json_fragment_combined_with_other_flags() {
        // Both bit 0 and bit 1 set — should be fragment
        let flow = make_flow(2, 0, 0, 0, 0, 6, FLOW_FLAG_FRAGMENT | 0x0002);
        let ev = make_event(flow, PolicyAction::Pass, PolicyAction::Pass);
        let json = EventJson::from_event(&ev, "INGRESS");
        assert!(json.fragment);
    }

    // ── EventJson: JSON serialization ─────────────────────────────────────────

    #[test]
    fn event_json_serializes_to_valid_json() {
        let flow = make_flow(
            2,
            u32::from_le_bytes([10, 0, 0, 1]),
            u32::from_le_bytes([10, 0, 0, 2]),
            1234,
            80,
            libc::IPPROTO_TCP as u8,
            0,
        );
        let ev = make_event(flow, PolicyAction::Drop, PolicyAction::Drop);
        let json_obj = EventJson::from_event(&ev, "INGRESS");
        let serialized = serde_json::to_string(&json_obj).expect("should serialize to JSON");
        let parsed: serde_json::Value =
            serde_json::from_str(&serialized).expect("should parse as JSON");
        assert_eq!(parsed["action"], "DROP");
        assert_eq!(parsed["direction"], "INGRESS");
        assert_eq!(parsed["sport"], 1234);
        assert_eq!(parsed["dport"], 80);
        assert_eq!(parsed["src"], "10.0.0.1");
        assert_eq!(parsed["dst"], "10.0.0.2");
    }

    #[test]
    fn event_json_sni_present_serialized() {
        let flow = make_flow(2, 0, 0, 0, 443, 6, 0);
        let mut ev = make_event(flow, PolicyAction::Pass, PolicyAction::Pass);
        let sni = b"secure.example.com";
        ev.sni[..sni.len()].copy_from_slice(sni);
        ev.sni_len = sni.len() as u8;
        let json_obj = EventJson::from_event(&ev, "INGRESS");
        let serialized = serde_json::to_string(&json_obj).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed["sni"], "secure.example.com");
    }

    // ── EventJson: QUIC flags ─────────────────────────────────────────────────

    #[test]
    fn event_json_quic_v1_flag() {
        let flow = make_flow(
            2,
            0,
            0,
            0,
            443,
            libc::IPPROTO_UDP as u8,
            FLOW_FLAG_QUIC | FLOW_FLAG_QUIC_V1,
        );
        let ev = make_event(flow, PolicyAction::Pass, PolicyAction::Pass);
        let json = EventJson::from_event(&ev, "INGRESS");
        assert_eq!(json.quic_version, Some("v1".to_string()));
    }

    #[test]
    fn event_json_quic_v2_flag() {
        let flow = make_flow(
            2,
            0,
            0,
            0,
            443,
            libc::IPPROTO_UDP as u8,
            FLOW_FLAG_QUIC | FLOW_FLAG_QUIC_V2,
        );
        let ev = make_event(flow, PolicyAction::Pass, PolicyAction::Pass);
        let json = EventJson::from_event(&ev, "INGRESS");
        assert_eq!(json.quic_version, Some("v2".to_string()));
    }

    #[test]
    fn event_json_quic_short_header_no_version() {
        // Short header: QUIC set but neither V1 nor V2
        let flow = make_flow(2, 0, 0, 0, 443, libc::IPPROTO_UDP as u8, FLOW_FLAG_QUIC);
        let ev = make_event(flow, PolicyAction::Pass, PolicyAction::Pass);
        let json = EventJson::from_event(&ev, "INGRESS");
        assert_eq!(json.quic_version, Some("any".to_string()));
    }

    #[test]
    fn event_json_not_quic_is_none() {
        let flow = make_flow(2, 0, 0, 0, 80, libc::IPPROTO_UDP as u8, 0);
        let ev = make_event(flow, PolicyAction::Pass, PolicyAction::Pass);
        let json = EventJson::from_event(&ev, "INGRESS");
        assert!(json.quic_version.is_none());
    }

    // ── Struct layout ─────────────────────────────────────────────────────────

    #[test]
    fn flow_key_struct_size() {
        // saddr6 (16) + daddr6 (16) + sport (2) + dport (2) + protocol (1) + af (1) + flags (2) = 40
        assert_eq!(std::mem::size_of::<FlowKey>(), 40);
    }

    #[test]
    fn policy_event_has_expected_minimum_size() {
        // PolicyEvent must be at least large enough to hold the ring buffer sample
        // we read with read_unaligned. It must be > 0.
        assert!(std::mem::size_of::<PolicyEvent>() > 0);
    }

    #[test]
    fn tagged_event_direction_egress() {
        let flow = make_flow(2, 0, 0, 0, 0, 6, 0);
        let ev = make_event(flow, PolicyAction::Drop, PolicyAction::Drop);
        let tagged = TaggedEvent {
            event: ev,
            direction: "EGRESS".to_string(),
        };
        assert_eq!(tagged.direction, "EGRESS");
    }
}
