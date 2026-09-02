// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! QUIC Initial packet decryption and ClientHello SNI extraction.
//!
//! Implements just enough of RFC 9001 (QUIC v1) and RFC 9369 (QUIC v2) to:
//!   * derive client Initial keys from the Destination Connection ID,
//!   * remove header protection and AEAD-decrypt the Initial payload,
//!   * walk QUIC frames, reassemble a contiguous CRYPTO stream at offset 0,
//!   * parse the TLS ClientHello and pull out the SNI (server_name) extension.
//!
//! Fragmented ClientHellos that span multiple Initial packets are not
//! reassembled here — the BPF tail call seeds a 2 s PASS verdict and the next
//! Initial will be inspected again.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Nonce};
use anyhow::{anyhow, bail, Result};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::types::{QUIC_VERSION_V1, QUIC_VERSION_V2};

/// QUIC v1 Initial salt (RFC 9001 §5.2).
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// QUIC v2 Initial salt (RFC 9369 §3.3).
const INITIAL_SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// Derived client Initial secrets used by [`decrypt_initial`].
#[derive(Clone)]
pub struct InitialKeys {
    pub key: [u8; 16],
    pub iv: [u8; 12],
    pub hp_key: [u8; 16],
}

/// Compute HKDF-Expand-Label per TLS 1.3 (RFC 8446 §7.1).
///
/// The label form is `"tls13 " || label` for TLS, but QUIC uses `"tls13 quic..."`
/// or `"tls13 quicv2..."` already encoded in the caller-supplied label string.
fn hkdf_expand_label(prk: &[u8], label: &str, length: usize) -> Result<Vec<u8>> {
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1);
    info.extend_from_slice(&(length as u16).to_be_bytes());
    let full_label = format!("tls13 {}", label);
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(0); // empty context

    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|e| anyhow!("HKDF from_prk failed: {:?}", e))?;
    let mut out = vec![0u8; length];
    hk.expand(&info, &mut out)
        .map_err(|e| anyhow!("HKDF expand failed: {:?}", e))?;
    Ok(out)
}

/// Derive client Initial AEAD keys for the given DCID and QUIC version.
pub fn derive_initial_keys(dcid: &[u8], version: u32) -> Result<InitialKeys> {
    let (salt, key_label, iv_label, hp_label) = match version {
        QUIC_VERSION_V1 => (&INITIAL_SALT_V1[..], "quic key", "quic iv", "quic hp"),
        QUIC_VERSION_V2 => (&INITIAL_SALT_V2[..], "quicv2 key", "quicv2 iv", "quicv2 hp"),
        v => bail!("unsupported QUIC version 0x{:08x}", v),
    };

    // HKDF-Extract(salt, dcid) → initial_secret
    let (initial_secret, _) = Hkdf::<Sha256>::extract(Some(salt), dcid);

    // client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
    let cis = hkdf_expand_label(&initial_secret, "client in", 32)?;

    let key = hkdf_expand_label(&cis, key_label, 16)?;
    let iv = hkdf_expand_label(&cis, iv_label, 12)?;
    let hp = hkdf_expand_label(&cis, hp_label, 16)?;

    let mut k = [0u8; 16];
    k.copy_from_slice(&key);
    let mut i = [0u8; 12];
    i.copy_from_slice(&iv);
    let mut h = [0u8; 16];
    h.copy_from_slice(&hp);

    Ok(InitialKeys {
        key: k,
        iv: i,
        hp_key: h,
    })
}

/// Read a QUIC varint at `offset`, returning `(value, bytes_consumed)`.
fn read_varint(buf: &[u8], offset: usize) -> Result<(u64, usize)> {
    if offset >= buf.len() {
        bail!("varint: out of bounds");
    }
    let first = buf[offset];
    let len = 1usize << (first >> 6); // 1, 2, 4, 8
    if offset + len > buf.len() {
        bail!("varint: truncated ({}B needed)", len);
    }
    let mut v = (first & 0x3f) as u64;
    for i in 1..len {
        v = (v << 8) | buf[offset + i] as u64;
    }
    Ok((v, len))
}

/// Parsed offsets within an Initial packet, sufficient to remove header
/// protection and run AEAD decryption.
struct InitialFraming {
    /// Offset of the start of the (still-protected) packet number.
    pn_offset: usize,
    /// `length` varint value: pn bytes + encrypted payload + 16-byte tag.
    length: usize,
}

/// Parse the long-header framing up to (but not into) the protected packet
/// number, returning the offsets we'll need for decryption.
fn parse_initial_framing(pkt: &[u8]) -> Result<InitialFraming> {
    if pkt.len() < 7 {
        bail!("initial: too short for header");
    }
    let dcid_len = pkt[5] as usize;
    let scid_off = 6 + dcid_len;
    if scid_off >= pkt.len() {
        bail!("initial: dcid overruns buffer");
    }
    let scid_len = pkt[scid_off] as usize;
    let token_len_off = scid_off + 1 + scid_len;
    if token_len_off >= pkt.len() {
        bail!("initial: scid overruns buffer");
    }
    let (token_len, token_len_size) = read_varint(pkt, token_len_off)?;
    let token_off = token_len_off + token_len_size;
    let length_off = token_off + token_len as usize;
    if length_off > pkt.len() {
        bail!("initial: token overruns buffer");
    }
    let (length, length_size) = read_varint(pkt, length_off)?;
    let pn_offset = length_off + length_size;
    if pn_offset + length as usize > pkt.len() {
        bail!(
            "initial: declared length {} extends past captured payload (have {})",
            length,
            pkt.len() - pn_offset
        );
    }
    Ok(InitialFraming {
        pn_offset,
        length: length as usize,
    })
}

/// Decrypt a client Initial packet and return the cleartext QUIC frame bytes.
///
/// `pkt` must start at the QUIC long-header first byte and contain the full
/// packet (header + protected payload + 16-byte AEAD tag).  Only client
/// Initial packets are supported — the function uses the client_initial_secret
/// to derive keys.
pub fn decrypt_initial(pkt: &[u8], dcid: &[u8], version: u32) -> Result<Vec<u8>> {
    let keys = derive_initial_keys(dcid, version)?;
    decrypt_initial_with_keys(pkt, &keys)
}

/// Internal: same as [`decrypt_initial`] but takes pre-derived keys (cheaper
/// in tests that want to assert the key-derivation step separately).
pub fn decrypt_initial_with_keys(pkt: &[u8], keys: &InitialKeys) -> Result<Vec<u8>> {
    let framing = parse_initial_framing(pkt)?;
    let pn_offset = framing.pn_offset;

    // Header-protection sample: 16 bytes starting at pn_offset + 4.
    if pn_offset + 4 + 16 > pkt.len() {
        bail!("initial: not enough payload for HP sample");
    }
    let sample = &pkt[pn_offset + 4..pn_offset + 4 + 16];

    // mask = AES-128-ECB(hp_key, sample) — single block, no chaining needed.
    let cipher = Aes128::new(GenericArray::from_slice(&keys.hp_key));
    let mut block = [0u8; 16];
    block.copy_from_slice(sample);
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
    let mask = block;

    // Unprotect the header.  Long header: low 4 bits of first byte are masked.
    let mut hdr = pkt[..pn_offset].to_vec();
    hdr[0] ^= mask[0] & 0x0f;
    let pn_len = ((hdr[0] & 0x03) as usize) + 1;
    if pn_offset + pn_len > pkt.len() {
        bail!("initial: pn extends past buffer");
    }
    // Append the unprotected packet number bytes to the AAD header.
    let mut pn_bytes = [0u8; 4];
    for i in 0..pn_len {
        let b = pkt[pn_offset + i] ^ mask[1 + i];
        pn_bytes[4 - pn_len + i] = b;
        hdr.push(b);
    }
    // For the first Initial we assume largest_pn = 0, so the truncated PN is
    // the full packet number.  Build the 12-byte nonce.
    let pn = u32::from_be_bytes(pn_bytes) as u64;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&keys.iv);
    let pn_be = pn.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= pn_be[i];
    }

    // Ciphertext spans from end of PN to end of declared length (which
    // includes pn_len + ciphertext + 16-byte tag).
    let ct_start = pn_offset + pn_len;
    let ct_end = pn_offset + framing.length;
    if ct_end > pkt.len() || ct_end - ct_start < 16 {
        bail!("initial: ciphertext bounds invalid");
    }
    let ciphertext = &pkt[ct_start..ct_end];

    let gcm = Aes128Gcm::new(GenericArray::from_slice(&keys.key));
    let plaintext = gcm
        .decrypt(
            Nonce::from_slice(&nonce),
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: &hdr,
            },
        )
        .map_err(|_| anyhow!("AES-GCM decrypt failed (bad keys or corrupted packet)"))?;

    Ok(plaintext)
}

// ── Frame walk + ClientHello SNI extraction ───────────────────────────────

/// Frame type constants from RFC 9000 §19.
const FRAME_PADDING: u64 = 0x00;
const FRAME_PING: u64 = 0x01;
const FRAME_ACK: u64 = 0x02;
const FRAME_ACK_ECN: u64 = 0x03;
const FRAME_CRYPTO: u64 = 0x06;
const FRAME_CONNECTION_CLOSE: u64 = 0x1c;
const FRAME_CONNECTION_CLOSE_APP: u64 = 0x1d;

/// Walk QUIC frames in `frames` and return every CRYPTO chunk as `(offset, data)`.
/// The chunks may overlap, be out-of-order, and have gaps — Firefox/Chrome
/// commonly fragment the ClientHello deliberately for anti-fingerprinting.
/// Returns an empty `Vec` if the packet contains no CRYPTO frames.
pub fn collect_crypto_chunks(frames: &[u8]) -> Result<Vec<(u64, Vec<u8>)>> {
    let mut out: Vec<(u64, Vec<u8>)> = Vec::new();
    walk_initial_frames(frames, |off, data| out.push((off, data.to_vec())))?;
    Ok(out)
}

/// Walk QUIC frames in `frames`, collecting CRYPTO data into a contiguous
/// TLS-message buffer starting at stream offset 0.  Returns `None` if the
/// CRYPTO stream has a gap at the start (fragmented ClientHello we can't
/// reassemble from a single packet).
fn reassemble_crypto_stream(frames: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut chunks: Vec<(u64, &[u8])> = Vec::new();
    walk_initial_frames(frames, |off, data| chunks.push((off, data)))?;
    coalesce_contiguous_prefix(&mut chunks)
}

/// Re-arrange chunks (sort by offset, splice contiguous prefix from 0) and
/// return that prefix, or `None` if there's a gap at the start of the stream.
fn coalesce_contiguous_prefix(chunks: &mut Vec<(u64, &[u8])>) -> Result<Option<Vec<u8>>> {
    if chunks.is_empty() {
        return Ok(None);
    }
    chunks.sort_by_key(|c| c.0);
    if chunks[0].0 != 0 {
        return Ok(None);
    }
    let mut out = Vec::new();
    let mut next_off: u64 = 0;
    for (off, data) in chunks.iter() {
        if *off > next_off {
            break;
        }
        if *off == next_off {
            out.extend_from_slice(data);
            next_off += data.len() as u64;
        } else {
            let skip = (next_off - off) as usize;
            if skip < data.len() {
                out.extend_from_slice(&data[skip..]);
                next_off += (data.len() - skip) as u64;
            }
        }
    }
    Ok(Some(out))
}

/// Walk QUIC frames legal in an Initial packet, invoking `on_crypto` for each
/// CRYPTO frame's `(offset, data)`.  Rejects any frame type not permitted in
/// Initial packets (RFC 9000 §17.2.2).
fn walk_initial_frames<'a>(
    frames: &'a [u8],
    mut on_crypto: impl FnMut(u64, &'a [u8]),
) -> Result<()> {
    let mut i = 0;
    while i < frames.len() {
        let (ftype, ft_len) = read_varint(frames, i)?;
        i += ft_len;
        match ftype {
            FRAME_PADDING | FRAME_PING => {
                // Single-byte frame; nothing more to consume.  PADDING is
                // technically a single byte per frame and the loop will pick
                // up any further PADDING bytes on its own.
            }
            FRAME_ACK | FRAME_ACK_ECN => {
                // largest_ack, ack_delay, ack_range_count, first_ack_range
                let (_largest, n1) = read_varint(frames, i)?;
                i += n1;
                let (_delay, n2) = read_varint(frames, i)?;
                i += n2;
                let (range_count, n3) = read_varint(frames, i)?;
                i += n3;
                let (_first, n4) = read_varint(frames, i)?;
                i += n4;
                for _ in 0..range_count {
                    let (_gap, ng) = read_varint(frames, i)?;
                    i += ng;
                    let (_len, nl) = read_varint(frames, i)?;
                    i += nl;
                }
                if ftype == FRAME_ACK_ECN {
                    for _ in 0..3 {
                        let (_v, nv) = read_varint(frames, i)?;
                        i += nv;
                    }
                }
            }
            FRAME_CRYPTO => {
                let (offset, n1) = read_varint(frames, i)?;
                i += n1;
                let (length, n2) = read_varint(frames, i)?;
                i += n2;
                let end = i + length as usize;
                if end > frames.len() {
                    bail!("CRYPTO frame length {} exceeds remaining bytes", length);
                }
                on_crypto(offset, &frames[i..end]);
                i = end;
            }
            FRAME_CONNECTION_CLOSE => {
                let (_err, n1) = read_varint(frames, i)?;
                i += n1;
                let (_ft, n2) = read_varint(frames, i)?;
                i += n2;
                let (reason_len, n3) = read_varint(frames, i)?;
                i += n3 + reason_len as usize;
            }
            FRAME_CONNECTION_CLOSE_APP => {
                let (_err, n1) = read_varint(frames, i)?;
                i += n1;
                let (reason_len, n2) = read_varint(frames, i)?;
                i += n2 + reason_len as usize;
            }
            other => {
                bail!(
                    "unexpected frame type 0x{:x} in Initial (only PADDING/PING/ACK/CRYPTO permitted)",
                    other
                );
            }
        }
    }
    Ok(())
}

/// Parse a TLS Handshake message (expected: ClientHello) and extract the SNI
/// hostname from the server_name extension.  Returns `Ok(None)` if no SNI
/// extension is present.
fn extract_sni_from_client_hello(tls: &[u8]) -> Result<Option<String>> {
    // TLS Handshake header: msg_type(1) + length(3) + body.
    if tls.len() < 4 {
        bail!("TLS handshake too short");
    }
    if tls[0] != 0x01 {
        bail!("expected ClientHello (msg_type=1), got {}", tls[0]);
    }
    let body_len = ((tls[1] as usize) << 16) | ((tls[2] as usize) << 8) | tls[3] as usize;
    if 4 + body_len > tls.len() {
        bail!(
            "ClientHello truncated: declared {} have {}",
            body_len,
            tls.len() - 4
        );
    }
    let body = &tls[4..4 + body_len];

    // ClientHello body:
    //   legacy_version(2) + random(32) + session_id<0..32> + cipher_suites<2..>
    //   + legacy_compression_methods<1..> + extensions<0..>
    let mut p = 0;
    if body.len() < 34 {
        bail!("ClientHello: too short for version+random");
    }
    p += 2 + 32;

    if p >= body.len() {
        bail!("ClientHello: missing session_id");
    }
    let sid_len = body[p] as usize;
    p += 1 + sid_len;

    if p + 2 > body.len() {
        bail!("ClientHello: missing cipher_suites");
    }
    let cs_len = ((body[p] as usize) << 8) | body[p + 1] as usize;
    p += 2 + cs_len;

    if p >= body.len() {
        bail!("ClientHello: missing compression_methods");
    }
    let cm_len = body[p] as usize;
    p += 1 + cm_len;

    if p + 2 > body.len() {
        // No extensions — no SNI.
        return Ok(None);
    }
    let ext_total = ((body[p] as usize) << 8) | body[p + 1] as usize;
    p += 2;
    if p + ext_total > body.len() {
        bail!("ClientHello: extensions length overruns");
    }
    let ext_end = p + ext_total;

    while p + 4 <= ext_end {
        let ext_type = ((body[p] as u16) << 8) | body[p + 1] as u16;
        let ext_len = ((body[p + 2] as usize) << 8) | body[p + 3] as usize;
        p += 4;
        if p + ext_len > ext_end {
            bail!("extension {} length overruns", ext_type);
        }
        if ext_type == 0x0000 {
            // server_name extension (RFC 6066 §3):
            //   ServerNameList<2..> { NameType(1) + HostName<2..> }
            let ext = &body[p..p + ext_len];
            if ext.len() < 2 {
                return Ok(None);
            }
            let list_len = ((ext[0] as usize) << 8) | ext[1] as usize;
            if 2 + list_len > ext.len() {
                bail!("SNI list length overruns");
            }
            let mut q = 2;
            while q + 3 <= 2 + list_len {
                let name_type = ext[q];
                let name_len = ((ext[q + 1] as usize) << 8) | ext[q + 2] as usize;
                q += 3;
                if q + name_len > 2 + list_len {
                    bail!("SNI name length overruns");
                }
                if name_type == 0 {
                    return Ok(Some(
                        std::str::from_utf8(&ext[q..q + name_len])
                            .map_err(|_| anyhow!("SNI hostname not valid UTF-8"))?
                            .to_string(),
                    ));
                }
                q += name_len;
            }
            return Ok(None);
        }
        p += ext_len;
    }
    Ok(None)
}

/// End-to-end: take the raw QUIC Initial bytes captured by BPF and return the
/// SNI hostname if one is present.  Returns `Ok(None)` if the ClientHello is
/// spread across multiple Initials, or has no SNI extension.
pub fn extract_sni(pkt: &[u8], dcid: &[u8], version: u32) -> Result<Option<String>> {
    let frames = decrypt_initial(pkt, dcid, version)?;
    let Some(tls) = reassemble_crypto_stream(&frames)? else {
        return Ok(None);
    };
    extract_sni_from_client_hello(&tls)
}

// ── Cross-packet CRYPTO reassembly ────────────────────────────────────────
//
// Modern Firefox/Chrome routinely fragment the ClientHello into many tiny,
// out-of-order CRYPTO frames spread across multiple Initial packets for
// anti-fingerprinting.  A single Initial usually does not carry a parseable
// ClientHello — we have to accumulate chunks across packets sharing a DCID
// and try again once enough is in hand.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Hard cap on contiguous CRYPTO-stream bytes per flow.  A real ClientHello
/// is at most a few kB; this guards against a malicious sender pinning
/// memory with arbitrary CRYPTO offsets.
const REASSEMBLY_MAX_BYTES: usize = 32 * 1024;
/// Per-flow idle timeout.  The handshake completes in a few RTTs; if we
/// haven't gotten enough to parse after this long, give up.
const REASSEMBLY_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
/// Hard cap on concurrent reassemblies to bound memory across pathological
/// flow counts.  Evicts the oldest entry first when full.
const REASSEMBLY_MAX_ENTRIES: usize = 4096;

/// Identifies a single client→server QUIC connection during its handshake.
/// 5-tuple alone is not sufficient — connection migration changes ports
/// mid-flow — but during Initial-packet exchange the DCID is the stable
/// anchor and the 5-tuple is also stable, so we key on both.
#[derive(Clone, Hash, PartialEq, Eq, Debug)]
pub struct ReassemblyKey {
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub protocol: u8,
    pub af: u8,
    pub dcid: Vec<u8>,
}

/// Outcome of feeding one Initial packet into a reassembly table.
#[derive(Debug)]
pub enum ReassemblyOutcome {
    /// Full ClientHello reassembled and a `server_name` extension was found.
    Sni(String),
    /// Full ClientHello reassembled, no SNI extension present.  Treat as
    /// "no rule match" — there's no name to compare against.
    NoSni,
    /// ClientHello header parsed; still waiting on bytes.
    Partial { have: usize, need: usize },
    /// Don't have enough contiguous prefix yet to even read the TLS handshake
    /// header (4 bytes from offset 0).
    NeedMore { contiguous: usize },
    /// First byte of the contiguous prefix is not 0x01 (ClientHello).  Either
    /// a malformed packet or — more likely — we never got the chunk at
    /// offset 0 and another stream type starts at offset 0.  Either way,
    /// no SNI will come out of this flow.
    NotClientHello,
}

struct ReassemblyState {
    chunks: Vec<(u64, Vec<u8>)>,
    total_bytes: usize,
    first_seen: Instant,
    last_seen: Instant,
}

/// Per-process table holding partial ClientHellos across multiple Initial
/// packets, keyed by `(5-tuple, DCID)`.  Not thread-safe — intended to be
/// owned by a single consumer task.
#[derive(Default)]
pub struct ReassemblyTable {
    entries: HashMap<ReassemblyKey, ReassemblyState>,
}

impl ReassemblyTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of active reassemblies (for stats/diagnostics).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Feed an Initial packet into the table.  Decrypts it, extracts CRYPTO
    /// chunks, appends them to the entry for `key`, and attempts to extract
    /// the SNI from the accumulated stream.
    ///
    /// On `Sni`/`NoSni`/`NotClientHello`/`Partial { need > MAX }` the entry
    /// is removed so subsequent packets don't keep allocating against it.
    pub fn add_packet(
        &mut self,
        key: ReassemblyKey,
        pkt: &[u8],
        version: u32,
    ) -> Result<ReassemblyOutcome> {
        let frames = decrypt_initial(pkt, &key.dcid, version)?;
        let new_chunks = collect_crypto_chunks(&frames)?;

        let now = Instant::now();
        self.evict_stale(now);

        if new_chunks.is_empty() {
            // Initial with no CRYPTO frame (PING-only retransmission probe);
            // touch the entry if it exists so the idle timeout doesn't fire,
            // but don't allocate one if we've never seen this flow.
            if let Some(state) = self.entries.get_mut(&key) {
                state.last_seen = now;
                let prefix = current_contiguous_prefix(&state.chunks);
                return Ok(classify_prefix(&prefix));
            }
            return Ok(ReassemblyOutcome::NeedMore { contiguous: 0 });
        }

        let added_bytes: usize = new_chunks.iter().map(|(_, d)| d.len()).sum();

        // Bound concurrent reassemblies; evict oldest when full.
        if !self.entries.contains_key(&key) && self.entries.len() >= REASSEMBLY_MAX_ENTRIES {
            if let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, s)| s.first_seen)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest_key);
            }
        }

        let _ = version; // currently unused; retained for future per-version diagnostics
        let state = self
            .entries
            .entry(key.clone())
            .or_insert_with(|| ReassemblyState {
                chunks: Vec::new(),
                total_bytes: 0,
                first_seen: now,
                last_seen: now,
            });
        state.last_seen = now;
        state.total_bytes = state.total_bytes.saturating_add(added_bytes);
        state.chunks.extend(new_chunks);

        if state.total_bytes > REASSEMBLY_MAX_BYTES {
            self.entries.remove(&key);
            bail!(
                "CRYPTO stream exceeded {} byte cap (likely malformed)",
                REASSEMBLY_MAX_BYTES
            );
        }

        let prefix = current_contiguous_prefix(&state.chunks);
        let outcome = classify_prefix(&prefix);

        match &outcome {
            ReassemblyOutcome::Sni(_)
            | ReassemblyOutcome::NoSni
            | ReassemblyOutcome::NotClientHello => {
                self.entries.remove(&key);
            }
            ReassemblyOutcome::Partial { .. } | ReassemblyOutcome::NeedMore { .. } => {}
        }
        Ok(outcome)
    }

    /// Drop entries idle for longer than `REASSEMBLY_IDLE_TIMEOUT`.
    pub fn evict_stale(&mut self, now: Instant) {
        self.entries
            .retain(|_, s| now.duration_since(s.last_seen) < REASSEMBLY_IDLE_TIMEOUT);
    }
}

/// Sort the collected chunks by offset and return the largest contiguous
/// prefix starting at offset 0.  Returns empty if there's no chunk at 0.
fn current_contiguous_prefix(chunks: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut sorted: Vec<(u64, &[u8])> = chunks.iter().map(|(o, d)| (*o, d.as_slice())).collect();
    sorted.sort_by_key(|c| c.0);
    if sorted.is_empty() || sorted[0].0 != 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut next_off: u64 = 0;
    for (off, data) in sorted {
        if off > next_off {
            break;
        }
        if off == next_off {
            out.extend_from_slice(data);
            next_off += data.len() as u64;
        } else {
            let skip = (next_off - off) as usize;
            if skip < data.len() {
                out.extend_from_slice(&data[skip..]);
                next_off += (data.len() - skip) as u64;
            }
        }
    }
    out
}

/// Inspect the contiguous prefix and decide whether we can extract an SNI
/// yet.  Distinguishes "need more bytes for the TLS handshake header",
/// "header parsed, need more bytes for the body", "complete" and "doesn't
/// look like a ClientHello at all".
fn classify_prefix(prefix: &[u8]) -> ReassemblyOutcome {
    if prefix.len() < 4 {
        return ReassemblyOutcome::NeedMore {
            contiguous: prefix.len(),
        };
    }
    if prefix[0] != 0x01 {
        return ReassemblyOutcome::NotClientHello;
    }
    let body_len = ((prefix[1] as usize) << 16) | ((prefix[2] as usize) << 8) | prefix[3] as usize;
    let need = 4 + body_len;
    if prefix.len() < need {
        return ReassemblyOutcome::Partial {
            have: prefix.len(),
            need,
        };
    }
    match extract_sni_from_client_hello(&prefix[..need]) {
        Ok(Some(sni)) => ReassemblyOutcome::Sni(sni),
        Ok(None) => ReassemblyOutcome::NoSni,
        Err(_) => ReassemblyOutcome::NotClientHello,
    }
}

// ── SNI rule matching ─────────────────────────────────────────────────────

use crate::traits::BpfOperations;
use crate::types::{
    Direction, L4Rule, RuleAction, SniRuleEntry, MAX_ACTIONS_PER_RULE, SNI_MATCH_EXACT,
    SNI_MATCH_SUFFIX,
};

/// The matched rule's id plus its ordered action list (truncated to
/// `num_actions`).  Callers apply the actions in priority order, stopping at
/// the first terminal verdict (DROP).
#[derive(Clone)]
pub struct MatchedSniRule {
    pub rule_id: u64,
    pub actions: Vec<RuleAction>,
}

/// Look up which SNI rule (if any) the extracted hostname matches and return
/// the rule's full action list.  Rules are scanned in rule-id order; the
/// first match wins.  Action sequencing (LOG before DROP, etc.) is the
/// caller's responsibility — mirroring how the TC SNI path in BPF walks
/// `actions[0..num_actions]`.
pub fn match_sni_rules(
    sni: &str,
    direction: Direction,
    bpf: &dyn BpfOperations,
) -> Result<Option<MatchedSniRule>> {
    let sni_lower = sni.to_ascii_lowercase();

    // Collect candidate UDP rules with sni_match_type != NONE from both v4 and v6 tries.
    let mut candidates: Vec<L4Rule> = Vec::new();
    for (_, _, r) in bpf.list_policy_rules_v4(direction)? {
        if r.sni_match_type != crate::types::SNI_MATCH_NONE && r.protocol == libc::IPPROTO_UDP as u8
        {
            candidates.push(r);
        }
    }
    for (_, _, r) in bpf.list_policy_rules_v6(direction)? {
        if r.sni_match_type != crate::types::SNI_MATCH_NONE && r.protocol == libc::IPPROTO_UDP as u8
        {
            candidates.push(r);
        }
    }
    candidates.sort_by_key(|r| r.rule_id);

    for r in candidates {
        let rule_id = r.rule_id;
        let entry = match bpf.lookup_sni_rule(rule_id, direction)? {
            Some(e) => e,
            None => continue,
        };
        if sni_entry_matches(&sni_lower, &entry) {
            let n = (r.num_actions as usize).min(MAX_ACTIONS_PER_RULE as usize);
            let actions = r.actions[..n].to_vec();
            return Ok(Some(MatchedSniRule { rule_id, actions }));
        }
    }
    Ok(None)
}

/// Test whether a (lowercase) hostname matches a single SNI rule entry.
fn sni_entry_matches(sni_lower: &str, entry: &SniRuleEntry) -> bool {
    let len = entry.sni_len as usize;
    if len == 0 || len > entry.sni_pattern.len() {
        return false;
    }
    let pat = match std::str::from_utf8(&entry.sni_pattern[..len]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    match entry.sni_match_type {
        SNI_MATCH_EXACT => sni_lower == pat,
        SNI_MATCH_SUFFIX => {
            // SUFFIX patterns are stored as ".example.com" (leading dot).
            // Match if the hostname ends with the pattern, OR equals the
            // pattern sans the leading dot.
            if let Some(bare) = pat.strip_prefix('.') {
                sni_lower == bare || sni_lower.ends_with(pat)
            } else {
                sni_lower.ends_with(pat)
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9001 §A.1 — known Initial keys derived from
    /// DCID = 0x8394c8f03e515708.
    #[test]
    fn rfc9001_a1_client_initial_keys() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let keys = derive_initial_keys(&dcid, QUIC_VERSION_V1).unwrap();

        // Expected values from RFC 9001 Appendix A.1.
        let expected_key: [u8; 16] = [
            0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1,
            0xa2, 0x2d,
        ];
        let expected_iv: [u8; 12] = [
            0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c,
        ];
        let expected_hp: [u8; 16] = [
            0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad,
            0xed, 0xd2,
        ];
        assert_eq!(keys.key, expected_key);
        assert_eq!(keys.iv, expected_iv);
        assert_eq!(keys.hp_key, expected_hp);
    }

    /// RFC 9001 §A.2 — decrypt the published example Initial packet and
    /// confirm the cleartext begins with a CRYPTO frame containing a TLS
    /// ClientHello (handshake type 0x01).
    #[test]
    fn rfc9001_a2_decrypts_example_initial() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let pkt = rfc9001_a2_packet();

        let frames = decrypt_initial(&pkt, &dcid, QUIC_VERSION_V1).unwrap();

        // Must start with a CRYPTO frame (0x06).
        assert_eq!(frames[0], 0x06, "first frame should be CRYPTO");

        let tls = reassemble_crypto_stream(&frames).unwrap().unwrap();
        assert_eq!(tls[0], 0x01, "expected ClientHello handshake byte");
    }

    /// Synthesize a minimal ClientHello with an SNI extension and confirm the
    /// extractor pulls out the hostname.  This exercises the TLS parser
    /// directly (no QUIC framing).
    #[test]
    fn extract_sni_from_minimal_client_hello() {
        let hostname = "example.com";
        let ch = build_client_hello_with_sni(hostname);
        let got = extract_sni_from_client_hello(&ch).unwrap();
        assert_eq!(got.as_deref(), Some(hostname));
    }

    #[test]
    fn extract_sni_returns_none_when_extension_absent() {
        let ch = build_client_hello_with_sni_opt(None);
        let got = extract_sni_from_client_hello(&ch).unwrap();
        assert_eq!(got, None);
    }

    #[test]
    fn sni_rule_matches_exact_and_suffix() {
        let mut exact = SniRuleEntry::default();
        let pat = b"example.com";
        exact.sni_match_type = SNI_MATCH_EXACT;
        exact.sni_len = pat.len() as u8;
        exact.sni_pattern[..pat.len()].copy_from_slice(pat);
        assert!(sni_entry_matches("example.com", &exact));
        assert!(!sni_entry_matches("api.example.com", &exact));
        assert!(!sni_entry_matches("evilexample.com", &exact));

        let mut suffix = SniRuleEntry::default();
        let pat = b".example.com";
        suffix.sni_match_type = SNI_MATCH_SUFFIX;
        suffix.sni_len = pat.len() as u8;
        suffix.sni_pattern[..pat.len()].copy_from_slice(pat);
        assert!(sni_entry_matches("api.example.com", &suffix));
        assert!(sni_entry_matches("example.com", &suffix));
        assert!(!sni_entry_matches("evilexample.com", &suffix));
        assert!(!sni_entry_matches("notexample.com", &suffix));
    }

    // ── helpers ──────────────────────────────────────────────────────────

    /// The complete client Initial packet from RFC 9001 §A.2.
    fn rfc9001_a2_packet() -> Vec<u8> {
        // Hex string straight from the RFC.
        const HEX: &str = concat!(
            "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11",
            "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399",
            "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c",
            "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212",
            "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5",
            "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208",
            "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec",
            "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3",
            "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db",
            "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c",
            "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8",
            "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556",
            "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74",
            "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a",
            "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00",
            "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632",
            "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964",
            "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd",
            "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff",
            "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198",
            "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd",
            "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73",
            "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f",
            "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e",
            "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade",
            "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047",
            "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2",
            "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4",
            "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0",
            "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e",
            "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0",
            "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400",
            "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab",
            "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9",
            "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4",
            "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064",
            "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241",
            "e221af44860018ab0856972e194cd934",
        );
        hex_to_bytes(HEX)
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(s.len() / 2);
        let b = s.as_bytes();
        let mut i = 0;
        while i + 1 < b.len() {
            let h = hex_nibble(b[i]);
            let l = hex_nibble(b[i + 1]);
            out.push((h << 4) | l);
            i += 2;
        }
        out
    }

    fn hex_nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        }
    }

    /// Build a minimal valid TLS ClientHello message (handshake-level, no
    /// record-layer framing — QUIC carries handshake messages directly).
    fn build_client_hello_with_sni(hostname: &str) -> Vec<u8> {
        build_client_hello_with_sni_opt(Some(hostname))
    }

    fn build_client_hello_with_sni_opt(hostname: Option<&str>) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id length
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites: TLS_AES_128_GCM_SHA256
        body.extend_from_slice(&[0x01, 0x00]); // compression_methods: null

        let mut exts = Vec::new();
        if let Some(h) = hostname {
            let hb = h.as_bytes();
            let mut sni = Vec::new();
            // ServerNameList length placeholder
            let list_len = 3 + hb.len();
            sni.extend_from_slice(&(list_len as u16).to_be_bytes());
            sni.push(0); // host_name
            sni.extend_from_slice(&(hb.len() as u16).to_be_bytes());
            sni.extend_from_slice(hb);
            exts.extend_from_slice(&[0x00, 0x00]); // extension_type = server_name
            exts.extend_from_slice(&(sni.len() as u16).to_be_bytes());
            exts.extend_from_slice(&sni);
        }
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut out = Vec::with_capacity(4 + body.len());
        out.push(0x01); // ClientHello
        out.push(((body.len() >> 16) & 0xff) as u8);
        out.push(((body.len() >> 8) & 0xff) as u8);
        out.push((body.len() & 0xff) as u8);
        out.extend_from_slice(&body);
        out
    }
}
