#!/usr/bin/env python3
# Copyright (c) Dufferin Software

"""
Send a single TLS ClientHello with a chosen SNI over a real TCP connection.

Deployed onto the netsim client node so the SNI matching e2e tests can
exercise the policy-engine in-kernel TC/XDP ClientHello parser
(`match_sni_in_packet`) with realistic on-the-wire bytes.

Construction uses scapy's TLS layer rather than openssl s_client so we
control every byte of the handshake — version, extension order, padding
size — and have no certificate-validation or session-resumption noise.

The kernel handles the TCP three-way handshake; we just push one TLS
record containing the ClientHello and close the connection.  The server
side is unmanaged (typically nothing listens on 443), so RST/timeout on
close is expected and ignored.

Usage:
    tls_sni_send.py <server_ip> <server_port> <sni> [--pad-to N]

`--pad-to N` adds a TLS Padding extension so the assembled record reaches
at least N bytes.  Used to drive ClientHellos past `SNI_PULL_MAX` so the
test exercises `bpf_skb_pull_data` on the TC egress path.

Exits 0 on send success, 1 on any failure.
"""

import argparse
import socket
import sys

try:
    # scapy's TLS layer must be imported under its full path; the top-level
    # scapy package does not autoload it.
    from scapy.layers.tls.record import TLS
    from scapy.layers.tls.handshake import TLSClientHello
    from scapy.layers.tls.extensions import (
        TLS_Ext_ServerName,
        ServerName,
        TLS_Ext_SupportedVersion_CH,
        TLS_Ext_SupportedGroups,
        TLS_Ext_SignatureAlgorithms,
    )
except ImportError as e:
    print(f"missing scapy.layers.tls: {e}", file=sys.stderr)
    sys.exit(1)


# Standard TLS 1.3 cipher suites — value choice is irrelevant to the SNI
# parser but real clients always include them, and keeping a non-empty
# cipher list avoids tripping any future stricter validation in the parser.
_TLS13_CIPHERS = [0x1301, 0x1302, 0x1303]

# TLS 1.3 / 1.2 supported_versions.  Putting 1.3 first matches modern client
# behaviour.
_SUPPORTED_VERSIONS = [0x0304, 0x0303]

# A minimal supported_groups list (x25519, secp256r1).
_SUPPORTED_GROUPS = [0x001D, 0x0017]

# ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256.
_SIG_ALGS = [0x0403, 0x0804, 0x0401]


def _build_clienthello(sni: str, pad_to: int) -> bytes:
    """Assemble a TLS ClientHello record carrying `sni`, optionally padded."""
    extensions = [
        TLS_Ext_ServerName(servernames=[ServerName(servername=sni.encode())]),
        TLS_Ext_SupportedVersion_CH(versions=_SUPPORTED_VERSIONS),
        TLS_Ext_SupportedGroups(groups=_SUPPORTED_GROUPS),
        TLS_Ext_SignatureAlgorithms(sig_algs=_SIG_ALGS),
    ]

    ch = TLSClientHello(ciphers=_TLS13_CIPHERS, ext=extensions)
    record = TLS(msg=[ch])
    wire = bytes(record)

    if pad_to > len(wire):
        # Rebuild with a TLS_Ext_Padding sized so the total record reaches
        # `pad_to`.  The padding extension adds 4 bytes of TLV overhead plus
        # the payload itself, so subtract that from the gap.
        from scapy.layers.tls.extensions import TLS_Ext_Padding

        gap = pad_to - len(wire)
        pad_payload = max(gap - 4, 0)
        extensions.append(TLS_Ext_Padding(padding=b"\x00" * pad_payload))
        ch = TLSClientHello(ciphers=_TLS13_CIPHERS, ext=extensions)
        record = TLS(msg=[ch])
        wire = bytes(record)

    return wire


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("server_ip")
    parser.add_argument("server_port", type=int)
    parser.add_argument("sni")
    parser.add_argument(
        "--pad-to",
        type=int,
        default=0,
        help="Pad the ClientHello so the wire record is at least N bytes.",
    )
    parser.add_argument(
        "--src-port",
        type=int,
        default=0,
        help="Bind the source port (0 = ephemeral). Used to drive distinct "
        "5-tuples for verdict-cache tests.",
    )
    args = parser.parse_args()

    try:
        wire = _build_clienthello(args.sni, args.pad_to)
    except Exception as e:
        print(f"clienthello build failed: {e}", file=sys.stderr)
        return 1

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        if args.src_port:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", args.src_port))
        try:
            sock.connect((args.server_ip, args.server_port))
        except (ConnectionRefusedError, OSError) as e:
            # No listener is the common case — what we care about is that the
            # SYN/SYN-ACK round-trip happened and the TC/XDP parser saw the
            # ClientHello.  ECONNREFUSED means no SYN-ACK, so the CH never
            # left the kernel; report that distinctly.
            print(f"tcp connect failed: {e}", file=sys.stderr)
            return 1

        sock.sendall(wire)
        print(
            f"sent {len(wire)} bytes to {args.server_ip}:{args.server_port} sni={args.sni}"
        )
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
