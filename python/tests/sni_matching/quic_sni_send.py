#!/usr/bin/env python3
# Copyright (c) Dufferin Software

"""
Fire a single real QUIC v1 or v2 Initial packet with a chosen SNI.

Deployed onto the netsim originator node so the SNI matching e2e tests
can exercise the policy-engine BPF tail-call → userspace decryption →
ClientHello SNI extraction → flow_verdict_cache path with real
on-the-wire QUIC traffic.

Usage:
    quic_sni_send.py <server_ip> <server_port> <sni> [--version v1|v2]

The script uses aioquic to construct a valid client Initial packet (long
header, chosen version, DCID, encrypted ClientHello with the supplied
server_name extension) and sends it via a UDP socket.  We do not wait
for a server response — the policy-engine inspector only needs the
Initial to cross the inspected interface.

Exits 0 on send success, 1 on any failure.
"""

import argparse
import socket
import ssl
import sys
import time

try:
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
except ImportError as e:
    print(f"missing aioquic: {e}", file=sys.stderr)
    sys.exit(1)


# QUIC version constants — aioquic exposes these as ints; pin them locally so
# the script is robust to internal symbol moves.
_QUIC_V1 = 0x00000001
_QUIC_V2 = 0x6B3343CF


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("server_ip")
    parser.add_argument("server_port", type=int)
    parser.add_argument("sni")
    parser.add_argument(
        "--version",
        choices=("v1", "v2"),
        default="v1",
        help="QUIC long-header version to advertise.",
    )
    parser.add_argument(
        "--src-port",
        type=int,
        default=0,
        help="Bind the source UDP port (0 = ephemeral). Used to drive distinct "
        "5-tuples for verdict-cache tests.",
    )
    args = parser.parse_args()

    config = QuicConfiguration(
        is_client=True,
        server_name=args.sni,
        verify_mode=ssl.CERT_NONE,
        alpn_protocols=["h3"],
    )
    # aioquic defaults to v1.  Override for v2 by setting the negotiation list
    # to the v2 codepoint only.
    if args.version == "v2":
        config.supported_versions = [_QUIC_V2]
        config.original_version = _QUIC_V2

    conn = QuicConnection(configuration=config)

    now = time.time()
    conn.connect((args.server_ip, args.server_port), now=now)

    datagrams = conn.datagrams_to_send(now=now)
    if not datagrams:
        print("aioquic produced no datagrams to send", file=sys.stderr)
        return 1

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if args.src_port:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", args.src_port))
    try:
        sent = 0
        for data, addr in datagrams:
            sock.sendto(data, addr)
            sent += len(data)
        print(
            f"sent {sent} bytes to {args.server_ip}:{args.server_port} "
            f"sni={args.sni} version={args.version}"
        )
    finally:
        sock.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
