# Copyright (c) Dufferin Software

"""
Malformed packet resilience tests for policy-engine BPF programs.

Sends various malformed packets to verify the BPF XDP/TC programs handle
them gracefully without crashing. After each malformed packet batch, we
verify the BPF program is still functional by sending normal traffic.

Malformed scenarios tested:
- Truncated IP header (IHL < 5)
- IP total length set to zero
- TCP packet with truncated TCP header
- UDP packet too short for UDP header
- IP header IHL larger than actual packet
- Packet with invalid IP version
"""

import logging
import textwrap
import time

from netsim.testkit.nping_utils import send_ping

logger = logging.getLogger(__name__)


def _send_raw_packets(node, python_code: str, count: int = 5, timeout: int = 15):
    """
    Send raw crafted packets from a node using a python3 one-liner.

    The python_code should define a function `build_packet(target_ip)` that
    returns bytes. This helper wraps it in a script that sends `count` packets.

    Args:
        node: Node to send from
        python_code: Python code defining a build_packet(target_ip) function
        count: Number of packets to send
        timeout: SSH command timeout
    """
    # Dedent and escape for shell
    code = textwrap.dedent(python_code).strip()
    full_script = f"""
import socket
import struct
import time

{code}

target_ip = TARGET_IP
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
for i in range({count}):
    pkt = build_packet(target_ip)
    try:
        s.sendto(pkt, (target_ip, 0))
    except Exception as e:
        pass
    time.sleep(0.01)
s.close()
"""
    return full_script


def send_malformed_packets(
    node, target_ip: str, python_code: str, count: int = 5, timeout: int = 15
):
    """
    Send malformed packets from a node.

    Args:
        node: Node to send from
        target_ip: Target IP address string
        python_code: Python code that defines build_packet(target_ip)
        count: Number of packets to send
        timeout: SSH command timeout
    """
    script = _send_raw_packets(node, python_code, count)
    # Replace TARGET_IP placeholder
    script = script.replace("TARGET_IP", f'"{target_ip}"')

    # Use ssh_command_with_stdin for large payloads
    try:
        node.ssh_command_with_stdin(
            "sudo python3 -",
            stdin_data=script,
            timeout=timeout,
        )
    except Exception as e:
        # Sending malformed packets may raise errors, that's expected
        logger.debug(f"Malformed packet send raised (expected): {e}")


# ============================================================================
# Malformed packet builders
# ============================================================================

TRUNCATED_IP_HEADER = """
def build_packet(target_ip):
    '''IP header with IHL=2 (8 bytes, less than minimum 20).'''
    import socket
    dst = socket.inet_aton(target_ip)
    src = socket.inet_aton("10.0.0.1")
    # Version=4, IHL=2 (8 bytes, invalid - minimum is 5/20 bytes)
    ver_ihl = (4 << 4) | 2
    # Minimal fields, packet truncated
    header = struct.pack('!BBHHHBBH4s4s',
        ver_ihl,    # version + IHL
        0,          # DSCP/ECN
        28,         # total length (claimed)
        0,          # identification
        0,          # flags + fragment offset
        64,         # TTL
        6,          # protocol (TCP)
        0,          # checksum (kernel fills)
        src,        # source IP
        dst,        # dest IP
    )
    return header[:8]  # Truncate to match IHL=2
"""

ZERO_LENGTH_IP = """
def build_packet(target_ip):
    '''IP packet with total length = 0.'''
    import socket
    dst = socket.inet_aton(target_ip)
    src = socket.inet_aton("10.0.0.1")
    ver_ihl = (4 << 4) | 5
    header = struct.pack('!BBHHHBBH4s4s',
        ver_ihl,
        0,          # DSCP/ECN
        0,          # total length = 0 (invalid)
        0,          # identification
        0,          # flags + fragment offset
        64,         # TTL
        6,          # protocol (TCP)
        0,          # checksum
        src,
        dst,
    )
    return header
"""

TRUNCATED_TCP_HEADER = """
def build_packet(target_ip):
    '''IP says TCP but only 4 bytes of TCP header present.'''
    import socket
    dst = socket.inet_aton(target_ip)
    src = socket.inet_aton("10.0.0.1")
    ver_ihl = (4 << 4) | 5
    # IP header claiming 24 bytes total (20 IP + 4 TCP, but TCP needs 20)
    ip_header = struct.pack('!BBHHHBBH4s4s',
        ver_ihl,
        0,
        24,         # total length: 20 (IP) + 4 (truncated TCP)
        0,
        0,
        64,
        6,          # protocol = TCP
        0,
        src,
        dst,
    )
    # Only 4 bytes of "TCP" header (source port only, missing everything else)
    tcp_partial = struct.pack('!HH', 12345, 443)
    return ip_header + tcp_partial
"""

TRUNCATED_UDP_HEADER = """
def build_packet(target_ip):
    '''IP says UDP but only 2 bytes of UDP header present.'''
    import socket
    dst = socket.inet_aton(target_ip)
    src = socket.inet_aton("10.0.0.1")
    ver_ihl = (4 << 4) | 5
    ip_header = struct.pack('!BBHHHBBH4s4s',
        ver_ihl,
        0,
        22,         # total length: 20 (IP) + 2 (truncated UDP)
        0,
        0,
        64,
        17,         # protocol = UDP
        0,
        src,
        dst,
    )
    # Only 2 bytes of "UDP" header (source port, missing dest port + length + checksum)
    udp_partial = struct.pack('!H', 12345)
    return ip_header + udp_partial
"""

OVERSIZED_IHL = """
def build_packet(target_ip):
    '''IP header with IHL=15 (60 bytes) but packet is only 30 bytes total.'''
    import socket
    dst = socket.inet_aton(target_ip)
    src = socket.inet_aton("10.0.0.1")
    # IHL=15 means 60-byte header, but we only send 30 bytes
    ver_ihl = (4 << 4) | 15
    ip_header = struct.pack('!BBHHHBBH4s4s',
        ver_ihl,
        0,
        30,         # total length (less than IHL*4=60)
        0,
        0,
        64,
        6,          # protocol = TCP
        0,
        src,
        dst,
    )
    # Add 10 bytes of padding (total 30, but IHL claims 60)
    return ip_header + b'\\x00' * 10
"""

INVALID_IP_VERSION = """
def build_packet(target_ip):
    '''Packet with invalid IP version (version=7).'''
    import socket
    dst = socket.inet_aton(target_ip)
    src = socket.inet_aton("10.0.0.1")
    # Version=7 (invalid), IHL=5
    ver_ihl = (7 << 4) | 5
    header = struct.pack('!BBHHHBBH4s4s',
        ver_ihl,
        0,
        40,         # total length
        0,
        0,
        64,
        6,          # protocol = TCP
        0,
        src,
        dst,
    )
    # Add a fake TCP header
    tcp = struct.pack('!HHIIBBHHH',
        12345,      # source port
        80,         # dest port
        0,          # seq
        0,          # ack
        (5 << 4),   # data offset
        0x02,       # SYN flag
        1024,       # window
        0,          # checksum
        0,          # urgent pointer
    )
    return header + tcp
"""

TRUNCATED_ICMP = """
def build_packet(target_ip):
    '''IP says ICMP but only 2 bytes of ICMP header present.'''
    import socket
    dst = socket.inet_aton(target_ip)
    src = socket.inet_aton("10.0.0.1")
    ver_ihl = (4 << 4) | 5
    ip_header = struct.pack('!BBHHHBBH4s4s',
        ver_ihl,
        0,
        22,         # total length: 20 (IP) + 2 (truncated ICMP)
        0,
        0,
        64,
        1,          # protocol = ICMP
        0,
        src,
        dst,
    )
    # Only 2 bytes of ICMP (type + code, missing checksum + rest)
    icmp_partial = struct.pack('!BB', 8, 0)  # Echo request type/code
    return ip_header + icmp_partial
"""


class TestMalformedPacketResilience:
    """Tests that BPF programs handle malformed packets without crashing."""

    def _verify_bpf_still_functional(
        self, nodes, server_interface, client_ip_v4, label
    ):
        """Send normal ICMP traffic and verify BPF is still processing packets."""
        server = nodes["server"]
        result = send_ping(
            server,
            client_ip_v4,
            count=3,
            interface=server_interface.if_name,
        )
        assert result.success, (
            f"BPF program not functional after {label}: "
            f"ping failed with {result.error_message}"
        )
        logger.info(f"BPF still functional after {label}: ping succeeded")

    def test_truncated_ip_header(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        server_interface,
        server_ip_v4,
        client_ip_v4,
        nmap_installed_server,
    ):
        """BPF should handle packets with truncated IP header (IHL < 5)."""
        client = nodes["client"]

        send_malformed_packets(client, str(server_ip_v4), TRUNCATED_IP_HEADER, count=10)

        time.sleep(0.5)
        self._verify_bpf_still_functional(
            nodes, server_interface, client_ip_v4, "truncated IP header"
        )

    def test_zero_length_ip(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        server_interface,
        server_ip_v4,
        client_ip_v4,
        nmap_installed_server,
    ):
        """BPF should handle IP packets with total length = 0."""
        client = nodes["client"]

        send_malformed_packets(client, str(server_ip_v4), ZERO_LENGTH_IP, count=10)

        time.sleep(0.5)
        self._verify_bpf_still_functional(
            nodes, server_interface, client_ip_v4, "zero-length IP"
        )

    def test_truncated_tcp_header(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        server_interface,
        server_ip_v4,
        client_ip_v4,
        nmap_installed_server,
    ):
        """BPF should handle TCP packets with truncated TCP header."""
        client = nodes["client"]

        send_malformed_packets(
            client, str(server_ip_v4), TRUNCATED_TCP_HEADER, count=10
        )

        time.sleep(0.5)
        self._verify_bpf_still_functional(
            nodes, server_interface, client_ip_v4, "truncated TCP header"
        )

    def test_truncated_udp_header(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        server_interface,
        server_ip_v4,
        client_ip_v4,
        nmap_installed_server,
    ):
        """BPF should handle UDP packets with truncated UDP header."""
        client = nodes["client"]

        send_malformed_packets(
            client, str(server_ip_v4), TRUNCATED_UDP_HEADER, count=10
        )

        time.sleep(0.5)
        self._verify_bpf_still_functional(
            nodes, server_interface, client_ip_v4, "truncated UDP header"
        )

    def test_oversized_ihl(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        server_interface,
        server_ip_v4,
        client_ip_v4,
        nmap_installed_server,
    ):
        """BPF should handle IP packets where IHL > actual packet size."""
        client = nodes["client"]

        send_malformed_packets(client, str(server_ip_v4), OVERSIZED_IHL, count=10)

        time.sleep(0.5)
        self._verify_bpf_still_functional(
            nodes, server_interface, client_ip_v4, "oversized IHL"
        )

    def test_invalid_ip_version(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        server_interface,
        server_ip_v4,
        client_ip_v4,
        nmap_installed_server,
    ):
        """BPF should handle packets with invalid IP version field."""
        client = nodes["client"]

        send_malformed_packets(client, str(server_ip_v4), INVALID_IP_VERSION, count=10)

        time.sleep(0.5)
        self._verify_bpf_still_functional(
            nodes, server_interface, client_ip_v4, "invalid IP version"
        )

    def test_truncated_icmp(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        server_interface,
        server_ip_v4,
        client_ip_v4,
        nmap_installed_server,
    ):
        """BPF should handle ICMP packets with truncated ICMP header."""
        client = nodes["client"]

        send_malformed_packets(client, str(server_ip_v4), TRUNCATED_ICMP, count=10)

        time.sleep(0.5)
        self._verify_bpf_still_functional(
            nodes, server_interface, client_ip_v4, "truncated ICMP"
        )

    def test_parse_errors_increment(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        server_interface,
        server_ip_v4,
        client_ip_v4,
        nmap_installed_server,
    ):
        """Malformed packets should increment parse_errors stat."""
        client = nodes["client"]

        # Get baseline parse errors
        initial_stats = policy_client.get_stats(
            server_interface.if_name, direction="ingress"
        )
        initial_parse_errors = initial_stats.global_stats.parse_errors

        # Send a batch of malformed packets (truncated TCP is most likely to
        # be classified as a parse error since it has a valid IP header but
        # invalid L4)
        send_malformed_packets(
            client, str(server_ip_v4), TRUNCATED_TCP_HEADER, count=20
        )

        time.sleep(0.5)

        # Check if parse errors increased
        final_stats = policy_client.get_stats(
            server_interface.if_name, direction="ingress"
        )
        final_parse_errors = final_stats.global_stats.parse_errors
        parse_error_delta = final_parse_errors - initial_parse_errors

        logger.info(
            f"Parse errors: initial={initial_parse_errors}, "
            f"final={final_parse_errors}, delta={parse_error_delta}"
        )

        # We expect at least some parse errors from the malformed packets.
        # The exact count depends on how many packets the kernel actually
        # delivers to XDP vs drops in the network stack, so we check > 0.
        assert parse_error_delta > 0, (
            f"Expected parse_errors to increase after malformed packets, "
            f"got delta={parse_error_delta}"
        )
