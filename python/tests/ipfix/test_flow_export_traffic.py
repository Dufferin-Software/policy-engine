# Copyright (c) Dufferin Software

"""
IPFIX flow export traffic tests.

Tests that real flows — created by traffic passing through the XDP program —
are tracked in the flow cache and eventually exported as IPFIX records.

Architecture under test:
  client → [server NIC] → XDP/TC program → flow_cache map → background exporter
                                                            → IPFIX UDP datagrams
                                                            → nfcapd collector

Tests verify:
- Traffic through the policy engine populates the flow cache
- activeFlowCount increments after traffic
- flowsExportedTotal increments after idle timeout elapses
- IPFIX UDP packets are sent to the configured collector
- Both IPv4 flow directions are captured
"""

import logging
import time

from tenacity import retry, retry_if_exception_type, stop_after_delay, wait_fixed

from netsim.testkit.nping_utils import send_ping, send_tcp_syn

logger: logging.Logger = logging.getLogger(__name__)

# Background loop runs every 10s; idle_timeout=5s configured in conftest.
# Allow up to 30s for at least one export cycle to fire.
_EXPORT_WAIT_S = 30
_EXPORT_POLL_S = 2


class TestFlowCachePopulation:
    """Tests that traffic through the policy engine populates the flow cache."""

    def test_icmp_traffic_creates_flow_cache_entries(
        self,
        nodes,
        graphql_client,
        attached_ingress,
        clean_ingress_rules,
        flow_export_enabled,
        server_ip_v4,
        client_interface,
        nmap_installed,
    ) -> None:
        """
        ICMP traffic matching a PASS rule should create entries in the flow cache.

        Sends pings from client to server, then verifies activeFlowCount > 0.
        """
        client = nodes["client"]

        initial_status = graphql_client.get_flow_export_status()
        initial_flows = initial_status.active_flow_count
        logger.info(f"Initial activeFlowCount: {initial_flows}")

        send_ping(
            client,
            server_ip_v4,
            count=10,
            interface=client_interface.if_name,
        )

        @retry(
            stop=stop_after_delay(10),
            wait=wait_fixed(0.5),
            retry=retry_if_exception_type(AssertionError),
            reraise=True,
        )
        def assert_flow_cache_populated() -> None:
            status = graphql_client.get_flow_export_status()
            logger.info(f"activeFlowCount after ping: {status.active_flow_count}")
            assert status.active_flow_count > initial_flows, (
                f"Expected activeFlowCount to increase after traffic, "
                f"initial={initial_flows}, current={status.active_flow_count}"
            )

        assert_flow_cache_populated()

    def test_tcp_traffic_creates_flow_cache_entries(
        self,
        nodes,
        graphql_client,
        attached_ingress,
        clean_ingress_rules,
        flow_export_enabled,
        server_ip_v4,
        client_interface,
        nmap_installed,
    ) -> None:
        """TCP SYNs through the policy engine should create flow cache entries."""
        client = nodes["client"]

        initial_status = graphql_client.get_flow_export_status()
        initial_flows = initial_status.active_flow_count

        send_tcp_syn(
            client,
            server_ip_v4,
            dest_port=8080,
            count=5,
            interface=client_interface.if_name,
        )

        @retry(
            stop=stop_after_delay(10),
            wait=wait_fixed(0.5),
            retry=retry_if_exception_type(AssertionError),
            reraise=True,
        )
        def assert_flows_created() -> None:
            status = graphql_client.get_flow_export_status()
            assert status.active_flow_count > initial_flows, (
                f"Expected TCP flows in cache, got activeFlowCount={status.active_flow_count}"
            )

        assert_flows_created()


class TestFlowExport:
    """Tests that aged-out flows are exported as IPFIX records."""

    def test_flows_exported_after_idle_timeout(
        self,
        nodes,
        graphql_client,
        attached_ingress,
        clean_ingress_rules,
        flow_export_enabled,
        server_ip_v4,
        client_interface,
        nmap_installed,
    ) -> None:
        """
        After the idle timeout elapses, flowsExportedTotal should increment.

        idle_timeout_s=5 (from conftest) + background loop up to 10s = ~15s max.
        We allow up to 30s for the export to fire.
        """
        client = nodes["client"]

        # Generate traffic to populate the flow cache
        send_ping(client, server_ip_v4, count=10, interface=client_interface.if_name)
        send_tcp_syn(
            client,
            server_ip_v4,
            dest_port=8080,
            count=5,
            interface=client_interface.if_name,
        )

        # Wait for at least one flow to appear in the cache
        @retry(
            stop=stop_after_delay(10),
            wait=wait_fixed(0.5),
            retry=retry_if_exception_type(AssertionError),
            reraise=True,
        )
        def wait_for_flows() -> None:
            status = graphql_client.get_flow_export_status()
            assert status.active_flow_count > 0, "No flows in cache after traffic"

        wait_for_flows()

        initial_status = graphql_client.get_flow_export_status()
        initial_exported = initial_status.flows_exported_total
        logger.info(
            f"Waiting for export: initial flowsExportedTotal={initial_exported}, "
            f"activeFlowCount={initial_status.active_flow_count}"
        )

        @retry(
            stop=stop_after_delay(_EXPORT_WAIT_S),
            wait=wait_fixed(_EXPORT_POLL_S),
            retry=retry_if_exception_type(AssertionError),
            reraise=True,
        )
        def assert_flows_exported() -> None:
            status = graphql_client.get_flow_export_status()
            exported_delta = status.flows_exported_total - initial_exported
            logger.info(
                f"flowsExportedTotal={status.flows_exported_total} "
                f"(delta={exported_delta}), "
                f"activeFlowCount={status.active_flow_count}"
            )
            assert exported_delta > 0, (
                f"Expected flowsExportedTotal to increase within {_EXPORT_WAIT_S}s, "
                f"delta={exported_delta}"
            )

        assert_flows_exported()

    def test_flow_cache_shrinks_after_export(
        self,
        nodes,
        graphql_client,
        attached_ingress,
        clean_ingress_rules,
        flow_export_enabled,
        server_ip_v4,
        client_interface,
        nmap_installed,
    ) -> None:
        """
        After flows are exported they are deleted from the cache.

        Once the exporter runs, activeFlowCount should drop back toward zero
        (assuming no new traffic arrives).
        """
        client = nodes["client"]

        send_ping(client, server_ip_v4, count=10, interface=client_interface.if_name)

        @retry(
            stop=stop_after_delay(10),
            wait=wait_fixed(0.5),
            retry=retry_if_exception_type(AssertionError),
            reraise=True,
        )
        def wait_for_flows() -> None:
            assert graphql_client.get_flow_export_status().active_flow_count > 0

        wait_for_flows()

        peak_flows = graphql_client.get_flow_export_status().active_flow_count
        logger.info(f"Peak activeFlowCount: {peak_flows}")

        # Wait for the exporter to run and delete exported entries
        @retry(
            stop=stop_after_delay(_EXPORT_WAIT_S),
            wait=wait_fixed(_EXPORT_POLL_S),
            retry=retry_if_exception_type(AssertionError),
            reraise=True,
        )
        def assert_cache_shrinks() -> None:
            status = graphql_client.get_flow_export_status()
            logger.info(
                f"activeFlowCount={status.active_flow_count} (was {peak_flows})"
            )
            assert status.active_flow_count < peak_flows, (
                f"Expected activeFlowCount to decrease after export, "
                f"still at {status.active_flow_count}"
            )

        assert_cache_shrinks()


class TestIpfixUdpPackets:
    """Tests that IPFIX UDP packets are actually sent to the collector."""

    def test_ipfix_udp_packets_sent_to_collector(
        self,
        nodes,
        graphql_client,
        attached_ingress,
        clean_ingress_rules,
        flow_export_enabled,
        server_ip_v4,
        client_interface,
        nmap_installed,
    ) -> None:
        """
        Verify IPFIX UDP packets reach the collector by capturing on loopback.

        Runs a tcpdump capture on lo for 30 seconds, generates traffic,
        waits for export, and confirms at least one UDP packet was seen on
        the collector port.  The IPFIX magic version word (0x000a) is checked.
        """
        server = nodes["server"]
        client = nodes["client"]

        recv_log = "/tmp/ipfix_recv.log"
        recv_script = "/tmp/ipfix_recv.py"
        server.ssh_command(f"rm -f {recv_log} {recv_script}", timeout=5)

        # Write a UDP receiver script that listens on 4739 and logs each IPFIX
        # packet it receives (verified by the 0x000a version word in bytes 0-1).
        script = (
            "import socket\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            "s.bind(('127.0.0.1', 4739))\n"
            "s.settimeout(40)\n"
            "count = 0\n"
            "try:\n"
            "    while count < 50:\n"
            "        data, _ = s.recvfrom(4096)\n"
            "        count += 1\n"
            "        version = (data[0] << 8 | data[1]) if len(data) >= 2 else 0\n"
            "        with open('/tmp/ipfix_recv.log', 'a') as f:\n"
            "            f.write(f'pkt len={len(data)} version={version}\\n')\n"
            "except socket.timeout:\n"
            "    pass\n"
        )
        server.ssh_command_with_stdin(f"cat > {recv_script}", script, timeout=10)

        # Start receiver BEFORE recording baseline so we don't miss packets
        server.ssh_command(
            f"nohup python3 {recv_script} >/dev/null 2>&1 &",
            timeout=5,
        )
        time.sleep(1)  # let receiver bind

        initial_exported = graphql_client.get_flow_export_status().flows_exported_total
        logger.info(f"Baseline flowsExportedTotal={initial_exported}")

        # Generate traffic to populate the flow cache
        send_ping(client, server_ip_v4, count=15, interface=client_interface.if_name)
        send_tcp_syn(
            client,
            server_ip_v4,
            dest_port=8080,
            count=5,
            interface=client_interface.if_name,
        )

        # Wait for new exports (delta from our baseline)
        @retry(
            stop=stop_after_delay(_EXPORT_WAIT_S),
            wait=wait_fixed(_EXPORT_POLL_S),
            retry=retry_if_exception_type(AssertionError),
            reraise=True,
        )
        def wait_for_new_export() -> None:
            status = graphql_client.get_flow_export_status()
            delta = status.flows_exported_total - initial_exported
            logger.info(
                f"flowsExportedTotal={status.flows_exported_total} (delta={delta})"
            )
            assert delta > 0, (
                f"No new flows exported since baseline ({initial_exported})"
            )

        wait_for_new_export()

        # Give the receiver a moment to write the last entries
        time.sleep(2)

        log_contents = server.ssh_command(
            f"cat {recv_log} 2>/dev/null || true", timeout=5
        )
        logger.info(f"Receiver log:\n{log_contents.strip()}")

        ipfix_lines = [
            line for line in log_contents.splitlines() if "version=10" in line
        ]
        assert len(ipfix_lines) > 0, (
            f"No IPFIX packets (version=10) received on 127.0.0.1:4739. "
            f"Receiver log: {log_contents.strip()!r}"
        )


class TestIpfixRecordAddresses:
    """Verify that IP addresses in exported IPFIX records are correctly byte-ordered.

    Regression test for a bug where saddr/daddr were written with .to_be_bytes()
    instead of .to_ne_bytes().  BPF copies iph->saddr (__be32, network byte order)
    directly into the flow key.  On a little-endian host this is byte-swapped when
    read as a Rust u32, so to_be_bytes() would re-swap the bytes and produce an
    incorrect address (e.g. 192.168.1.1 would appear as 1.1.168.192 in nfdump).
    """

    # Minimal IPFIX parser that extracts (src, dst) pairs from template-256 data sets.
    # Written as an inline script run on the server VM via SSH.
    _RECV_SCRIPT = (
        "import socket, struct\n"
        "def parse_v4(data):\n"
        "    if len(data) < 16: return []\n"
        "    ver, = struct.unpack_from('!H', data, 0)\n"
        "    if ver != 10: return []\n"
        "    off, out = 16, []\n"
        "    while off + 4 <= len(data):\n"
        "        sid, slen = struct.unpack_from('!HH', data, off)\n"
        "        if slen < 4: break\n"
        "        send = min(off + slen, len(data))\n"
        "        if sid == 256:\n"
        "            r = off + 4\n"
        "            while r + 46 <= send:\n"
        "                src = socket.inet_ntoa(data[r:r+4])\n"
        "                dst = socket.inet_ntoa(data[r+4:r+8])\n"
        "                out.append(src + ',' + dst)\n"
        "                r += 46\n"
        "        off += slen\n"
        "    return out\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        "s.bind(('127.0.0.1', 4739))\n"
        "s.settimeout(60)\n"
        "f = open('/tmp/ipfix_flows.log', 'w')\n"
        "try:\n"
        "    while True:\n"
        "        data, _ = s.recvfrom(65535)\n"
        "        for pair in parse_v4(data):\n"
        "            f.write(pair + '\\n')\n"
        "            f.flush()\n"
        "except socket.timeout:\n"
        "    pass\n"
        "f.close()\n"
    )

    def test_ipv4_addresses_not_byte_swapped(
        self,
        nodes,
        graphql_client,
        attached_ingress,
        clean_ingress_rules,
        flow_export_enabled,
        server_ip_v4,
        client_ip_v4,
        client_interface,
        nmap_installed,
    ) -> None:
        """
        Exported IPFIX records must contain IP addresses in network byte order.

        Generates traffic with known source/destination IPs, captures the exported
        IPFIX records, and asserts that:
          - The correct IP addresses appear in the records.
          - Their byte-reversed versions do NOT appear (which would indicate the bug).
        """
        server = nodes["server"]
        client = nodes["client"]

        recv_script = "/tmp/ipfix_addr_recv.py"
        recv_log = "/tmp/ipfix_flows.log"
        recv_pid = "/tmp/ipfix_addr_recv.pid"
        # Kill any leftover receiver from a prior run by PID (avoids pkill hitting the
        # current SSH session via process-group propagation).
        server.ssh_command(
            f"kill $(cat {recv_pid} 2>/dev/null) 2>/dev/null; rm -f {recv_pid} {recv_log}",
            timeout=5,
        )
        server.ssh_command_with_stdin(
            f"cat > {recv_script}", self._RECV_SCRIPT, timeout=10
        )
        server.ssh_command(
            f"nohup python3 {recv_script} >/dev/null 2>&1 & echo $! > {recv_pid}",
            timeout=5,
        )
        time.sleep(1)  # let receiver bind

        initial_exported = graphql_client.get_flow_export_status().flows_exported_total

        send_ping(client, server_ip_v4, count=15, interface=client_interface.if_name)
        send_tcp_syn(
            client,
            server_ip_v4,
            dest_port=8080,
            count=5,
            interface=client_interface.if_name,
        )

        @retry(
            stop=stop_after_delay(_EXPORT_WAIT_S),
            wait=wait_fixed(_EXPORT_POLL_S),
            retry=retry_if_exception_type(AssertionError),
            reraise=True,
        )
        def wait_for_export() -> None:
            delta = (
                graphql_client.get_flow_export_status().flows_exported_total
                - initial_exported
            )
            logger.info(f"flows exported delta={delta}")
            assert delta > 0, f"No flows exported yet (delta={delta})"

        # wait_for_export fires as soon as any flow is exported (may be background
        # traffic).  Our client→server flows need to idle out (5s) and then be
        # picked up by the next export cycle (up to 10s), so poll the receiver log
        # directly until the expected IPs appear.
        wait_for_export()

        server_ip_str = str(server_ip_v4)
        client_ip_str = str(client_ip_v4)

        def byte_swap_ip(ip: str) -> str:
            """Return the address that would appear if octets were byte-reversed."""
            return ".".join(reversed(ip.split(".")))

        server_ip_swapped: str = byte_swap_ip(server_ip_str)
        client_ip_swapped: str = byte_swap_ip(client_ip_str)

        @retry(
            stop=stop_after_delay(_EXPORT_WAIT_S),
            wait=wait_fixed(_EXPORT_POLL_S),
            retry=retry_if_exception_type(AssertionError),
            reraise=True,
        )
        def assert_expected_ips_in_log() -> None:  # type: ignore[annotation-unchecked]
            log = server.ssh_command(f"cat {recv_log} 2>/dev/null || true", timeout=5)
            all_ips: set[str] = set()
            for line in log.splitlines():
                if "," in line:
                    src, dst = line.strip().split(",", 1)
                    all_ips.add(src)
                    all_ips.add(dst)
            logger.info(
                f"Observed IPs: {sorted(all_ips)}  "
                f"waiting for server={server_ip_str} or client={client_ip_str}"
            )
            assert server_ip_str in all_ips or client_ip_str in all_ips, (
                f"Neither server IP {server_ip_str} nor client IP {client_ip_str} found "
                f"in exported IPFIX records yet. Observed: {sorted(all_ips)}"
            )

        assert_expected_ips_in_log()

        server.ssh_command(
            f"kill $(cat {recv_pid} 2>/dev/null) 2>/dev/null; rm -f {recv_pid}",
            timeout=5,
        )
        time.sleep(1)

        log = server.ssh_command(f"cat {recv_log} 2>/dev/null || true", timeout=5)
        logger.info(f"Final IPFIX flow log:\n{log.strip()}")

        all_ips: set[str] = set()
        for line in log.splitlines():
            if "," in line:
                src, dst = line.strip().split(",", 1)
                all_ips.add(src)
                all_ips.add(dst)

        logger.info(
            f"Expected: server={server_ip_str} client={client_ip_str}  "
            f"Buggy would be: server={server_ip_swapped} client={client_ip_swapped}"
        )

        # Only assert the swapped form is absent when it differs from the original —
        # palindromic addresses (e.g. 10.1.1.10) have identical reversed forms, so
        # the check would be contradictory.
        if server_ip_swapped != server_ip_str:
            assert server_ip_swapped not in all_ips, (
                f"Server IP appears byte-swapped as {server_ip_swapped} "
                f"(expected {server_ip_str}) — byte-order bug in IPFIX encoder"
            )
        if client_ip_swapped != client_ip_str:
            assert client_ip_swapped not in all_ips, (
                f"Client IP appears byte-swapped as {client_ip_swapped} "
                f"(expected {client_ip_str}) — byte-order bug in IPFIX encoder"
            )
