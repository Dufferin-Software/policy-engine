# Copyright (c) Peter Morrow

"""
Two node policy engine sanity tests.

Tests basic features:
- XDP program attach/detach
- Adding/removing rules
- Traffic matching with different protocols (TCP/UDP/ICMP)
- Packet counting and statistics
- Various prefix lengths
- IPv4 and IPv6 support
- Negative tests for error handling

Tests are parameterized to run against both:
- CLI client (policy-client binary)
- GraphQL API (direct HTTP requests)
"""

import logging
import time
from typing import Union

import netaddr
import pytest

from netsim.testkit.base import BaseTopologyTests
from netsim.testkit.systemd_utils import get_service_status
from policy_engine_client.engine.cli.client import (
    PolicyClient,
    AddRuleOptions,
    IngressMode,
    PolicyAction,
    Protocol,
)
from policy_engine_client.engine.graphql.client import GraphQLPolicyClient
from netsim.testkit.nping_utils import (
    send_icmp_with_type,
    send_ping,
    send_tcp_syn,
    send_udp_packets,
)

logger = logging.getLogger(__name__)

# Type alias for either client type
AnyPolicyClient = Union[PolicyClient, GraphQLPolicyClient]


# ============================================================================
# Module-level fixtures
# ============================================================================


@pytest.fixture(scope="module", params=["cli", "graphql"], ids=["cli", "graphql"])
def client_type(request):
    """Parameterized fixture for client type."""
    return request.param


@pytest.fixture(scope="module")
def cli_policy_client(nodes, policy_engine_service):
    """Create a CLI PolicyClient instance for the server."""
    server = nodes["server"]
    return PolicyClient(server)


@pytest.fixture(scope="module")
def graphql_policy_client(nodes, policy_engine_service):
    """Create a GraphQL PolicyClient instance for the server."""
    server = nodes["server"]
    return GraphQLPolicyClient(server)


@pytest.fixture(scope="module")
def policy_client(
    client_type, cli_policy_client, graphql_policy_client
) -> AnyPolicyClient:
    """
    Parameterized policy client fixture.

    Returns either the CLI client or GraphQL client based on client_type parameter.
    Tests using this fixture will run twice: once with CLI, once with GraphQL.
    """
    if client_type == "cli":
        return cli_policy_client
    else:
        return graphql_policy_client


@pytest.fixture(scope="module")
def server_interface(node_interfaces):
    """Get the server's interface on net1."""
    server_ifaces = node_interfaces["server"]
    return server_ifaces["net1"]


@pytest.fixture(scope="module")
def client_interface(node_interfaces):
    """Get the client's interface on net1."""
    client_ifaces = node_interfaces["client"]
    return client_ifaces["net1"]


# ============================================================================
# IPv4-specific fixtures (use proper netaddr types)
# ============================================================================


@pytest.fixture(scope="module")
def client_network_v4(client_interface):
    """Get client's IPv4 network (e.g., '10.1.1.0/24')."""
    network = client_interface.get_ipv4_network()
    if network is None:
        pytest.skip("No IPv4 address configured on client interface")
    return str(network)


@pytest.fixture(scope="module")
def client_ip_v4(client_interface) -> netaddr.IPAddress:
    """Get client's IPv4 address (e.g., '10.1.1.2')."""
    ip = client_interface.get_ip_address()
    if ip is None:
        pytest.skip("No IPv4 address configured on client interface")
    return ip


@pytest.fixture(scope="module")
def server_ip_v4(server_interface) -> netaddr.IPAddress:
    """Get server's IPv4 address (e.g., '10.1.1.1')."""
    ip = server_interface.get_ip_address()
    if ip is None:
        pytest.skip("No IPv4 address configured on server interface")
    return ip


# ============================================================================
# IPv6-specific fixtures
# ============================================================================


@pytest.fixture(scope="module")
def client_network_v6(client_interface):
    """Get client's IPv6 network (e.g., 'fd00:1::0/64')."""
    network = client_interface.get_ipv6_network()
    if network is None:
        pytest.skip("No IPv6 address configured on client interface")
    return str(network)


@pytest.fixture(scope="module")
def client_ip_v6(client_interface) -> netaddr.IPAddress:
    """Get client's IPv6 address (e.g., 'fd00:1::2')."""
    ip = client_interface.get_ipv6_address()
    if ip is None:
        pytest.skip("No IPv6 address configured on client interface")
    return ip


@pytest.fixture(scope="module")
def server_ip_v6(server_interface) -> netaddr.IPAddress:
    """Get server's IPv6 address (e.g., 'fd00:1::1')."""
    ip = server_interface.get_ipv6_address()
    if ip is None:
        pytest.skip("No IPv6 address configured on server interface")
    return ip


@pytest.fixture(scope="function")
def clean_rules(policy_client):
    """Fixture to ensure rules are cleaned up before and after each test."""
    # Clean before test
    policy_client.flush_rules()
    yield
    # Clean after test
    policy_client.flush_rules()


@pytest.fixture(scope="function")
def attached_ingress(policy_client, server_interface):
    """
    Fixture that attaches ingress program before test and detaches after.

    Yields the interface name.
    """
    iface_name = server_interface.if_name

    # Attach ingress
    result = policy_client.attach_ingress(iface_name, IngressMode.AUTO)
    if not result.success:
        pytest.fail(f"Failed to attach ingress: {result.message}")

    logger.info(f"Ingress attached to {iface_name}")
    yield iface_name

    # Detach ingress
    try:
        policy_client.detach_ingress(iface_name)
        logger.info(f"Ingress detached from {iface_name}")
    except Exception as e:
        logger.warning(f"Failed to detach ingress: {e}")


# ============================================================================
# Test Classes
# ============================================================================


class TestTwoNodePolicy(BaseTopologyTests):
    """Test basic policy engine features between two nodes.

    Inherits standard validation tests from BaseTopologyTests.
    """

    def test_two_nodes_exist(self, topology):
        """Verify topology has exactly two nodes."""
        assert len(topology.nodes) == 2, "Policy topology should have exactly 2 nodes"
        assert topology.nodes[0].name == "server"
        assert topology.nodes[1].name == "client"

    def test_policy_engine_service_running(self, nodes, policy_engine_service):
        """Verify policy-engine service is running and healthy."""
        server = nodes["server"]

        # Verify it started correctly
        assert policy_engine_service.is_healthy, (
            f"Service should be healthy, got: {policy_engine_service.status_text}"
        )
        assert policy_engine_service.main_pid is not None, "Service should have a PID"

        # Double-check current status
        status = get_service_status(server, "policy-engine")
        assert status.is_healthy, (
            f"Service should still be healthy, got: {status.status_text}"
        )
        logger.info(f"policy-engine confirmed running with PID {status.main_pid}")


class TestIngressAttachment:
    """Tests for ingress program attachment and detachment."""

    def test_attach_ingress(self, policy_client, server_interface):
        """Test attaching ingress program to an interface."""
        iface_name = server_interface.if_name

        # Attach ingress
        result = policy_client.attach_ingress(iface_name, IngressMode.AUTO)
        assert result.success, f"Failed to attach ingress: {result.message}"

        # Verify attachment
        interfaces = policy_client.list_interfaces()
        attached = [i for i in interfaces if i.interface == iface_name]
        assert len(attached) >= 1, f"Interface {iface_name} should be attached"
        logger.info(f"Ingress attached in mode: {attached[0].mode}")

        # Check server status
        status = policy_client.status()
        assert status.program_attached, "program_attached should be True"

        # Check that show stats reports program_attached correctly
        stats = policy_client.get_stats(iface_name, direction="ingress")
        assert stats.program_attached, (
            "get_stats should report program_attached=True after attach"
        )

        # Cleanup
        policy_client.detach_ingress(iface_name)

    def test_detach_ingress(self, policy_client, server_interface):
        """Test detaching ingress program from an interface."""
        iface_name = server_interface.if_name

        # First attach
        result = policy_client.attach_ingress(iface_name, IngressMode.AUTO)
        assert result.success, f"Failed to attach ingress: {result.message}"

        # Then detach
        result = policy_client.detach_ingress(iface_name)
        assert result.success, f"Failed to detach ingress: {result.message}"

        # Verify detachment
        interfaces = policy_client.list_interfaces()
        attached = [
            i
            for i in interfaces
            if i.interface == iface_name and i.direction == "ingress"
        ]
        assert len(attached) == 0, f"Interface {iface_name} should be detached"

    def test_detach_all(self, policy_client, server_interface):
        """Test detaching all programs."""
        iface_name = server_interface.if_name

        # Attach first
        policy_client.attach_ingress(iface_name, IngressMode.AUTO)

        # Detach all
        result = policy_client.detach_all()
        assert result.success, f"Failed to detach all: {result.message}"

        # Verify
        interfaces = policy_client.list_interfaces()
        assert len(interfaces) == 0, "All interfaces should be detached"


class TestRuleManagement:
    """Tests for rule addition, deletion, and listing."""

    def test_add_rule_basic_ipv4(self, policy_client, attached_ingress, clean_rules):
        """Test adding a basic IPv4 rule."""
        options = AddRuleOptions(
            interface=attached_ingress,
            src="10.0.0.0/8",
            dst="0.0.0.0/0",
            protocol="any",
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options)
        assert result.success, f"Failed to add rule: {result.message}"

        # Verify rule was added
        rules = policy_client.list_rules()
        assert len(rules) == 1, "Should have 1 rule"
        assert rules[0].src_prefix == "10.0.0.0/8"
        assert rules[0].actions[0].action == PolicyAction.DROP

    def test_add_rule_basic_ipv6(self, policy_client, attached_ingress, clean_rules):
        """Test adding a basic IPv6 rule."""
        options = AddRuleOptions(
            interface=attached_ingress,
            src="2001:db8::/32",
            dst="::/0",
            protocol="any",
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options)
        assert result.success, f"Failed to add IPv6 rule: {result.message}"

        # Verify rule was added
        rules = policy_client.list_rules()
        assert len(rules) == 1, "Should have 1 rule"
        assert "2001:db8::" in rules[0].src_prefix.lower()
        assert rules[0].actions[0].action == PolicyAction.DROP

    def test_add_rule_with_ports(self, policy_client, attached_ingress, clean_rules):
        """Test adding a rule with port matching."""
        options = AddRuleOptions(
            interface=attached_ingress,
            src="0.0.0.0/0",
            dst="0.0.0.0/0",
            protocol="tcp",
            sport=1234,
            dport=80,
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options)
        assert result.success, f"Failed to add rule: {result.message}"

        rules = policy_client.list_rules()
        assert len(rules) == 1
        assert rules[0].sport == 1234
        assert rules[0].dport == 80
        assert rules[0].protocol == Protocol.TCP

    def test_add_rule_icmp(self, policy_client, attached_ingress, clean_rules):
        """Test adding an ICMP rule."""
        options = AddRuleOptions(
            interface=attached_ingress,
            src="10.1.1.0/24",
            dst="0.0.0.0/0",
            protocol="icmp",
            actions=[("log", 0), ("drop", 1)],
        )
        result = policy_client.add_rule(options)
        assert result.success, f"Failed to add rule: {result.message}"

        rules = policy_client.list_rules()
        assert len(rules) == 1
        assert rules[0].protocol == Protocol.ICMP
        assert len(rules[0].actions) == 2

    def test_add_multiple_rules(self, policy_client, attached_ingress, clean_rules):
        """Test adding multiple rules."""
        # Add first rule
        policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                src="10.0.0.0/8",
                protocol="any",
                actions=[("pass", 0)],
            )
        )

        # Add second rule
        policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                src="192.168.0.0/16",
                protocol="tcp",
                dport=22,
                actions=[("drop", 0)],
            )
        )

        # Add third rule
        policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                src="172.16.0.0/12",
                protocol="udp",
                actions=[("log", 0)],
            )
        )

        rules = policy_client.list_rules()
        assert len(rules) == 3, "Should have 3 rules"

    def test_delete_rule_by_id(self, policy_client, attached_ingress, clean_rules):
        """Test deleting a rule by ID."""
        # Add a rule with specific ID
        options = AddRuleOptions(
            interface=attached_ingress,
            src="10.0.0.0/8",
            protocol="any",
            actions=[("drop", 0)],
            rule_id=12345,
        )
        policy_client.add_rule(options)

        # Verify it exists
        rules = policy_client.list_rules()
        assert len(rules) == 1
        assert rules[0].rule_id == 12345

        # Delete by ID
        result = policy_client.delete_rule(attached_ingress, rule_id=12345)
        assert result.success, f"Failed to delete rule: {result.message}"

        # Verify deletion
        rules = policy_client.list_rules()
        assert len(rules) == 0, "Rule should be deleted"

    def test_flush_rules(self, policy_client, attached_ingress, clean_rules):
        """Test flushing all rules."""
        # Add several rules
        for i in range(5):
            policy_client.add_rule(
                AddRuleOptions(
                    interface=attached_ingress,
                    src=f"10.{i}.0.0/16",
                    protocol="any",
                    actions=[("pass", 0)],
                )
            )

        rules = policy_client.list_rules()
        assert len(rules) == 5

        # Flush all
        result = policy_client.flush_rules()
        assert result.success, f"Failed to flush rules: {result.message}"

        # Verify
        rules = policy_client.list_rules()
        assert len(rules) == 0, "All rules should be flushed"

    def test_rule_prefix_lengths_ipv4(
        self, policy_client, attached_ingress, clean_rules
    ):
        """Test rules with various IPv4 prefix lengths."""
        prefix_lengths = [8, 16, 24, 32]

        for prefix_len in prefix_lengths:
            options = AddRuleOptions(
                interface=attached_ingress,
                src=f"10.0.0.0/{prefix_len}",
                protocol="any",
                actions=[("pass", 0)],
            )
            result = policy_client.add_rule(options)
            assert result.success, (
                f"Failed to add rule with /{prefix_len}: {result.message}"
            )

        rules = policy_client.list_rules()
        assert len(rules) == len(prefix_lengths)

        # Verify prefix lengths
        for rule in rules:
            prefix_len = int(rule.src_prefix.split("/")[1])
            assert prefix_len in prefix_lengths

    def test_rule_prefix_lengths_ipv6(
        self, policy_client, attached_ingress, clean_rules
    ):
        """Test rules with various IPv6 prefix lengths."""
        prefix_lengths = [32, 48, 64, 128]

        for prefix_len in prefix_lengths:
            options = AddRuleOptions(
                interface=attached_ingress,
                src=f"2001:db8::/{prefix_len}",
                dst="::/0",
                protocol="any",
                actions=[("pass", 0)],
            )
            result = policy_client.add_rule(options)
            assert result.success, (
                f"Failed to add IPv6 rule with /{prefix_len}: {result.message}"
            )

        rules = policy_client.list_rules()
        assert len(rules) == len(prefix_lengths)


class TestTrafficMatching:
    """Tests for traffic matching and packet counting."""

    def test_icmp_traffic_pass_v4(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        server_ip_v4,
        nmap_installed,
    ):
        """Test that ICMP traffic passes by default (IPv4)."""
        client = nodes["client"]

        # Send ICMP ping from client to server
        result = send_ping(
            client,
            server_ip_v4,
            count=5,
            interface=client_interface.if_name,
        )

        assert result.success, f"ICMP ping failed: {result.error_message}"
        assert result.packets_received > 0, "Should receive some packets"
        logger.info(
            f"ICMP ping: sent={result.packets_sent}, received={result.packets_received}"
        )

    def test_icmp_traffic_pass_v6(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        server_ip_v6,
        nmap_installed,
    ):
        """Test that ICMPv6 traffic passes by default."""
        client = nodes["client"]

        # Send ICMPv6 ping from client to server
        result = send_ping(
            client,
            server_ip_v6,
            count=5,
            interface=client_interface.if_name,
        )

        assert result.success, f"ICMPv6 ping failed: {result.error_message}"
        assert result.packets_received > 0, "Should receive some packets"
        logger.info(
            f"ICMPv6 ping: sent={result.packets_sent}, received={result.packets_received}"
        )

    def test_icmp_traffic_drop_rule_v4(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_network_v4,
        server_ip_v4,
        nmap_installed,
    ):
        """Test that ICMP traffic is dropped when matching a drop rule (IPv4)."""
        client = nodes["client"]

        # Add a drop rule for ICMP from client's network
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            protocol="icmp",
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options)
        assert result.success, f"Failed to add drop rule: {result.message}"

        # Get stats BEFORE sending traffic
        initial_stats = policy_client.get_stats(attached_ingress)
        initial_drops = initial_stats.global_stats.policy_drops

        # Send a known number of ICMP packets - should be dropped
        packets_to_send = 5
        result = send_ping(
            client,
            server_ip_v4,
            count=packets_to_send,
            interface=client_interface.if_name,
        )

        # With a drop rule, we expect packet loss
        assert result.packets_lost > 0, "Packets should be dropped"
        logger.info(f"ICMP with drop rule: lost={result.packets_lost}")

        # Get stats AFTER sending traffic and verify exact count
        final_stats = policy_client.get_stats(attached_ingress)
        final_drops = final_stats.global_stats.policy_drops
        drops_delta = final_drops - initial_drops

        logger.info(
            f"Policy drops: initial={initial_drops}, final={final_drops}, "
            f"delta={drops_delta}, expected={packets_to_send}"
        )
        assert drops_delta == packets_to_send, (
            f"Expected exactly {packets_to_send} policy drops, got {drops_delta}"
        )

    def test_icmp_traffic_drop_rule_v6(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_network_v6,
        server_ip_v6,
        nmap_installed,
    ):
        """Test that ICMPv6 traffic is dropped when matching a drop rule."""
        client = nodes["client"]

        # Add a drop rule for ICMPv6 from client's network
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v6,
            dst="::/0",
            protocol="icmpv6",
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options)
        assert result.success, f"Failed to add IPv6 drop rule: {result.message}"

        # Get stats BEFORE sending traffic
        initial_stats = policy_client.get_stats(attached_ingress)
        initial_drops = initial_stats.global_stats.policy_drops

        # Send a known number of ICMPv6 packets - should be dropped
        packets_to_send = 5
        result = send_ping(
            client,
            server_ip_v6,
            count=packets_to_send,
            interface=client_interface.if_name,
        )

        # With a drop rule, we expect packet loss
        assert result.packets_lost > 0, "Packets should be dropped"
        logger.info(f"ICMPv6 with drop rule: lost={result.packets_lost}")

        # Get stats AFTER sending traffic and verify exact count
        final_stats = policy_client.get_stats(attached_ingress)
        final_drops = final_stats.global_stats.policy_drops
        drops_delta = final_drops - initial_drops

        logger.info(
            f"Policy drops: initial={initial_drops}, final={final_drops}, "
            f"delta={drops_delta}, expected>={packets_to_send}"
        )
        assert drops_delta >= packets_to_send, (
            f"Expected at least {packets_to_send} policy drops, got {drops_delta}"
        )

    def test_tcp_traffic_with_port_matching_v4(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_network_v4,
        server_ip_v4,
        nmap_installed,
    ):
        """Test TCP traffic matching with specific ports and exact packet counting (IPv4)."""
        client = nodes["client"]

        # Add a drop rule for TCP port 8080 from client
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            protocol="tcp",
            dport=8080,
            actions=[("drop", 0)],
        )
        policy_client.add_rule(options)

        # Get stats BEFORE sending traffic
        initial_stats = policy_client.get_stats(attached_ingress)
        initial_drops = initial_stats.global_stats.policy_drops

        # Send TCP SYN to port 8080 - should be dropped
        packets_to_send = 5
        send_tcp_syn(
            client,
            server_ip_v4,
            dest_port=8080,
            count=packets_to_send,
            interface=client_interface.if_name,
        )

        # Get stats AFTER sending traffic to port 8080
        stats_after_8080 = policy_client.get_stats(attached_ingress)
        drops_8080 = stats_after_8080.global_stats.policy_drops - initial_drops

        logger.info(
            f"TCP 8080 (drop rule): sent={packets_to_send}, "
            f"policy_drops={drops_8080}, expected={packets_to_send}"
        )
        assert drops_8080 == packets_to_send, (
            f"Expected exactly {packets_to_send} policy drops for TCP 8080, got {drops_8080}"
        )

        # Now test that traffic to a different port is NOT dropped
        initial_drops_9090 = stats_after_8080.global_stats.policy_drops

        # Send TCP SYN to port 9090 - should pass (no matching rule)
        send_tcp_syn(
            client,
            server_ip_v4,
            dest_port=9090,
            count=packets_to_send,
            interface=client_interface.if_name,
        )

        # Get stats AFTER sending traffic to port 9090
        stats_after_9090 = policy_client.get_stats(attached_ingress)
        drops_9090 = stats_after_9090.global_stats.policy_drops - initial_drops_9090

        logger.info(f"TCP 9090 (no rule): policy_drops={drops_9090}, expected=0")
        assert drops_9090 == 0, (
            f"Expected 0 policy drops for TCP 9090, got {drops_9090}"
        )

    def test_tcp_traffic_with_port_matching_v6(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_network_v6,
        client_ip_v6,
        server_ip_v6,
        nmap_installed,
    ):
        """Test TCP traffic matching with specific ports and exact packet counting (IPv6)."""
        client = nodes["client"]

        # Add a drop rule for TCP port 8080 from client IPv6 network
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v6,
            dst="::/0",
            protocol="tcp",
            dport=8080,
            actions=[("drop", 0)],
        )
        policy_client.add_rule(options)

        # Get stats BEFORE sending traffic
        initial_stats = policy_client.get_stats(attached_ingress)
        initial_drops = initial_stats.global_stats.policy_drops

        # Send TCP SYN to port 8080 - should be dropped
        # Note: source_ip is required for nping IPv6 to use correct source address
        packets_to_send = 5
        send_tcp_syn(
            client,
            server_ip_v6,
            dest_port=8080,
            count=packets_to_send,
            source_ip=str(client_ip_v6),
            interface=client_interface.if_name,
        )

        # Get stats AFTER sending traffic to port 8080
        stats_after_8080 = policy_client.get_stats(attached_ingress)
        drops_8080 = stats_after_8080.global_stats.policy_drops - initial_drops

        logger.info(
            f"TCP6 8080 (drop rule): sent={packets_to_send}, "
            f"policy_drops={drops_8080}, expected={packets_to_send}"
        )
        assert drops_8080 == packets_to_send, (
            f"Expected exactly {packets_to_send} policy drops for TCP6 8080, got {drops_8080}"
        )

    def test_udp_traffic_with_port_matching_v4(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_network_v4,
        server_ip_v4,
        nmap_installed,
    ):
        """Test UDP traffic matching with specific ports and exact packet counting (IPv4)."""
        client = nodes["client"]

        # Add a drop rule for UDP port 5353 (mDNS)
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            protocol="udp",
            dport=5353,
            actions=[("drop", 0)],
        )
        policy_client.add_rule(options)

        # Get stats BEFORE sending traffic
        initial_stats = policy_client.get_stats(attached_ingress)
        initial_drops = initial_stats.global_stats.policy_drops

        # Send UDP to port 5353 - should be dropped
        packets_to_send = 5
        send_udp_packets(
            client,
            server_ip_v4,
            dest_port=5353,
            count=packets_to_send,
            interface=client_interface.if_name,
        )

        # Get stats AFTER sending traffic and verify exact count
        final_stats = policy_client.get_stats(attached_ingress)
        drops_delta = final_stats.global_stats.policy_drops - initial_drops

        logger.info(
            f"UDP 5353 (drop rule): sent={packets_to_send}, "
            f"policy_drops={drops_delta}, expected={packets_to_send}"
        )
        assert drops_delta == packets_to_send, (
            f"Expected exactly {packets_to_send} policy drops for UDP 5353, got {drops_delta}"
        )

    def test_udp_traffic_with_port_matching_v6(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_network_v6,
        client_ip_v6,
        server_ip_v6,
        nmap_installed,
    ):
        """Test UDP traffic matching with specific ports and exact packet counting (IPv6)."""
        client = nodes["client"]

        # Add a drop rule for UDP port 5353 (mDNS)
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v6,
            dst="::/0",
            protocol="udp",
            dport=5353,
            actions=[("drop", 0)],
        )
        policy_client.add_rule(options)

        # Get stats BEFORE sending traffic
        initial_stats = policy_client.get_stats(attached_ingress)
        initial_drops = initial_stats.global_stats.policy_drops

        # Send UDP to port 5353 - should be dropped
        # Note: source_ip is required for nping IPv6 to use correct source address
        packets_to_send = 5
        nping_result = send_udp_packets(
            client,
            server_ip_v6,
            dest_port=5353,
            count=packets_to_send,
            source_ip=str(client_ip_v6),
            interface=client_interface.if_name,
        )

        # Brief wait for stats to settle
        time.sleep(0.5)

        # Get stats AFTER sending traffic and verify exact count
        final_stats = policy_client.get_stats(attached_ingress)
        drops_delta = final_stats.global_stats.policy_drops - initial_drops

        # Also check rule stats for debugging
        rule_stats = policy_client.get_rule_stats()

        logger.info(
            f"UDP6 5353 (drop rule): nping_sent={nping_result.packets_sent}, "
            f"policy_drops={drops_delta}, expected={packets_to_send}, "
            f"rule_stats={rule_stats}"
        )
        assert drops_delta == packets_to_send, (
            f"Expected exactly {packets_to_send} policy drops for UDP6 5353, got {drops_delta}. "
            f"nping result: sent={nping_result.packets_sent}, raw={nping_result.raw_output[:200]}"
        )

    def test_source_port_matching_v4(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_network_v4,
        server_ip_v4,
        nmap_installed,
    ):
        """Test matching on source port with exact packet counting (IPv4)."""
        client = nodes["client"]

        # Add a drop rule for traffic FROM source port 12345
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            protocol="tcp",
            sport=12345,
            actions=[("drop", 0)],
        )
        policy_client.add_rule(options)

        # Get stats BEFORE sending traffic
        initial_stats = policy_client.get_stats(attached_ingress)
        initial_drops = initial_stats.global_stats.policy_drops

        # Send TCP from source port 12345 - should be dropped
        packets_to_send = 5
        send_tcp_syn(
            client,
            server_ip_v4,
            dest_port=80,
            source_port=12345,
            count=packets_to_send,
            interface=client_interface.if_name,
        )

        # Get stats AFTER sending traffic and verify exact count
        final_stats = policy_client.get_stats(attached_ingress)
        drops_delta = final_stats.global_stats.policy_drops - initial_drops

        logger.info(
            f"TCP sport 12345 (drop rule): sent={packets_to_send}, "
            f"policy_drops={drops_delta}, expected={packets_to_send}"
        )
        assert drops_delta == packets_to_send, (
            f"Expected exactly {packets_to_send} policy drops for TCP sport 12345, "
            f"got {drops_delta}"
        )


class TestPacketCounting:
    """Tests for packet counting and statistics."""

    def test_rule_stats_increment_v4(
        self,
        configure_node_interfaces,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_network_v4,
        server_ip_v4,
        nmap_installed,
    ):
        """Test that rule statistics increment correctly with exact counts (IPv4)."""
        client = nodes["client"]

        logger.info(f"Client network: {client_network_v4}, server IP: {server_ip_v4}")

        # Add a log rule (will pass traffic but count it)
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            protocol="icmp",
            actions=[("log", 0), ("pass", 1)],
            rule_id=99999,
        )
        result = policy_client.add_rule(options)
        assert result.success, f"Failed to add rule: {result.message}"

        # Verify the rule was added
        rules = policy_client.list_rules()
        rule_found = any(r.rule_id == 99999 for r in rules)
        assert rule_found, "Rule 99999 should exist after adding"
        logger.info(f"Rules after add: {[(r.rule_id, r.src_prefix) for r in rules]}")

        # Clear rule stats for deterministic measurement
        policy_client.clear_rule_stats(99999)

        # Send a known number of ICMP packets
        packets_to_send = 10
        ping_result = send_ping(
            client,
            server_ip_v4,
            count=packets_to_send,
            interface=client_interface.if_name,
        )
        logger.info(
            f"Ping result: sent={ping_result.packets_sent}, "
            f"received={ping_result.packets_received}"
        )

        # Get stats AFTER sending traffic
        final_stats = policy_client.get_rule_stats()
        packets_counted = 0
        for rws in final_stats.rules:
            logger.info(f"Rule {rws.rule.rule_id}: stats={rws.stats}")
            if rws.rule.rule_id == 99999:
                if rws.stats:
                    packets_counted = rws.stats.packets
                break

        logger.info(
            f"Rule stats: packets_counted={packets_counted}, expected={packets_to_send}"
        )

        # Verify exact packet count - stats were cleared so we expect exact match
        assert packets_counted == packets_to_send, (
            f"Expected rule to count exactly {packets_to_send} packets, got {packets_counted}"
        )

    def test_global_stats_increment_v4(
        self,
        nodes,
        configure_node_interfaces,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_network_v4,
        server_ip_v4,
        nmap_installed,
    ):
        """Test that global statistics increment correctly with exact counts (IPv4)."""
        client = nodes["client"]

        # Add a pass rule for ICMP so we can count rx_packets precisely
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            protocol="icmp",
            actions=[("pass", 0)],
        )
        policy_client.add_rule(options)

        # Clear stats before the test for deterministic measurement
        policy_client.clear_interface_stats(attached_ingress)

        # Send a known number of ICMP packets
        packets_to_send = 10
        send_ping(
            client,
            server_ip_v4,
            count=packets_to_send,
            interface=client_interface.if_name,
        )

        # Get stats AFTER sending traffic
        final_stats = policy_client.get_stats(attached_ingress)
        packets_received = final_stats.global_stats.rx_packets
        logger.info(
            f"Global RX: rx_packets={packets_received}, expected>={packets_to_send}"
        )

        # Verify packet count - use >= since background traffic may arrive
        assert packets_received >= packets_to_send, (
            f"Expected at least {packets_to_send} rx_packets, got {packets_received}"
        )

    def test_global_stats_increment_v6(
        self,
        nodes,
        configure_node_interfaces,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_network_v6,
        server_ip_v6,
        nmap_installed,
    ):
        """Test that global statistics increment correctly with exact counts (IPv6)."""
        client = nodes["client"]

        # Add a pass rule for ICMPv6 so we can count rx_packets precisely
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v6,
            dst="::/0",
            protocol="icmpv6",
            actions=[("pass", 0)],
        )
        policy_client.add_rule(options)

        # Clear stats before the test for deterministic measurement
        policy_client.clear_interface_stats(attached_ingress)

        # Send a known number of ICMPv6 packets
        packets_to_send = 10
        send_ping(
            client,
            server_ip_v6,
            count=packets_to_send,
            interface=client_interface.if_name,
        )

        # Get stats AFTER sending traffic
        final_stats = policy_client.get_stats(attached_ingress)
        packets_received = final_stats.global_stats.rx_packets
        logger.info(
            f"Global RX (v6): rx_packets={packets_received}, expected>={packets_to_send}"
        )

        # Verify packet count - use >= since background traffic may arrive
        assert packets_received >= packets_to_send, (
            f"Expected at least {packets_to_send} rx_packets, got {packets_received}"
        )

    def test_l4_port_rule_isolation_v4(
        self,
        configure_node_interfaces,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        server_ip_v4,
        nmap_installed,
    ):
        """Test that two rules differing only by dport each count independently (IPv4).

        Rule 1: src=any, dst=any, tcp dport=80, drop, rule_id=10080
        Rule 2: src=any, dst=any, tcp dport=22, drop, rule_id=10022

        Send 5 packets to port 80 and 7 packets to port 22.  Verify:
          - rule 10080 counts exactly 5 packets
          - rule 10022 counts exactly 7 packets
          - global policy_drops == 12
        """
        client = nodes["client"]

        port80_rule_id = 10080
        port22_rule_id = 10022

        # Add rule for TCP port 80
        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                src="0.0.0.0/0",
                dst="0.0.0.0/0",
                protocol="tcp",
                dport=80,
                actions=[("drop", 0)],
                rule_id=port80_rule_id,
            )
        )
        assert result.success, f"Failed to add port-80 rule: {result.message}"

        # Add rule for TCP port 22
        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                src="0.0.0.0/0",
                dst="0.0.0.0/0",
                protocol="tcp",
                dport=22,
                actions=[("drop", 0)],
                rule_id=port22_rule_id,
            )
        )
        assert result.success, f"Failed to add port-22 rule: {result.message}"

        # Clear per-rule stats so counts start from zero
        policy_client.clear_rule_stats(port80_rule_id)
        policy_client.clear_rule_stats(port22_rule_id)

        # Baseline global drops
        initial_stats = policy_client.get_stats(attached_ingress)
        initial_drops = initial_stats.global_stats.policy_drops

        packets_to_port80 = 5
        packets_to_port22 = 7

        # Send traffic to port 80
        send_tcp_syn(
            client,
            server_ip_v4,
            dest_port=80,
            count=packets_to_port80,
            interface=client_interface.if_name,
        )

        # Send traffic to port 22
        send_tcp_syn(
            client,
            server_ip_v4,
            dest_port=22,
            count=packets_to_port22,
            interface=client_interface.if_name,
        )

        # Check per-rule stats
        rule_stats = policy_client.get_rule_stats()
        stats_by_id = {
            rws.rule.rule_id: rws.stats
            for rws in rule_stats.rules
            if rws.rule.rule_id in (port80_rule_id, port22_rule_id)
        }

        packets_80 = stats_by_id.get(port80_rule_id)
        packets_22 = stats_by_id.get(port22_rule_id)

        count_80 = packets_80.packets if packets_80 else 0
        count_22 = packets_22.packets if packets_22 else 0

        logger.info(
            f"L4 port isolation: port80 rule counted {count_80} (expected {packets_to_port80}), "
            f"port22 rule counted {count_22} (expected {packets_to_port22})"
        )

        assert count_80 == packets_to_port80, (
            f"Rule {port80_rule_id} (dport=80) expected {packets_to_port80} packets, got {count_80}"
        )
        assert count_22 == packets_to_port22, (
            f"Rule {port22_rule_id} (dport=22) expected {packets_to_port22} packets, got {count_22}"
        )

        # Verify global drops match the sum
        final_stats = policy_client.get_stats(attached_ingress)
        drops_delta = final_stats.global_stats.policy_drops - initial_drops
        expected_total = packets_to_port80 + packets_to_port22

        logger.info(f"Global drops delta: {drops_delta} (expected {expected_total})")
        assert drops_delta == expected_total, (
            f"Expected {expected_total} total policy drops, got {drops_delta}"
        )


class TestPrefixLengths:
    """Tests for various IP prefix lengths."""

    def test_host_prefix_32_v4(
        self,
        nodes,
        configure_node_interfaces,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_ip_v4,
        server_ip_v4,
        nmap_installed,
    ):
        """Test matching a specific host (/32 prefix) (IPv4)."""
        client = nodes["client"]

        # Add drop rule for specific client IP
        options = AddRuleOptions(
            interface=attached_ingress,
            src=f"{client_ip_v4}/32",
            protocol="icmp",
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options)
        assert result.success

        # Traffic should be dropped
        result = send_ping(
            client,
            server_ip_v4,
            count=5,
            interface=client_interface.if_name,
        )

        assert result.packets_lost > 0, "Packets should be dropped with /32 rule"

    def test_host_prefix_128_v6(
        self,
        nodes,
        configure_node_interfaces,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_ip_v6,
        server_ip_v6,
        nmap_installed,
    ):
        """Test matching a specific IPv6 host (/128 prefix)."""
        client = nodes["client"]

        # Add drop rule for specific client IPv6
        options = AddRuleOptions(
            interface=attached_ingress,
            src=f"{client_ip_v6}/128",
            dst="::/0",
            protocol="icmpv6",
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options)
        assert result.success

        # Traffic should be dropped
        result = send_ping(
            client,
            server_ip_v6,
            count=5,
            interface=client_interface.if_name,
        )

        assert result.packets_lost > 0, "Packets should be dropped with /128 rule"

    def test_network_prefix_24_v4(
        self,
        nodes,
        configure_node_interfaces,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_network_v4,
        server_ip_v4,
        nmap_installed,
    ):
        """Test matching a /24 network (IPv4)."""
        client = nodes["client"]

        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            protocol="icmp",
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options)
        assert result.success

        result = send_ping(
            client,
            server_ip_v4,
            count=5,
            interface=client_interface.if_name,
        )

        assert result.packets_lost > 0, "Packets should be dropped with /24 rule"

    def test_network_prefix_64_v6(
        self,
        nodes,
        configure_node_interfaces,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_network_v6,
        server_ip_v6,
        nmap_installed,
    ):
        """Test matching a /64 IPv6 network."""
        client = nodes["client"]

        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v6,
            dst="::/0",
            protocol="icmpv6",
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options)
        assert result.success

        result = send_ping(
            client,
            server_ip_v6,
            count=5,
            interface=client_interface.if_name,
        )

        assert result.packets_lost > 0, "Packets should be dropped with /64 rule"

    def test_wide_prefix_8_v4(
        self,
        nodes,
        configure_node_interfaces,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_ip_v4,
        server_ip_v4,
        nmap_installed,
    ):
        """Test matching a /8 network (IPv4)."""
        client = nodes["client"]

        # Get the /8 network from the client IP using netaddr
        client_addr = netaddr.IPAddress(client_ip_v4)
        network_8 = netaddr.IPNetwork(f"{client_addr}/8").cidr

        options = AddRuleOptions(
            interface=attached_ingress,
            src=str(network_8),
            protocol="icmp",
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options)
        assert result.success

        result = send_ping(
            client,
            server_ip_v4,
            count=5,
            interface=client_interface.if_name,
        )

        assert result.packets_lost > 0, "Packets should be dropped with /8 rule"

    def test_wide_prefix_32_v6(
        self,
        nodes,
        configure_node_interfaces,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_ip_v6,
        server_ip_v6,
        nmap_installed,
    ):
        """Test matching a /32 IPv6 network."""
        client = nodes["client"]

        # Get the /32 network from the client IPv6 using netaddr
        client_addr = netaddr.IPAddress(client_ip_v6)
        network_32 = netaddr.IPNetwork(f"{client_addr}/32").cidr

        options = AddRuleOptions(
            interface=attached_ingress,
            src=str(network_32),
            dst="::/0",
            protocol="icmpv6",
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options)
        assert result.success

        result = send_ping(
            client,
            server_ip_v6,
            count=5,
            interface=client_interface.if_name,
        )

        assert result.packets_lost > 0, "Packets should be dropped with /32 IPv6 rule"


class TestIcmpTypes:
    """Tests for ICMP type and code matching."""

    def test_icmp_echo_request_v4(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        server_ip_v4,
        nmap_installed,
    ):
        """Test ICMP echo request (type 8) (IPv4)."""
        client = nodes["client"]

        # Send echo request (type 8, code 0)
        result = send_icmp_with_type(
            client,
            server_ip_v4,
            icmp_type=8,
            icmp_code=0,
            count=5,
            interface=client_interface.if_name,
        )

        logger.info(
            f"ICMP type 8: sent={result.packets_sent}, received={result.packets_received}"
        )
        assert result.packets_sent > 0

    def test_icmp_timestamp_request_v4(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        server_ip_v4,
        nmap_installed,
    ):
        """Test ICMP timestamp request (type 13) (IPv4)."""
        client = nodes["client"]

        # Send timestamp request (type 13, code 0)
        result = send_icmp_with_type(
            client,
            server_ip_v4,
            icmp_type=13,
            icmp_code=0,
            count=5,
            interface=client_interface.if_name,
        )

        logger.info(f"ICMP type 13: sent={result.packets_sent}")
        assert result.packets_sent > 0


class TestDefaultAction:
    """Tests for default action configuration."""

    def test_set_default_action_drop_v4(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        server_ip_v4,
        nmap_installed,
    ):
        """Test setting default action to drop (IPv4)."""
        client = nodes["client"]

        # Set default action to drop
        result = policy_client.set_default_action(
            PolicyAction.DROP, interface=attached_ingress
        )
        assert result.success, f"Failed to set default action: {result.message}"

        # With no rules and default drop, traffic should be dropped
        result = send_ping(
            client,
            server_ip_v4,
            count=5,
            interface=client_interface.if_name,
        )

        assert result.packets_lost > 0, (
            "Packets should be dropped with default drop action"
        )

        # Reset to pass for other tests
        policy_client.set_default_action(PolicyAction.PASS, interface=attached_ingress)

    def test_set_default_action_pass_v4(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        server_ip_v4,
        nmap_installed,
    ):
        """Test setting default action to pass (IPv4)."""
        client = nodes["client"]

        # Set default action to pass
        result = policy_client.set_default_action(
            PolicyAction.PASS, interface=attached_ingress
        )
        assert result.success, f"Failed to set default action: {result.message}"

        # With no rules and default pass, traffic should pass
        result = send_ping(
            client,
            server_ip_v4,
            count=5,
            interface=client_interface.if_name,
        )

        assert result.success, "Traffic should pass with default pass action"
        assert result.packets_received > 0

    def test_set_default_action_drop_v6(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        server_ip_v6,
        nmap_installed,
    ):
        """Test setting default action to drop (IPv6)."""
        client = nodes["client"]

        # Set default action to drop
        result = policy_client.set_default_action(
            PolicyAction.DROP, interface=attached_ingress
        )
        assert result.success, f"Failed to set default action: {result.message}"

        # With no rules and default drop, traffic should be dropped
        result = send_ping(
            client,
            server_ip_v6,
            count=5,
            interface=client_interface.if_name,
        )

        assert result.packets_lost > 0, (
            "Packets should be dropped with default drop action"
        )

        # Reset to pass for other tests
        policy_client.set_default_action(PolicyAction.PASS, interface=attached_ingress)


# ============================================================================
# Negative Tests
# ============================================================================


class TestIngressAttachmentNegative:
    """Negative tests for ingress attachment."""

    def test_attach_nonexistent_interface(self, policy_client):
        """Test attaching to a non-existent interface fails gracefully."""
        result = policy_client.attach_ingress("nonexistent0", IngressMode.AUTO)
        assert not result.success, "Should fail to attach to non-existent interface"
        logger.info(f"Expected failure: {result.message}")

    def test_detach_not_attached(self, policy_client, server_interface):
        """Test detaching when not attached returns appropriate response."""
        # Ensure nothing is attached
        policy_client.detach_all()

        # Try to detach - should fail or return appropriate message
        result = policy_client.detach_ingress(server_interface.if_name)
        # Log the result - may succeed with "not attached" message or fail
        logger.info(
            f"Detach when not attached: success={result.success}, msg={result.message}"
        )

    def test_double_attach(self, policy_client, server_interface):
        """Test attaching twice to same interface."""
        iface_name = server_interface.if_name

        # First attach
        result1 = policy_client.attach_ingress(iface_name, IngressMode.AUTO)
        assert result1.success, f"First attach should succeed: {result1.message}"

        try:
            # Second attach - should fail or return already attached
            result2 = policy_client.attach_ingress(iface_name, IngressMode.AUTO)
            logger.info(
                f"Double attach: success={result2.success}, msg={result2.message}"
            )
        finally:
            # Cleanup
            policy_client.detach_ingress(iface_name)


class TestRuleManagementNegative:
    """Negative tests for rule management."""

    def test_add_rule_invalid_prefix(
        self, policy_client, attached_ingress, clean_rules
    ):
        """Test adding a rule with invalid prefix."""
        options = AddRuleOptions(
            interface=attached_ingress,
            src="invalid-prefix",
            protocol="any",
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options)
        assert not result.success, "Should fail with invalid prefix"
        logger.info(f"Expected failure: {result.message}")

    def test_add_rule_invalid_prefix_length(
        self, policy_client, attached_ingress, clean_rules
    ):
        """Test adding a rule with invalid prefix length."""
        options = AddRuleOptions(
            interface=attached_ingress,
            src="10.0.0.0/33",  # Invalid - max is /32 for IPv4
            protocol="any",
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options)
        assert not result.success, "Should fail with invalid prefix length"
        logger.info(f"Expected failure: {result.message}")

    def test_add_rule_invalid_ipv6_prefix_length(
        self, policy_client, attached_ingress, clean_rules
    ):
        """Test adding an IPv6 rule with invalid prefix length."""
        options = AddRuleOptions(
            interface=attached_ingress,
            src="2001:db8::/129",  # Invalid - max is /128 for IPv6
            dst="::/0",
            protocol="any",
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options)
        assert not result.success, "Should fail with invalid IPv6 prefix length"
        logger.info(f"Expected failure: {result.message}")

    def test_delete_nonexistent_rule(
        self, policy_client, attached_ingress, clean_rules
    ):
        """Test deleting a rule that doesn't exist."""
        result = policy_client.delete_rule(attached_ingress, rule_id=999999)
        # May succeed with "not found" message or fail
        logger.info(
            f"Delete nonexistent: success={result.success}, msg={result.message}"
        )

    def test_add_rule_without_ingress(self, policy_client, server_interface):
        """Test adding a rule without ingress attached fails."""
        # Ensure nothing is attached
        policy_client.detach_all()

        options = AddRuleOptions(
            interface=server_interface.if_name,
            src="10.0.0.0/8",
            protocol="any",
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options)
        assert not result.success, "Should fail without ingress attached"
        logger.info(f"Expected failure: {result.message}")

    def test_add_duplicate_rule_id(self, policy_client, attached_ingress, clean_rules):
        """Test adding a rule with duplicate ID."""
        options1 = AddRuleOptions(
            interface=attached_ingress,
            src="10.0.0.0/8",
            protocol="any",
            actions=[("drop", 0)],
            rule_id=11111,
        )
        result1 = policy_client.add_rule(options1)
        assert result1.success, f"First rule should succeed: {result1.message}"

        options2 = AddRuleOptions(
            interface=attached_ingress,
            src="192.168.0.0/16",
            protocol="any",
            actions=[("pass", 0)],
            rule_id=11111,  # Same ID
        )
        result2 = policy_client.add_rule(options2)
        # Should either fail or replace the existing rule
        logger.info(f"Duplicate ID: success={result2.success}, msg={result2.message}")

    def test_add_rule_invalid_port_tcp(
        self, policy_client, attached_ingress, clean_rules
    ):
        """Test adding a TCP rule with invalid port number."""
        options = AddRuleOptions(
            interface=attached_ingress,
            src="10.0.0.0/8",
            protocol="tcp",
            dport=70000,  # Invalid - max is 65535
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options)
        # Should fail with invalid port
        logger.info(f"Invalid port: success={result.success}, msg={result.message}")


class TestTrafficMatchingNegative:
    """Negative tests for traffic matching - verifying rules don't match wrong traffic."""

    def test_rule_does_not_match_different_network(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        server_ip_v4,
        nmap_installed,
    ):
        """Test that a rule for a different network doesn't match."""
        client = nodes["client"]
        rule_id = 770001  # Unique ID for this test

        # Add a drop rule for a completely different network (TEST-NET-1)
        options = AddRuleOptions(
            interface=attached_ingress,
            src="192.0.2.0/24",  # TEST-NET-1, won't match client
            protocol="icmp",
            actions=[("drop", 0)],
            rule_id=rule_id,
        )
        result = policy_client.add_rule(options)
        assert result.success

        # Clear rule stats for deterministic measurement
        policy_client.clear_rule_stats(rule_id)

        # Send ICMP - should pass (rule doesn't match)
        packets_to_send = 5
        result = send_ping(
            client,
            server_ip_v4,
            count=packets_to_send,
            interface=client_interface.if_name,
        )

        # Check the specific rule's stats - should have 0 matches
        rule_stats = policy_client.get_rule_stats(rule_id)
        rule_packets = 0
        for rws in rule_stats.rules:
            if rws.rule.rule_id == rule_id and rws.stats:
                rule_packets = rws.stats.packets
                break

        logger.info(f"Non-matching rule: rule_packets={rule_packets}, expected=0")
        assert rule_packets == 0, "Rule should not have matched any packets"
        assert result.packets_received > 0, "Packets should have passed"

    def test_rule_does_not_match_different_protocol(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_network_v4,
        server_ip_v4,
        nmap_installed,
    ):
        """Test that a TCP rule doesn't match ICMP traffic."""
        client = nodes["client"]
        rule_id = 770002  # Unique ID for this test

        # Add a drop rule for TCP only
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            protocol="tcp",
            actions=[("drop", 0)],
            rule_id=rule_id,
        )
        result = policy_client.add_rule(options)
        assert result.success

        # Clear rule stats for deterministic measurement
        policy_client.clear_rule_stats(rule_id)

        # Send ICMP - should pass (rule is for TCP)
        packets_to_send = 5
        result = send_ping(
            client,
            server_ip_v4,
            count=packets_to_send,
            interface=client_interface.if_name,
        )

        # Check the specific rule's stats - should have 0 matches
        rule_stats = policy_client.get_rule_stats(rule_id)
        rule_packets = 0
        for rws in rule_stats.rules:
            if rws.rule.rule_id == rule_id and rws.stats:
                rule_packets = rws.stats.packets
                break

        logger.info(
            f"TCP rule vs ICMP traffic: rule_packets={rule_packets}, expected=0"
        )
        assert rule_packets == 0, "TCP rule should not match ICMP traffic"
        assert result.packets_received > 0, "ICMP should have passed"

    def test_rule_does_not_match_different_port(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_network_v4,
        server_ip_v4,
        nmap_installed,
    ):
        """Test that a rule for port 80 doesn't match traffic to port 443."""
        client = nodes["client"]
        rule_id = 770003  # Unique ID for this test

        # Add a drop rule for TCP port 80
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            protocol="tcp",
            dport=80,
            actions=[("drop", 0)],
            rule_id=rule_id,
        )
        result = policy_client.add_rule(options)
        assert result.success

        # Clear rule stats for deterministic measurement
        policy_client.clear_rule_stats(rule_id)

        # Send TCP to port 443 - should pass
        packets_to_send = 5
        send_tcp_syn(
            client,
            server_ip_v4,
            dest_port=443,
            count=packets_to_send,
            interface=client_interface.if_name,
        )

        # Check the specific rule's stats - should have 0 matches
        rule_stats = policy_client.get_rule_stats(rule_id)
        rule_packets = 0
        for rws in rule_stats.rules:
            if rws.rule.rule_id == rule_id and rws.stats:
                rule_packets = rws.stats.packets
                break

        logger.info(
            f"Port 80 rule vs port 443 traffic: rule_packets={rule_packets}, expected=0"
        )
        assert rule_packets == 0, "Port 80 rule should not match port 443 traffic"

    def test_ipv4_rule_does_not_match_ipv6_traffic(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        server_ip_v6,
        nmap_installed,
    ):
        """Test that an IPv4 rule doesn't match IPv6 traffic."""
        client = nodes["client"]
        rule_id = 770004  # Unique ID for this test

        # Add a drop rule for IPv4 network
        options = AddRuleOptions(
            interface=attached_ingress,
            src="10.0.0.0/8",
            protocol="icmp",
            actions=[("drop", 0)],
            rule_id=rule_id,
        )
        result = policy_client.add_rule(options)
        assert result.success

        # Clear rule stats for deterministic measurement
        policy_client.clear_rule_stats(rule_id)

        # Send ICMPv6 - should pass (rule is IPv4)
        packets_to_send = 5
        result = send_ping(
            client,
            server_ip_v6,
            count=packets_to_send,
            interface=client_interface.if_name,
        )

        # Check the specific rule's stats - should have 0 matches
        rule_stats = policy_client.get_rule_stats(rule_id)
        rule_packets = 0
        for rws in rule_stats.rules:
            if rws.rule.rule_id == rule_id and rws.stats:
                rule_packets = rws.stats.packets
                break

        logger.info(
            f"IPv4 rule vs IPv6 traffic: rule_packets={rule_packets}, expected=0"
        )
        assert rule_packets == 0, "IPv4 rule should not match IPv6 traffic"

    def test_ipv6_rule_does_not_match_ipv4_traffic(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        server_ip_v4,
        nmap_installed,
    ):
        """Test that an IPv6 rule doesn't match IPv4 traffic."""
        client = nodes["client"]
        rule_id = 770005  # Unique ID for this test

        # Add a drop rule for IPv6 network
        options = AddRuleOptions(
            interface=attached_ingress,
            src="2001:db8::/32",
            dst="::/0",
            protocol="icmp",
            actions=[("drop", 0)],
            rule_id=rule_id,
        )
        result = policy_client.add_rule(options)
        assert result.success

        # Clear rule stats for deterministic measurement
        policy_client.clear_rule_stats(rule_id)

        # Send ICMP over IPv4 - should pass (rule is IPv6)
        packets_to_send = 5
        send_ping(
            client,
            server_ip_v4,
            count=packets_to_send,
            interface=client_interface.if_name,
        )

        # Check the specific rule's stats - should have 0 matches
        rule_stats = policy_client.get_rule_stats(rule_id)
        rule_packets = 0
        for rws in rule_stats.rules:
            if rws.rule.rule_id == rule_id and rws.stats:
                rule_packets = rws.stats.packets
                break

        logger.info(
            f"IPv6 rule vs IPv4 traffic: rule_packets={rule_packets}, expected=0"
        )
        assert rule_packets == 0, "IPv6 rule should not match IPv4 traffic"

    def test_udp_rule_does_not_match_tcp_traffic(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_network_v4,
        server_ip_v4,
        nmap_installed,
    ):
        """Test that a UDP rule doesn't match TCP traffic."""
        client = nodes["client"]
        rule_id = 770006  # Unique ID for this test

        # Add a drop rule for UDP
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            protocol="udp",
            dport=8080,
            actions=[("drop", 0)],
            rule_id=rule_id,
        )
        result = policy_client.add_rule(options)
        assert result.success

        # Clear rule stats for deterministic measurement
        policy_client.clear_rule_stats(rule_id)

        # Send TCP to same port - should pass (rule is for UDP)
        packets_to_send = 5
        send_tcp_syn(
            client,
            server_ip_v4,
            dest_port=8080,
            count=packets_to_send,
            interface=client_interface.if_name,
        )

        # Check the specific rule's stats - should have 0 matches
        rule_stats = policy_client.get_rule_stats(rule_id)
        rule_packets = 0
        for rws in rule_stats.rules:
            if rws.rule.rule_id == rule_id and rws.stats:
                rule_packets = rws.stats.packets
                break

        logger.info(f"UDP rule vs TCP traffic: rule_packets={rule_packets}, expected=0")
        assert rule_packets == 0, "UDP rule should not match TCP traffic"

    def test_source_port_rule_does_not_match_wrong_sport(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_network_v4,
        server_ip_v4,
        nmap_installed,
    ):
        """Test that a rule for source port 12345 doesn't match traffic from port 54321."""
        client = nodes["client"]
        rule_id = 770007  # Unique ID for this test

        # Add a drop rule for traffic FROM source port 12345
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            protocol="tcp",
            sport=12345,
            actions=[("drop", 0)],
            rule_id=rule_id,
        )
        policy_client.add_rule(options)

        # Clear rule stats for deterministic measurement
        policy_client.clear_rule_stats(rule_id)

        # Send TCP from different source port - should pass
        packets_to_send = 5
        send_tcp_syn(
            client,
            server_ip_v4,
            dest_port=80,
            source_port=54321,  # Different from rule
            count=packets_to_send,
            interface=client_interface.if_name,
        )

        # Check the specific rule's stats - should have 0 matches
        rule_stats = policy_client.get_rule_stats(rule_id)
        rule_packets = 0
        for rws in rule_stats.rules:
            if rws.rule.rule_id == rule_id and rws.stats:
                rule_packets = rws.stats.packets
                break

        logger.info(
            f"Sport 12345 rule vs sport 54321: rule_packets={rule_packets}, expected=0"
        )
        assert rule_packets == 0, "Source port rule should not match wrong source port"


# ============================================================================
# Rule Priority/Specificity Tests
# ============================================================================


class TestRulePriority:
    """
    Test that more specific rules take precedence over less specific rules.

    Tests the scenario where:
    - Rule 1: src=<client_network>/24 dst=0.0.0.0/0 tcp dport=80 action=drop
    - Rule 2: src=0.0.0.0/0 dst=0.0.0.0/0 tcp dport=80 action=log (pass)

    Traffic from client_network should match Rule 1 (more specific) and be dropped.
    Traffic from other networks should match Rule 2 and pass/log.
    """

    @pytest.mark.parametrize("client_type", ["cli", "graphql"], indirect=True)
    def test_tcp_rule_specificity_v4(
        self,
        configure_node_interfaces,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_network_v4,
        server_ip_v4,
        nmap_installed,
    ):
        """Test TCP traffic with overlapping rules - more specific rule should match first (IPv4)."""
        client = nodes["client"]

        # Add more specific rule: drop traffic from client network to port 80
        specific_rule_id = 100001
        options_specific = AddRuleOptions(
            interface=attached_ingress,
            rule_id=specific_rule_id,
            src=client_network_v4,
            dst="0.0.0.0/0",
            protocol="tcp",
            dport=80,
            actions=[("drop", 0)],
        )
        policy_client.add_rule(options_specific)

        # Add less specific rule: log (pass) traffic from anywhere to port 80
        general_rule_id = 100002
        options_general = AddRuleOptions(
            interface=attached_ingress,
            rule_id=general_rule_id,
            src="0.0.0.0/0",
            dst="0.0.0.0/0",
            protocol="tcp",
            dport=80,
            actions=[("log", 0)],
        )
        policy_client.add_rule(options_general)

        # Clear rule stats before testing
        policy_client.clear_rule_stats(specific_rule_id)
        policy_client.clear_rule_stats(general_rule_id)

        # Send traffic from client (matches specific rule - should be dropped)
        packets_to_send = 5
        send_tcp_syn(
            client,
            server_ip_v4,
            dest_port=80,
            count=packets_to_send,
            interface=client_interface.if_name,
        )

        # Check specific rule stats - should have matched
        specific_stats = policy_client.get_rule_stats(specific_rule_id)
        specific_packets = (
            specific_stats.rules[0].stats.packets
            if specific_stats.rules and specific_stats.rules[0].stats
            else 0
        )

        logger.info(
            f"Specific rule ({client_network_v4}): matched={specific_packets}, expected={packets_to_send}"
        )
        assert specific_packets == packets_to_send, (
            f"Specific rule should match traffic from {client_network_v4}"
        )

        # Check general rule stats - should NOT have matched
        general_stats = policy_client.get_rule_stats(general_rule_id)
        general_packets = (
            general_stats.rules[0].stats.packets
            if general_stats.rules and general_stats.rules[0].stats
            else 0
        )

        logger.info(f"General rule (0.0.0.0/0): matched={general_packets}, expected=0")
        assert general_packets == 0, (
            "General rule should not match when specific rule matches"
        )

    @pytest.mark.parametrize("client_type", ["cli", "graphql"], indirect=True)
    def test_udp_rule_specificity_v4(
        self,
        configure_node_interfaces,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_network_v4,
        server_ip_v4,
        nmap_installed,
    ):
        """Test UDP traffic with overlapping rules - more specific rule should match first (IPv4)."""
        client = nodes["client"]

        # Add more specific rule: drop traffic from client network to UDP port 53
        specific_rule_id = 100003
        options_specific = AddRuleOptions(
            interface=attached_ingress,
            rule_id=specific_rule_id,
            src=client_network_v4,
            dst="0.0.0.0/0",
            protocol="udp",
            dport=53,
            actions=[("drop", 0)],
        )
        policy_client.add_rule(options_specific)

        # Add less specific rule: log (pass) traffic from anywhere to UDP port 53
        general_rule_id = 100004
        options_general = AddRuleOptions(
            interface=attached_ingress,
            rule_id=general_rule_id,
            src="0.0.0.0/0",
            dst="0.0.0.0/0",
            protocol="udp",
            dport=53,
            actions=[("log", 0)],
        )
        policy_client.add_rule(options_general)

        policy_client.clear_rule_stats(specific_rule_id)
        policy_client.clear_rule_stats(general_rule_id)

        # Send UDP from client (should match specific rule and be dropped)
        packets_to_send = 5
        send_udp_packets(
            client,
            server_ip_v4,
            dest_port=53,
            count=packets_to_send,
            interface=client_interface.if_name,
        )

        specific_stats = policy_client.get_rule_stats(specific_rule_id)
        specific_packets = (
            specific_stats.rules[0].stats.packets
            if specific_stats.rules and specific_stats.rules[0].stats
            else 0
        )

        logger.info(
            f"UDP specific rule ({client_network_v4}): matched={specific_packets}, expected={packets_to_send}"
        )
        assert specific_packets == packets_to_send, (
            f"Specific rule should match traffic from {client_network_v4}"
        )

        # Check general rule stats - should NOT have matched
        general_stats = policy_client.get_rule_stats(general_rule_id)
        general_packets = (
            general_stats.rules[0].stats.packets
            if general_stats.rules and general_stats.rules[0].stats
            else 0
        )

        logger.info(f"General rule (0.0.0.0/0): matched={general_packets}, expected=0")
        assert general_packets == 0, (
            "General rule should not match when specific rule matches"
        )

    @pytest.mark.parametrize("client_type", ["cli", "graphql"], indirect=True)
    def test_icmp_rule_specificity_v4(
        self,
        configure_node_interfaces,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_network_v4,
        server_ip_v4,
        nmap_installed,
    ):
        """Test ICMP traffic with overlapping rules - more specific rule should match first (IPv4)."""
        client = nodes["client"]

        # Add more specific rule: drop ICMP from client network
        specific_rule_id = 100005
        options_specific = AddRuleOptions(
            interface=attached_ingress,
            rule_id=specific_rule_id,
            src=client_network_v4,
            dst="0.0.0.0/0",
            protocol="icmp",
            actions=[("drop", 0)],
        )
        policy_client.add_rule(options_specific)

        # Add less specific rule: log (pass) ICMP from anywhere
        general_rule_id = 100006
        options_general = AddRuleOptions(
            interface=attached_ingress,
            rule_id=general_rule_id,
            src="0.0.0.0/0",
            dst="0.0.0.0/0",
            protocol="icmp",
            actions=[("log", 0)],
        )
        policy_client.add_rule(options_general)

        policy_client.clear_rule_stats(specific_rule_id)
        policy_client.clear_rule_stats(general_rule_id)

        # Send ICMP from client (should match specific rule)
        packets_to_send = 5
        send_ping(
            client,
            server_ip_v4,
            count=packets_to_send,
            interface=client_interface.if_name,
        )

        specific_stats = policy_client.get_rule_stats(specific_rule_id)
        specific_packets = (
            specific_stats.rules[0].stats.packets
            if specific_stats.rules and specific_stats.rules[0].stats
            else 0
        )

        logger.info(
            f"ICMP specific rule ({client_network_v4}): matched={specific_packets}, expected={packets_to_send}"
        )
        assert specific_packets == packets_to_send, (
            f"Specific rule should match traffic from {client_network_v4}"
        )

        # Check general rule stats - should NOT have matched
        general_stats = policy_client.get_rule_stats(general_rule_id)
        general_packets = (
            general_stats.rules[0].stats.packets
            if general_stats.rules and general_stats.rules[0].stats
            else 0
        )

        logger.info(f"General rule (0.0.0.0/0): matched={general_packets}, expected=0")
        assert general_packets == 0, (
            "General rule should not match when specific rule matches"
        )

    @pytest.mark.parametrize("client_type", ["cli", "graphql"], indirect=True)
    def test_tcp_rule_specificity_v6(
        self,
        configure_node_interfaces,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_network_v6,
        client_ip_v6,
        server_ip_v6,
        nmap_installed,
    ):
        """Test TCP traffic with overlapping rules - more specific rule should match first (IPv6)."""
        client = nodes["client"]

        # Add more specific rule: drop traffic from client network to port 80
        specific_rule_id = 100007
        options_specific = AddRuleOptions(
            interface=attached_ingress,
            rule_id=specific_rule_id,
            src=client_network_v6,
            dst="::/0",
            protocol="tcp",
            dport=80,
            actions=[("drop", 0)],
        )
        policy_client.add_rule(options_specific)

        # Add less specific rule: log (pass) traffic from anywhere to port 80
        # Use 2000::/3 (global unicast) instead of ::/0 to exclude link-local ND traffic
        general_rule_id = 100008
        options_general = AddRuleOptions(
            interface=attached_ingress,
            rule_id=general_rule_id,
            src="2000::/3",
            dst="::/0",
            protocol="tcp",
            dport=80,
            actions=[("log", 0)],
        )
        policy_client.add_rule(options_general)

        policy_client.clear_rule_stats(specific_rule_id)
        policy_client.clear_rule_stats(general_rule_id)

        # Send TCP from client (should match specific rule)
        packets_to_send = 5
        send_tcp_syn(
            client,
            server_ip_v6,
            dest_port=80,
            source_ip=str(client_ip_v6),
            count=packets_to_send,
            interface=client_interface.if_name,
        )

        specific_stats = policy_client.get_rule_stats(specific_rule_id)
        specific_packets = (
            specific_stats.rules[0].stats.packets
            if specific_stats.rules and specific_stats.rules[0].stats
            else 0
        )

        logger.info(
            f"TCP v6 specific rule ({client_network_v6}): matched={specific_packets}, expected={packets_to_send}"
        )
        assert specific_packets == packets_to_send, (
            f"Specific rule should match traffic from {client_network_v6}"
        )

        # Check general rule stats - should NOT have matched (ND traffic excluded by 2000::/3)
        general_stats = policy_client.get_rule_stats(general_rule_id)
        general_packets = (
            general_stats.rules[0].stats.packets
            if general_stats.rules and general_stats.rules[0].stats
            else 0
        )

        logger.info(f"General rule (2000::/3): matched={general_packets}, expected=0")
        assert general_packets == 0, (
            "General rule should not match when specific rule matches"
        )

    @pytest.mark.parametrize("client_type", ["cli", "graphql"], indirect=True)
    def test_udp_rule_specificity_v6(
        self,
        configure_node_interfaces,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_network_v6,
        client_ip_v6,
        server_ip_v6,
        nmap_installed,
    ):
        """Test UDP traffic with overlapping rules - more specific rule should match first (IPv6)."""
        client = nodes["client"]

        # Add more specific rule: drop UDP from client network to port 53
        specific_rule_id = 100009
        options_specific = AddRuleOptions(
            interface=attached_ingress,
            rule_id=specific_rule_id,
            src=client_network_v6,
            dst="::/0",
            protocol="udp",
            dport=53,
            actions=[("drop", 0)],
        )
        policy_client.add_rule(options_specific)

        # Add less specific rule: log (pass) UDP from anywhere to port 53
        # Use 2000::/3 (global unicast) instead of ::/0 to exclude link-local ND traffic
        general_rule_id = 100010
        options_general = AddRuleOptions(
            interface=attached_ingress,
            rule_id=general_rule_id,
            src="2000::/3",
            dst="::/0",
            protocol="udp",
            dport=53,
            actions=[("log", 0)],
        )
        policy_client.add_rule(options_general)

        policy_client.clear_rule_stats(specific_rule_id)
        policy_client.clear_rule_stats(general_rule_id)

        # Send UDP from client
        packets_to_send = 5
        send_udp_packets(
            client,
            server_ip_v6,
            dest_port=53,
            source_ip=str(client_ip_v6),
            count=packets_to_send,
            interface=client_interface.if_name,
        )

        specific_stats = policy_client.get_rule_stats(specific_rule_id)
        specific_packets = (
            specific_stats.rules[0].stats.packets
            if specific_stats.rules and specific_stats.rules[0].stats
            else 0
        )

        logger.info(
            f"UDP v6 specific rule ({client_network_v6}): matched={specific_packets}, expected={packets_to_send}"
        )
        assert specific_packets == packets_to_send, (
            f"Specific rule should match traffic from {client_network_v6}"
        )

        # Check general rule stats - should NOT have matched (ND traffic excluded by 2000::/3)
        general_stats = policy_client.get_rule_stats(general_rule_id)
        general_packets = (
            general_stats.rules[0].stats.packets
            if general_stats.rules and general_stats.rules[0].stats
            else 0
        )

        logger.info(f"General rule (2000::/3): matched={general_packets}, expected=0")
        assert general_packets == 0, (
            "General rule should not match when specific rule matches"
        )

    @pytest.mark.parametrize("client_type", ["cli", "graphql"], indirect=True)
    def test_icmp_rule_specificity_v6(
        self,
        configure_node_interfaces,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        client_interface,
        client_network_v6,
        server_ip_v6,
        nmap_installed,
    ):
        """Test ICMPv6 traffic with overlapping rules - more specific rule should match first (IPv6)."""
        client = nodes["client"]

        # Add more specific rule: drop ICMPv6 from client network
        specific_rule_id = 100011
        options_specific = AddRuleOptions(
            interface=attached_ingress,
            rule_id=specific_rule_id,
            src=client_network_v6,
            dst="::/0",
            protocol="icmp",
            actions=[("drop", 0)],
        )
        policy_client.add_rule(options_specific)

        # Add less specific rule: log (pass) ICMPv6 from anywhere
        # Use 2000::/3 (global unicast) instead of ::/0 to exclude link-local ND traffic
        general_rule_id = 100012
        options_general = AddRuleOptions(
            interface=attached_ingress,
            rule_id=general_rule_id,
            src="2000::/3",
            dst="::/0",
            protocol="icmp",
            actions=[("log", 0)],
        )
        policy_client.add_rule(options_general)

        policy_client.clear_rule_stats(specific_rule_id)
        policy_client.clear_rule_stats(general_rule_id)

        # Send ICMPv6 from client
        packets_to_send = 5
        send_ping(
            client,
            server_ip_v6,
            count=packets_to_send,
            interface=client_interface.if_name,
        )

        specific_stats = policy_client.get_rule_stats(specific_rule_id)
        specific_packets = (
            specific_stats.rules[0].stats.packets
            if specific_stats.rules and specific_stats.rules[0].stats
            else 0
        )

        logger.info(
            f"ICMPv6 specific rule ({client_network_v6}): matched={specific_packets}, expected>={packets_to_send}"
        )
        assert specific_packets >= packets_to_send, (
            f"Specific rule should match at least {packets_to_send} packets from {client_network_v6}, got {specific_packets}"
        )

        # Check general rule stats - should NOT have matched (ND traffic excluded by 2000::/3)
        general_stats = policy_client.get_rule_stats(general_rule_id)
        general_packets = (
            general_stats.rules[0].stats.packets
            if general_stats.rules and general_stats.rules[0].stats
            else 0
        )

        logger.info(f"General rule (2000::/3): matched={general_packets}, expected=0")
        assert general_packets == 0, (
            "General rule should not match when specific rule matches"
        )


# Rule installation performance tests have been moved to tests/policy_performance/
