# Copyright (c) Peter Morrow

"""
LPM covering-prefix fallback tests.

Verifies that when the most-specific LPM prefix has no matching L4 rule the
engine walks up to the next less-specific covering prefix rather than falling
through to the global default action.

Scenario
--------
Two ingress rules are installed on the server's XDP interface:

  Rule A  src=10.0.0.0/8  any proto  → DROP  (priority 100)
  Rule B  src=10.1.1.0/24 TCP/22    → PASS  (priority 10)

The client IP lives in 10.1.1.0/24 (which is also within 10.0.0.0/8).
The global default action is PASS throughout.

Expected behaviour
------------------
* TCP/22 from client  →  /24 entry matches, Rule B passes the packet.
* TCP/80 from client  →  /24 entry matches but TCP/22 rule misses; engine
                          walks up to /8 entry, Rule A drops the packet.
                          Crucially, the global default-PASS is NOT reached.
"""

import logging

import netaddr

from netsim.testkit.nping_utils import send_tcp_syn
from policy_engine_client.engine.cli.client import AddRuleOptions

logger = logging.getLogger(__name__)

# Well-known ports used in the tests.
PORT_SSH = 22  # matches Rule B → PASS
PORT_HTTP = 80  # does not match Rule B; should fall back to Rule A → DROP
PACKETS = 5


def _covering_prefix(network_str: str) -> str:
    """Return the /8 covering prefix for a given network string.

    e.g. '10.1.1.0/24' → '10.0.0.0/8'
    """
    net = netaddr.IPNetwork(network_str)
    first_octet = net.network.words[0]
    return f"{first_octet}.0.0.0/8"


class TestLpmFallback:
    """Covering-prefix fallback: unmatched /24 rules escalate to /8 rules."""

    def _install_rules(
        self, policy_client, client_network_v4: str, interface: str
    ) -> str:
        """Install Rule A (covering /8 DROP) and Rule B (specific /24 TCP/22 PASS).

        Returns the covering prefix string for use in log messages.
        """
        covering = _covering_prefix(client_network_v4)

        # Rule A: broad DROP on the /8 covering prefix
        result = policy_client.add_rule(
            AddRuleOptions(
                interface=interface,
                src=covering,
                protocol="any",
                actions=[("drop", 100)],
                rule_id=1001,
            ),
            direction="ingress",
        )
        assert result.success, (
            f"Failed to add covering-prefix DROP rule: {result.message}"
        )

        # Rule B: narrow PASS for TCP/22 at the /24 level
        result = policy_client.add_rule(
            AddRuleOptions(
                interface=interface,
                src=client_network_v4,
                protocol="tcp",
                dport=PORT_SSH,
                actions=[("pass", 10)],
                rule_id=1002,
            ),
            direction="ingress",
        )
        assert result.success, (
            f"Failed to add specific-prefix PASS rule: {result.message}"
        )

        logger.info(
            f"Rules installed: covering={covering} → DROP, "
            f"specific={client_network_v4} TCP/{PORT_SSH} → PASS"
        )
        return covering

    def test_fallback_to_covering_prefix_drops_unmatched_port(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        server_interface,
        server_ip_v4,
        client_ip_v4,
        client_network_v4,
        nmap_installed,
    ):
        """TCP/80 from the client falls back from the /24 entry to the /8 DROP rule.

        The default action is PASS, so any drop must come from the covering-prefix rule,
        confirming that the engine consulted the /8 entry rather than using the default.
        """
        client = nodes["client"]
        covering = self._install_rules(
            policy_client, client_network_v4, attached_ingress
        )

        initial_stats = policy_client.get_stats(attached_ingress, direction="ingress")
        initial_drops = initial_stats.global_stats.policy_drops

        send_tcp_syn(
            client,
            server_ip_v4,
            dest_port=PORT_HTTP,
            count=PACKETS,
        )

        final_stats = policy_client.get_stats(attached_ingress, direction="ingress")
        drops_delta = final_stats.global_stats.policy_drops - initial_drops

        logger.info(
            f"TCP/{PORT_HTTP} from {client_ip_v4} (in {client_network_v4}): "
            f"covering prefix={covering}, drops_delta={drops_delta}, expected={PACKETS}"
        )
        assert drops_delta == PACKETS, (
            f"Expected {PACKETS} drops via covering-prefix Rule A, got {drops_delta}. "
            f"Default action is PASS so any drop proves fallback to {covering} worked."
        )

    def test_specific_prefix_rule_passes_matching_traffic(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        server_interface,
        server_ip_v4,
        client_ip_v4,
        client_network_v4,
        nmap_installed,
    ):
        """TCP/22 from the client is passed by Rule B at the /24 level.

        Confirms that when the most-specific prefix does have a matching L4 rule the
        engine applies it directly and does not consult the /8 covering DROP rule.
        """
        client = nodes["client"]
        self._install_rules(policy_client, client_network_v4, attached_ingress)

        initial_stats = policy_client.get_stats(attached_ingress, direction="ingress")
        initial_drops = initial_stats.global_stats.policy_drops

        send_tcp_syn(
            client,
            server_ip_v4,
            dest_port=PORT_SSH,
            count=PACKETS,
        )

        final_stats = policy_client.get_stats(attached_ingress, direction="ingress")
        drops_delta = final_stats.global_stats.policy_drops - initial_drops

        logger.info(
            f"TCP/{PORT_SSH} from {client_ip_v4}: drops_delta={drops_delta}, expected=0"
        )
        assert drops_delta == 0, (
            f"Expected 0 drops for TCP/{PORT_SSH} (Rule B PASS at /24 level), got {drops_delta}"
        )

    def test_covering_prefix_drop_not_bypassed_by_default_pass(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        server_interface,
        server_ip_v4,
        client_ip_v4,
        client_network_v4,
        nmap_installed,
    ):
        """Explicitly set default=PASS; TCP/80 still drops via the /8 covering rule.

        This distinguishes a covering-prefix DROP from the default action: even though
        the default would allow the traffic, the /8 ancestor entry is consulted first
        and its DROP takes effect.
        """
        from policy_engine_client.engine.cli.client import PolicyAction

        client = nodes["client"]
        covering = self._install_rules(
            policy_client, client_network_v4, attached_ingress
        )

        # Ensure default is PASS (clean_ingress_rules already does this, but be explicit)
        result = policy_client.set_default_action(
            PolicyAction.PASS, direction="ingress", interface=attached_ingress
        )
        assert result.success, "Failed to set default action to PASS"

        initial_stats = policy_client.get_stats(attached_ingress, direction="ingress")
        initial_drops = initial_stats.global_stats.policy_drops

        send_tcp_syn(
            client,
            server_ip_v4,
            dest_port=PORT_HTTP,
            count=PACKETS,
        )

        final_stats = policy_client.get_stats(attached_ingress, direction="ingress")
        drops_delta = final_stats.global_stats.policy_drops - initial_drops

        logger.info(
            f"TCP/{PORT_HTTP} with default=PASS: covering={covering}, "
            f"drops_delta={drops_delta}, expected={PACKETS}"
        )
        assert drops_delta >= PACKETS, (
            f"Expected at least {PACKETS} drops even with default=PASS: "
            f"the covering prefix {covering} DROP rule should be applied "
            f"before the default action is reached. Got {drops_delta} drops."
        )
