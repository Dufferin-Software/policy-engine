# Copyright (c) Peter Morrow

"""
Policy Engine GraphQL client wrapper for test infrastructure.

Provides typed Python objects that mirror the policy-client JSON output,
but communicates directly with the GraphQL API instead of using the CLI.
"""

import json
import logging
from typing import Any, List, Optional

from ...node import Node
from policy_engine_client.engine.cli.client import (
    AddRuleOptions,
    BatchAddRulesResult,
    BatchDeleteRulesResult,
    EthertypeStats,
    FlowExportStatus,
    FlowVerdictEntry,
    FlowVerdictStats,
    GlobalStats,
    InspectStatus,
    InterfaceAttachment,
    InterfaceStats,
    IngressMode,
    LpmRule,
    ManagedRule,
    OperationResult,
    PolicyAction,
    Protocol,
    RuleAction,
    RuleStats,
    RuleStatsResponse,
    RuleWithStats,
    ServerFeatures,
    ServerStatus,
)

logger: logging.Logger = logging.getLogger(__name__)


class GraphQLPolicyClient:
    """
    GraphQL-based wrapper for the policy-engine API.

    Makes direct HTTP requests to the GraphQL endpoint instead of using the CLI.
    Implements the same interface as PolicyClient for test compatibility.
    """

    def __init__(
        self,
        node: Node,
        server_url: str = "http://127.0.0.1:8080/graphql",
        tls_ca_cert: Optional[str] = None,
        tls_insecure: bool = False,
    ) -> None:
        """
        Initialize the GraphQL policy client wrapper.

        Args:
            node: Node where policy-engine is running
            server_url: URL of the policy-engine GraphQL server
            tls_ca_cert: Path (on the remote node) to a PEM CA cert to trust
            tls_insecure: Skip TLS certificate verification (dev only)
        """
        self.node: Node = node
        self.server_url: str = server_url
        self.tls_ca_cert: str | None = tls_ca_cert
        self.tls_insecure: bool = tls_insecure

    def _execute_graphql(self, query: str, variables: Optional[dict] = None) -> dict:
        """
        Execute a GraphQL query/mutation via HTTP from the remote node.

        Args:
            query: GraphQL query or mutation string
            variables: Optional variables for the query

        Returns:
            The 'data' portion of the GraphQL response

        Raises:
            ValueError: If GraphQL returns errors
        """
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables

        payload_json: str = json.dumps(payload)
        logger.debug(f"[{self.node.name}] GraphQL: {query[:100]}...")

        tls_flags: str = ""
        if self.tls_ca_cert:
            tls_flags = f"--cacert {self.tls_ca_cert}"
        elif self.tls_insecure:
            tls_flags = "-k"

        # Use stdin for large payloads to avoid command-line length limits
        cmd: str
        output: str
        if len(payload_json) > 10000:
            # Use curl with stdin (-d @-)
            cmd = f"curl -s {tls_flags} -X POST -H 'Content-Type: application/json' -d @- {self.server_url}"
            output = self.node.ssh_command_with_stdin(cmd, payload_json, timeout=30)
        else:
            # For small payloads, use command line (simpler)
            payload_escaped: str = payload_json.replace(
                "'", "'\\''"
            )  # Escape single quotes
            cmd = f"curl -s {tls_flags} -X POST -H 'Content-Type: application/json' -d '{payload_escaped}' {self.server_url}"
            output = self.node.ssh_command(cmd, timeout=30)

        try:
            response = json.loads(output)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse GraphQL response: {output}")
            raise ValueError(f"Invalid JSON from GraphQL: {e}") from e

        if "errors" in response and response["errors"]:
            error_msg = response["errors"][0].get("message", str(response["errors"]))
            logger.debug(f"GraphQL error: {error_msg}")
            # Return as a failed OperationResult-like response
            return {"__error__": error_msg}

        return response.get("data", {})

    # ========================================================================
    # Status commands
    # ========================================================================

    def status(self) -> ServerStatus:
        """Get server status (base fields only)."""
        query = """
        query {
            status {
                running
                version
                uptimeSecs
                programAttached
                inspectMode
            }
        }
        """
        data = self._execute_graphql(query)
        status_data = data.get("status", {})
        return ServerStatus(
            running=status_data.get("running", False),
            version=status_data.get("version", ""),
            uptime_secs=status_data.get("uptimeSecs", 0),
            program_attached=status_data.get("programAttached", False),
            inspect_mode=status_data.get("inspectMode"),
        )

    def server_features(self) -> ServerFeatures:
        """Get server compile-time feature flags."""
        query = """
        query {
            serverFeatures {
                suricata
                ipfix
            }
        }
        """
        data = self._execute_graphql(query)
        features_data = data.get("serverFeatures", {})
        return ServerFeatures(
            suricata=features_data.get("suricata", False),
            ipfix=features_data.get("ipfix", False),
        )

    # ========================================================================
    # Attach/Detach commands
    # ========================================================================

    def attach_ingress(
        self, interface: str, mode: IngressMode = IngressMode.AUTO
    ) -> OperationResult:
        """
        Attach ingress program to an interface.

        Args:
            interface: Interface name
            mode: Ingress attach mode

        Returns:
            OperationResult indicating success/failure
        """
        mutation = """
        mutation AttachIngress($input: AttachIngressInput!) {
            attachIngress(input: $input) {
                success
                message
            }
        }
        """
        variables: dict[str, dict[str, str]] = {
            "input": {
                "interface": interface,
                "mode": mode.value,
            }
        }
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("attachIngress", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def detach_ingress(self, interface: str) -> OperationResult:
        """
        Detach ingress program from an interface.

        Args:
            interface: Interface name

        Returns:
            OperationResult indicating success/failure
        """
        mutation = """
        mutation DetachIngress($input: DetachIngressInput!) {
            detachIngress(input: $input) {
                success
                message
            }
        }
        """
        variables: dict[str, dict[str, str]] = {"input": {"interface": interface}}
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("detachIngress", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def configure_stop_behavior(self, behavior: str) -> OperationResult:
        """
        Set the daemon stop behavior.

        Args:
            behavior: "clear-state" or "preserve-state". With "preserve-state"
                the BPF programs stay attached when the daemon stops, so traffic
                continues to be enforced while it is down.

        Returns:
            OperationResult indicating success/failure
        """
        mutation = """
        mutation ConfigureStopBehavior($input: ConfigureStopBehaviorInput!) {
            configureStopBehavior(input: $input) {
                success
                message
            }
        }
        """
        variables: dict[str, dict[str, str]] = {"input": {"stopBehavior": behavior}}
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("configureStopBehavior", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def attach_egress(self, interface: str) -> OperationResult:
        """
        Attach egress program to an interface.

        Args:
            interface: Interface name

        Returns:
            OperationResult indicating success/failure
        """
        mutation = """
        mutation AttachEgress($input: AttachTcInput!) {
            attachTc(input: $input) {
                success
                message
            }
        }
        """
        variables: dict[str, dict[str, str]] = {"input": {"interface": interface}}
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("attachTc", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def detach_egress(self, interface: str) -> OperationResult:
        """
        Detach egress program from an interface.

        Args:
            interface: Interface name

        Returns:
            OperationResult indicating success/failure
        """
        mutation = """
        mutation DetachEgress($input: DetachTcInput!) {
            detachTc(input: $input) {
                success
                message
            }
        }
        """
        variables: dict[str, dict[str, str]] = {"input": {"interface": interface}}
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("detachTc", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def detach_all(self) -> OperationResult:
        """
        Detach all programs (both ingress and egress).

        Returns:
            OperationResult indicating success/failure
        """
        mutation = """
        mutation {
            detachAll {
                success
                message
            }
        }
        """
        data = self._execute_graphql(mutation)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("detachAll", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    # ========================================================================
    # Rule commands
    # ========================================================================

    def add_rule(
        self, options: AddRuleOptions, direction: str = "ingress", timeout: int = 10
    ) -> OperationResult:
        """
        Add a policy rule.

        Args:
            options: Rule configuration options
            direction: Traffic direction ("ingress" or "egress")
            timeout: Request timeout in seconds (default: 10)

        Returns:
            OperationResult indicating success/failure
        """
        mutation = """
        mutation AddRule($input: AddRuleInput!) {
            addRule(input: $input) {
                success
                message
            }
        }
        """

        # Convert actions to GraphQL format (support 2-tuple or 3-tuple with param_ms)
        gql_actions = []
        for entry in options.actions:
            action, priority = entry[0], entry[1]
            param_ms = entry[2] if len(entry) >= 3 else 0
            # Map action string to GraphQL enum value
            action_map: dict[str, str] = {
                "pass": "PASS",
                "drop": "DROP",
                "log": "LOG",
                "nat": "NAT",
                "inspect": "INSPECT",
                "tail_call": "TAIL_CALL",
                "tailcall": "TAIL_CALL",
            }
            gql_action: str = action_map.get(action.lower(), "PASS")
            gql_actions.append(
                {"action": gql_action, "priority": priority, "param": param_ms}
            )

        # Map protocol string to GraphQL string value (server expects lowercase)
        proto_map: dict[str, str] = {
            "any": "any",
            "tcp": "tcp",
            "udp": "udp",
            "icmp": "icmp",
            "icmpv6": "icmp",  # Server auto-converts to icmpv6 for IPv6 rules
        }
        gql_protocol: str = proto_map.get(options.protocol.lower(), "any")

        # Map direction string to GraphQL enum
        gql_direction: str = "INGRESS" if direction == "ingress" else "EGRESS"

        input_data: dict[str, Any] = {
            "interface": options.interface,
            "direction": gql_direction,
            "protocol": gql_protocol,
            "actions": gql_actions,
        }

        # Only include sport/dport when explicitly set — omitting them means "any
        # port", matching how the CLI omits --sport/--dport flags when the value
        # is zero.  Sending 0 would ask the server to match only port-0 traffic.
        if options.sport:
            input_data["sport"] = options.sport
        if options.dport:
            input_data["dport"] = options.dport
        if options.src:
            input_data["src"] = options.src
        if options.dst:
            input_data["dst"] = options.dst
        if options.rule_id is not None:
            input_data["id"] = str(options.rule_id)
        if options.sni:
            input_data["sni"] = options.sni
        if options.quic_version:
            input_data["quicVersion"] = options.quic_version
        if options.src_mac:
            input_data["srcMac"] = options.src_mac
        if options.dst_mac:
            input_data["dstMac"] = options.dst_mac
        if options.expires_after_secs is not None:
            input_data["expiresAfterSecs"] = options.expires_after_secs
        if options.schedule_windows:
            input_data["schedule"] = {
                "timezone": options.schedule_tz or "UTC",
                "windows": [w.to_graphql() for w in options.schedule_windows],
            }

        variables = {"input": input_data}
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("addRule", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def managed_rules(
        self, direction: str = "ingress", interface: Optional[str] = None
    ) -> List[ManagedRule]:
        """
        List rules with a TTL or schedule.

        Args:
            direction: Traffic direction ("ingress" or "egress")
            interface: Optional interface name to filter results

        Returns:
            List of ManagedRule objects
        """
        query = """
        query ManagedRules($direction: GqlDirection!) {
            managedRules(direction: $direction) {
                ruleId
                direction
                interface
                ruleState
                expiresAtMs
                schedule {
                    windows {
                        start { dayOfWeek hour minute }
                        end   { dayOfWeek hour minute }
                    }
                    timezone
                }
            }
        }
        """
        gql_direction: str = "INGRESS" if direction == "ingress" else "EGRESS"
        data = self._execute_graphql(query, {"direction": gql_direction})
        if "__error__" in data:
            return []
        raw = data.get("managedRules", [])
        rules = [ManagedRule.from_json(r) for r in raw]
        if interface is not None:
            rules = [r for r in rules if r.interface == interface]
        return rules

    def add_rules_batch(
        self, rules: List[AddRuleOptions], direction: str = "ingress"
    ) -> BatchAddRulesResult:
        """
        Add multiple policy rules in a single batch operation.

        This is more efficient than calling add_rule multiple times as it
        reduces network round-trips and allows the server to batch updates.

        Args:
            rules: List of rule configuration options
            direction: Traffic direction ("ingress" or "egress")

        Returns:
            BatchAddRulesResult with success status and per-rule results
        """
        mutation = """
        mutation AddRules($rules: [AddRuleInput!]!) {
            addRules(rules: $rules) {
                total
                succeeded
                failed
                success
                message
                results {
                    index
                    ruleId
                    success
                    error
                }
            }
        }
        """

        # Map action string to GraphQL enum value
        action_map: dict[str, str] = {
            "pass": "PASS",
            "drop": "DROP",
            "log": "LOG",
            "nat": "NAT",
            "inspect": "INSPECT",
            "tail_call": "TAIL_CALL",
            "tailcall": "TAIL_CALL",
        }

        # Map protocol string to GraphQL string value (server expects lowercase)
        proto_map: dict[str, str] = {
            "any": "any",
            "tcp": "tcp",
            "udp": "udp",
            "icmp": "icmp",
            "icmpv6": "icmp",  # Server auto-converts to icmpv6 for IPv6 rules
        }

        # Map direction string to GraphQL enum
        gql_direction: str = "INGRESS" if direction == "ingress" else "EGRESS"

        gql_rules = []
        for options in rules:
            # Convert actions to GraphQL format (support 2-tuple or 3-tuple with param_ms)
            gql_actions = []
            for entry in options.actions:
                action, priority = entry[0], entry[1]
                param_ms = entry[2] if len(entry) >= 3 else 0
                gql_action: str = action_map.get(action.lower(), "PASS")
                gql_actions.append(
                    {"action": gql_action, "priority": priority, "param": param_ms}
                )

            gql_protocol: str = proto_map.get(options.protocol.lower(), "any")

            input_data: dict[str, Any] = {
                "interface": options.interface,
                "direction": gql_direction,
                "protocol": gql_protocol,
                "actions": gql_actions,
            }

            if options.sport:
                input_data["sport"] = options.sport
            if options.dport:
                input_data["dport"] = options.dport
            if options.src:
                input_data["src"] = options.src
            if options.dst:
                input_data["dst"] = options.dst
            if options.rule_id is not None:
                input_data["id"] = str(options.rule_id)
            if options.sni:
                input_data["sni"] = options.sni
            if options.quic_version:
                input_data["quicVersion"] = options.quic_version
            if options.src_mac:
                input_data["srcMac"] = options.src_mac
            if options.dst_mac:
                input_data["dstMac"] = options.dst_mac

            gql_rules.append(input_data)

        variables = {"rules": gql_rules}
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return BatchAddRulesResult(
                total=len(rules),
                succeeded=0,
                failed=len(rules),
                success=False,
                message=data["__error__"],
                results=[],
            )

        result = data.get("addRules", {})
        return BatchAddRulesResult.from_json(result)

    def delete_rules_batch(
        self, interface: str, ids: List[int], direction: str = "ingress"
    ) -> "BatchDeleteRulesResult":
        """
        Delete multiple rules in a single batch operation via GraphQL.

        Args:
            interface: Interface the rules are scoped to (required)
            ids: List of rule IDs to delete
            direction: Traffic direction ("ingress" or "egress")

        Returns:
            BatchDeleteRulesResult with per-item results
        """
        mutation = """
        mutation DeleteRules($rules: [DeleteRuleInput!]!) {
            deleteRules(rules: $rules) {
                total
                succeeded
                failed
                success
                message
                results {
                    index
                    ruleId
                    success
                    error
                }
            }
        }
        """

        # Map direction string to GraphQL enum
        gql_direction: str = "INGRESS" if direction == "ingress" else "EGRESS"

        gql_rules = []
        for i, rid in enumerate(ids):
            gql_rules.append(
                {"interface": interface, "id": str(rid), "direction": gql_direction}
            )

        variables = {"rules": gql_rules}
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return BatchDeleteRulesResult(
                total=len(ids),
                succeeded=0,
                failed=len(ids),
                success=False,
                message=data["__error__"],
                results=[],
            )

        result = data.get("deleteRules", {})
        return BatchDeleteRulesResult.from_json(result)

    def delete_rule(
        self,
        interface: str,
        rule_id: int,
        direction: str = "ingress",
    ) -> OperationResult:
        """
        Delete a policy rule by ID.

        Args:
            interface: Interface the rule is scoped to (required)
            rule_id: Rule ID to delete (required)
            direction: Traffic direction ("ingress" or "egress")

        Returns:
            OperationResult indicating success/failure
        """
        mutation = """
        mutation DeleteRule($input: DeleteRuleInput!) {
            deleteRule(input: $input) {
                success
                message
            }
        }
        """

        # Map direction string to GraphQL enum
        gql_direction: str = "INGRESS" if direction == "ingress" else "EGRESS"

        input_data: dict[str, Any] = {
            "interface": interface,
            "direction": gql_direction,
            "id": str(rule_id),
        }

        variables: dict[str, dict[str, str]] = {"input": input_data}
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("deleteRule", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def list_rules(
        self, direction: str = "ingress", interface: Optional[str] = None
    ) -> List[LpmRule]:
        """
        List all policy rules.

        Args:
            direction: Traffic direction ("ingress" or "egress")
            interface: Optional interface name to filter results

        Returns:
            List of LpmRule objects
        """
        gql_direction: str = "INGRESS" if direction == "ingress" else "EGRESS"

        query = """
        query ListRules($direction: GqlDirection!) {
            rules(direction: $direction) {
                ruleId
                interface
                srcPrefix
                dstPrefix
                sport
                dport
                protocol
                actions {
                    action
                    priority
                    param
                }
                sni
                quicVersion
                srcMac
                dstMac
            }
        }
        """
        data = self._execute_graphql(query, {"direction": gql_direction})

        if "__error__" in data:
            return []

        rules_data = data.get("rules", [])
        rules = []
        for r in rules_data:
            if interface is not None and r.get("interface", "") != interface:
                continue
            # Convert GraphQL protocol enum to Protocol enum
            proto_str = r.get("protocol", "ANY")
            protocol: Protocol = Protocol.from_string(proto_str)

            # Convert actions
            actions = []
            for a in r.get("actions", []):
                action_str = a.get("action", "Pass")
                actions.append(
                    RuleAction(
                        action=PolicyAction.from_string(action_str),
                        priority=a.get("priority", 0),
                        param=a.get("param", 0),
                    )
                )

            # Convert ruleId (GraphQL ID scalar) to int for test consumers
            try:
                parsed_rule_id = int(r.get("ruleId", 0))
            except Exception:
                parsed_rule_id = 0

            rules.append(
                LpmRule(
                    rule_id=parsed_rule_id,
                    src_prefix=r.get("srcPrefix", "0.0.0.0/0"),
                    dst_prefix=r.get("dstPrefix", "0.0.0.0/0"),
                    sport=r.get("sport", 0),
                    dport=r.get("dport", 0),
                    protocol=protocol,
                    actions=actions,
                    sni=r.get("sni"),
                    quic_version=r.get("quicVersion"),
                    src_mac=r.get("srcMac"),
                    dst_mac=r.get("dstMac"),
                    interface=r.get("interface", ""),
                )
            )
        return rules

    def flush_rules(
        self, direction: str = "ingress", interface: Optional[str] = None
    ) -> OperationResult:
        """
        Flush policy rules scoped to a single (interface, direction).

        Args:
            direction: Traffic direction ("ingress" or "egress")
            interface: Interface name to flush. If omitted, the helper
                enumerates every interface attached in this direction and
                flushes each — convenient for tests that just want a clean
                slate on a single-interface node.

        Returns:
            OperationResult indicating success/failure
        """
        gql_direction: str = "INGRESS" if direction == "ingress" else "EGRESS"

        if interface is None:
            attachments = self.list_interfaces()
            ifaces = [
                a.interface
                for a in attachments
                if a.direction.lower() == direction.lower()
            ]
            total = 0
            for iface in ifaces:
                r = self.flush_rules(direction=direction, interface=iface)
                if not r.success:
                    return r
                total += 1
            return OperationResult(
                success=True,
                message=f"Flushed {direction} rules on {total} interface(s)",
            )

        mutation = """
        mutation FlushRules($interface: String!, $direction: GqlDirection!) {
            flushRules(interface: $interface, direction: $direction) {
                success
                message
            }
        }
        """
        data = self._execute_graphql(
            mutation, {"interface": interface, "direction": gql_direction}
        )

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("flushRules", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    # ========================================================================
    # Show commands
    # ========================================================================

    def list_interfaces(self) -> List[InterfaceAttachment]:
        """
        List attached interfaces.

        Returns:
            List of InterfaceAttachment objects
        """
        query = """
        query {
            interfaces {
                interface
                ifindex
                mode
                direction
            }
        }
        """
        data = self._execute_graphql(query)

        if "__error__" in data:
            return []

        ifaces_data = data.get("interfaces", [])
        return [
            InterfaceAttachment(
                interface=i.get("interface", ""),
                ifindex=i.get("ifindex", 0),
                mode=i.get("mode", ""),
                direction=i.get("direction", "ingress"),
            )
            for i in ifaces_data
        ]

    def get_stats(self, interface: str, direction: str = "ingress") -> InterfaceStats:
        """
        Get statistics for an interface.

        Args:
            interface: Interface name
            direction: Traffic direction ("ingress" or "egress")

        Returns:
            InterfaceStats object
        """
        gql_direction: str = "INGRESS" if direction == "ingress" else "EGRESS"

        query = """
        query GetStats($interface: String!, $direction: GqlDirection!) {
            stats(interface: $interface, direction: $direction) {
                rxPackets
                rxBytes
                txPackets
                txBytes
                policyMatches
                policyDrops
                policyPass
                policyRedirects
                parseErrors
                tailCalls
                bumPackets
                nonIpUnicast
                inspectRedirects
                fragments
                verdictPassPackets
                verdictPassBytes
                verdictDropPackets
                verdictDropBytes
                fibForwardedPackets
                fibForwardedBytes
                fibFallbackPackets
                urpfDropPackets
                urpfDropBytes
            }
            ethertypeStats(interface: $interface, direction: $direction) {
                ethertype
                name
                packets
            }
            status {
                programAttached
            }
        }
        """
        variables: dict[str, str] = {"interface": interface, "direction": gql_direction}
        data = self._execute_graphql(query, variables)

        if "__error__" in data:
            # Return empty stats on error
            return InterfaceStats(
                interface=interface,
                program_attached=False,
                global_stats=GlobalStats(
                    rx_packets=0,
                    rx_bytes=0,
                    tx_packets=0,
                    tx_bytes=0,
                    policy_matches=0,
                    policy_drops=0,
                    policy_pass=0,
                    policy_redirects=0,
                    parse_errors=0,
                    tail_calls=0,
                    bum_packets=0,
                    non_ip_unicast=0,
                    inspect_redirects=0,
                ),
                ethertype_stats=[],
            )

        stats_data = data.get("stats", {})
        ethertype_data = data.get("ethertypeStats", [])
        status_data = data.get("status", {})

        global_stats = GlobalStats(
            rx_packets=stats_data.get("rxPackets", 0),
            rx_bytes=stats_data.get("rxBytes", 0),
            tx_packets=stats_data.get("txPackets", 0),
            tx_bytes=stats_data.get("txBytes", 0),
            policy_matches=stats_data.get("policyMatches", 0),
            policy_drops=stats_data.get("policyDrops", 0),
            policy_pass=stats_data.get("policyPass", 0),
            policy_redirects=stats_data.get("policyRedirects", 0),
            parse_errors=stats_data.get("parseErrors", 0),
            tail_calls=stats_data.get("tailCalls", 0),
            bum_packets=stats_data.get("bumPackets", 0),
            non_ip_unicast=stats_data.get("nonIpUnicast", 0),
            inspect_redirects=stats_data.get("inspectRedirects", 0),
            fragments=stats_data.get("fragments", 0),
            verdict_pass_packets=stats_data.get("verdictPassPackets", 0),
            verdict_pass_bytes=stats_data.get("verdictPassBytes", 0),
            verdict_drop_packets=stats_data.get("verdictDropPackets", 0),
            verdict_drop_bytes=stats_data.get("verdictDropBytes", 0),
            fib_forwarded_packets=stats_data.get("fibForwardedPackets", 0),
            fib_forwarded_bytes=stats_data.get("fibForwardedBytes", 0),
            fib_fallback_packets=stats_data.get("fibFallbackPackets", 0),
            urpf_drop_packets=stats_data.get("urpfDropPackets", 0),
            urpf_drop_bytes=stats_data.get("urpfDropBytes", 0),
        )

        ethertype_stats: List[EthertypeStats] = [
            EthertypeStats(
                ethertype=e.get("ethertype", 0),
                ethertype_hex="",
                name=e.get("name", ""),
                packets=e.get("packets", 0),
            )
            for e in ethertype_data
        ]

        return InterfaceStats(
            interface=interface,
            program_attached=status_data.get("programAttached", False),
            global_stats=global_stats,
            ethertype_stats=ethertype_stats,
        )

    def get_rule_stats(
        self, rule_id: Optional[int] = None, direction: str = "ingress"
    ) -> RuleStatsResponse:
        """
        Get rule statistics.

        Args:
            rule_id: Optional rule ID (all rules if not specified)
            direction: Traffic direction ("ingress" or "egress")

        Returns:
            RuleStatsResponse object
        """
        gql_direction: str = "INGRESS" if direction == "ingress" else "EGRESS"

        if rule_id is not None:
            # Get stats for specific rule - note: ruleId is required (not optional)
            query = """
            query GetRuleStats($ruleId: String!, $direction: GqlDirection!) {
                ruleStats(ruleId: $ruleId, direction: $direction) {
                    packets
                    bytes
                    lastSeenNs
                }
                rules(direction: $direction) {
                    ruleId
                    srcPrefix
                    dstPrefix
                    sport
                    dport
                    protocol
                    actions {
                        action
                        priority
                    }
                }
                status {
                    programAttached
                }
            }
            """
            variables = {"ruleId": str(rule_id), "direction": gql_direction}
        else:
            # Get all rules with their stats
            query = """
            query GetAllRuleStats($direction: GqlDirection!) {
                rules(direction: $direction) {
                    ruleId
                    srcPrefix
                    dstPrefix
                    sport
                    dport
                    protocol
                    actions {
                        action
                        priority
                    }
                }
                status {
                    programAttached
                }
            }
            """
            variables = {"direction": gql_direction}

        data = self._execute_graphql(query, variables)

        if "__error__" in data:
            return RuleStatsResponse(program_attached=False, rules=[])

        status_data = data.get("status", {})
        rules_data = data.get("rules", [])

        rules_with_stats = []
        for r in rules_data:
            # Convert returned ruleId to int for comparisons
            try:
                parsed_rid = int(r.get("ruleId"))
            except Exception:
                parsed_rid = None

            # Skip rules that don't match if we're filtering by rule_id
            if rule_id is not None and parsed_rid != rule_id:
                continue

            # Convert rule data
            proto_str = r.get("protocol", "ANY")
            protocol: Protocol = Protocol.from_string(proto_str)

            actions = []
            for a in r.get("actions", []):
                action_str = a.get("action", "Pass")
                actions.append(
                    RuleAction(
                        action=PolicyAction.from_string(action_str),
                        priority=a.get("priority", 0),
                    )
                )

            rule = LpmRule(
                rule_id=parsed_rid if parsed_rid is not None else 0,
                src_prefix=r.get("srcPrefix", "0.0.0.0/0"),
                dst_prefix=r.get("dstPrefix", "0.0.0.0/0"),
                sport=r.get("sport", 0),
                dport=r.get("dport", 0),
                protocol=protocol,
                actions=actions,
            )

            # Get stats for this rule
            stats = None
            if rule_id is not None:
                # Use the ruleStats from the query for the specific rule
                stats_data = data.get("ruleStats")
                if stats_data:
                    stats = RuleStats(
                        packets=stats_data.get("packets", 0),
                        bytes=stats_data.get("bytes", 0),
                        last_seen_ns=stats_data.get("lastSeenNs", 0),
                    )
            else:
                # Query stats individually for each rule
                rule_stats_data = self._get_single_rule_stats(r.get("ruleId", 0))
                if rule_stats_data:
                    stats = RuleStats(
                        packets=rule_stats_data.get("packets", 0),
                        bytes=rule_stats_data.get("bytes", 0),
                        last_seen_ns=rule_stats_data.get("lastSeenNs", 0),
                    )

            rules_with_stats.append(RuleWithStats(rule=rule, stats=stats))

        return RuleStatsResponse(
            program_attached=status_data.get("programAttached", False),
            rules=rules_with_stats,
        )

    def _get_single_rule_stats(
        self, rule_id: int, direction: str = "ingress"
    ) -> Optional[dict]:
        """Get stats for a single rule."""
        gql_direction: str = "INGRESS" if direction == "ingress" else "EGRESS"

        query = """
        query GetRuleStats($ruleId: String!, $direction: GqlDirection!) {
            ruleStats(ruleId: $ruleId, direction: $direction) {
                packets
                bytes
                lastSeenNs
            }
        }
        """
        variables: dict[str, str] = {"ruleId": str(rule_id), "direction": gql_direction}
        data = self._execute_graphql(query, variables)
        return data.get("ruleStats")

    # ========================================================================
    # Config commands
    # ========================================================================

    def set_default_action(
        self, action: PolicyAction, direction: str = "ingress", interface: str = ""
    ) -> OperationResult:
        """
        Set the default action for unmatched packets.

        Args:
            action: Default action
            direction: Traffic direction ("ingress" or "egress")
            interface: Interface name (required by server)

        Returns:
            OperationResult indicating success/failure
        """
        mutation = """
        mutation SetDefaultAction($input: DefaultActionInput!) {
            setDefaultAction(input: $input) {
                success
                message
            }
        }
        """
        # Map action to GraphQL enum
        action_map: dict[PolicyAction, str] = {
            PolicyAction.PASS: "PASS",
            PolicyAction.DROP: "DROP",
            PolicyAction.LOG: "LOG",
            PolicyAction.NAT: "NAT",
        }
        gql_action: str = action_map.get(action, "PASS")
        gql_direction: str = "INGRESS" if direction == "ingress" else "EGRESS"

        variables: dict[str, dict[str, str]] = {
            "input": {
                "interface": interface,
                "action": gql_action,
                "direction": gql_direction,
            }
        }
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("setDefaultAction", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def get_default_action(self, interface: str, direction: str = "ingress") -> str:
        """
        Query the current default action for a specific interface+direction.

        Returns "PASS" or "DROP". Returns "PASS" when no explicit default has been set,
        or on error.
        """
        gql_direction: str = "INGRESS" if direction == "ingress" else "EGRESS"
        query = """
        query DefaultAction($interface: String!, $direction: GqlDirection!) {
            defaultAction(interface: $interface, direction: $direction)
        }
        """
        data = self._execute_graphql(
            query, {"interface": interface, "direction": gql_direction}
        )
        if "__error__" in data:
            return "PASS"
        return data.get("defaultAction", "PASS")

    def register_tail_call(
        self, slot: int, program: str, direction: str = "ingress"
    ) -> OperationResult:
        """
        Register a tail call program.

        Args:
            slot: Slot number (0-63)
            program: Program name
            direction: Traffic direction ("ingress" or "egress")

        Returns:
            OperationResult indicating success/failure
        """
        mutation = """
        mutation RegisterTailCall($input: TailCallInput!) {
            registerTailCall(input: $input) {
                success
                message
            }
        }
        """
        gql_direction: str = "INGRESS" if direction == "ingress" else "EGRESS"
        variables = {
            "input": {"slot": slot, "program": program, "direction": gql_direction}
        }
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("registerTailCall", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    # ========================================================================
    # Clear stats commands
    # ========================================================================

    def clear_global_stats(
        self, interface: str, direction: str = "ingress"
    ) -> OperationResult:
        """
        Clear global statistics for an interface.

        Args:
            interface: Interface name
            direction: Traffic direction ("ingress" or "egress")

        Returns:
            OperationResult indicating success/failure
        """
        gql_direction: str = "INGRESS" if direction == "ingress" else "EGRESS"

        mutation = """
        mutation ClearGlobalStats($interface: String!, $direction: GqlDirection!) {
            clearGlobalStats(interface: $interface, direction: $direction) {
                success
                message
            }
        }
        """
        variables: dict[str, str] = {"interface": interface, "direction": gql_direction}
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("clearGlobalStats", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def clear_interface_stats(
        self, interface: str, direction: str = "ingress"
    ) -> OperationResult:
        """
        Clear all statistics for an interface (global + ethertype).

        Args:
            interface: Interface name
            direction: Traffic direction ("ingress" or "egress")

        Returns:
            OperationResult indicating success/failure
        """
        gql_direction: str = "INGRESS" if direction == "ingress" else "EGRESS"

        mutation = """
        mutation ClearInterfaceStats($interface: String!, $direction: GqlDirection!) {
            clearInterfaceStats(interface: $interface, direction: $direction) {
                success
                message
            }
        }
        """
        variables: dict[str, str] = {"interface": interface, "direction": gql_direction}
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("clearInterfaceStats", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def clear_rule_stats(
        self, rule_id: Optional[int] = None, direction: str = "ingress"
    ) -> OperationResult:
        """
        Clear rule statistics.

        Args:
            rule_id: Optional rule ID (clears all rules if not specified)
            direction: Traffic direction ("ingress" or "egress")

        Returns:
            OperationResult indicating success/failure
        """
        gql_direction: str = "INGRESS" if direction == "ingress" else "EGRESS"

        if rule_id is not None:
            mutation = """
            mutation ClearRuleStats($ruleId: String!, $direction: GqlDirection!) {
                clearRuleStats(ruleId: $ruleId, direction: $direction) {
                    success
                    message
                }
            }
            """
            variables: dict[str, str] = {
                "ruleId": str(rule_id),
                "direction": gql_direction,
            }
            data = self._execute_graphql(mutation, variables)

            if "__error__" in data:
                return OperationResult(success=False, message=data["__error__"])

            result = data.get("clearRuleStats", {})
        else:
            mutation = """
            mutation ClearAllRuleStats($direction: GqlDirection!) {
                clearAllRuleStats(direction: $direction) {
                    success
                    message
                }
            }
            """
            data = self._execute_graphql(mutation, {"direction": gql_direction})

            if "__error__" in data:
                return OperationResult(success=False, message=data["__error__"])

            result = data.get("clearAllRuleStats", {})

        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def clear_ethertype_stats(
        self, interface: str, direction: str = "ingress"
    ) -> OperationResult:
        """
        Clear ethertype statistics for an interface.

        Args:
            interface: Interface name
            direction: Traffic direction ("ingress" or "egress")

        Returns:
            OperationResult indicating success/failure
        """
        gql_direction: str = "INGRESS" if direction == "ingress" else "EGRESS"

        mutation = """
        mutation ClearEthertypeStats($interface: String!, $direction: GqlDirection!) {
            clearEthertypeStats(interface: $interface, direction: $direction) {
                success
                message
            }
        }
        """
        variables: dict[str, str] = {"interface": interface, "direction": gql_direction}
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("clearEthertypeStats", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def clear_all_stats(self) -> OperationResult:
        """
        Clear all statistics.

        Returns:
            OperationResult indicating success/failure
        """
        mutation = """
        mutation {
            clearAllStats {
                success
                message
            }
        }
        """
        data = self._execute_graphql(mutation)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("clearAllStats", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    # ========================================================================
    # Inspect/IPS commands
    # ========================================================================

    def get_inspect_status(self) -> InspectStatus:
        """Get inspect/IPS mode status."""
        query = """
        query {
            inspectStatus {
                mode
                suricataRunning
                mirrorInterface
                mirrorIfindex
                peerInterface
                flowVerdictCount
                suricataVersion
                rulesetVersion
            }
        }
        """
        data = self._execute_graphql(query)

        if "__error__" in data:
            return InspectStatus(
                mode="DISABLED",
                suricata_running=False,
                mirror_interface=None,
                mirror_ifindex=None,
                peer_interface=None,
                flow_verdict_count=0,
            )

        d = data.get("inspectStatus", {})
        return InspectStatus(
            mode=d.get("mode", "DISABLED"),
            suricata_running=d.get("suricataRunning", False),
            mirror_interface=d.get("mirrorInterface"),
            mirror_ifindex=d.get("mirrorIfindex"),
            peer_interface=d.get("peerInterface"),
            flow_verdict_count=d.get("flowVerdictCount", 0),
            suricata_version=d.get("suricataVersion"),
            ruleset_version=d.get("rulesetVersion"),
        )

    def configure_inspect(self, mode: str) -> OperationResult:
        """
        Enable inspect mode (IPS or IDS).

        Args:
            mode: Inspect mode string ("ips" or "ids")
        """
        gql_mode: str = mode.upper()
        mutation = """
        mutation ConfigureInspect($input: ConfigureInspectInput!) {
            configureInspect(input: $input) {
                success
                message
            }
        }
        """
        variables: dict[str, dict[str, str]] = {"input": {"mode": gql_mode}}
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("configureInspect", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def disable_inspect(self) -> OperationResult:
        """Disable inspect mode."""
        mutation = """
        mutation {
            disableInspect {
                success
                message
            }
        }
        """
        data = self._execute_graphql(mutation)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("disableInspect", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def get_flow_verdicts(self, direction: str = "ingress") -> FlowVerdictStats:
        """
        Get flow verdict statistics for a direction.

        Args:
            direction: Traffic direction ("ingress" or "egress")
        """
        gql_direction: str = "INGRESS" if direction.lower() == "ingress" else "EGRESS"
        query = """
        query FlowVerdicts($direction: GqlDirection!) {
            flowVerdicts(direction: $direction) {
                activeVerdicts
            }
        }
        """
        variables: dict[str, str] = {"direction": gql_direction}
        data = self._execute_graphql(query, variables)

        if "__error__" in data:
            return FlowVerdictStats(active_verdicts=0)

        d = data.get("flowVerdicts", {})
        return FlowVerdictStats(
            active_verdicts=d.get("activeVerdicts", 0),
        )

    def list_flow_verdicts(
        self, direction: str = "ingress", limit: int | None = None
    ) -> list[FlowVerdictEntry]:
        """
        List individual cached flow verdict entries for a direction.

        Entries come back soonest-expiring first, capped server-side at
        ``limit`` (default 1000 when ``None``).

        Args:
            direction: Traffic direction ("ingress" or "egress")
            limit: Max entries to return (None = server default)
        """
        gql_direction: str = "INGRESS" if direction.lower() == "ingress" else "EGRESS"
        query = """
        query FlowVerdictList($direction: GqlDirection!, $limit: Int) {
            flowVerdictList(direction: $direction, limit: $limit) {
                srcIp dstIp srcPort dstPort protocol action
                expiresNs expired packets bytes
            }
        }
        """
        variables: dict = {"direction": gql_direction, "limit": limit}
        data = self._execute_graphql(query, variables)

        if "__error__" in data:
            return []

        return [
            FlowVerdictEntry.from_json(e) for e in data.get("flowVerdictList", []) or []
        ]

    def clear_flow_verdicts(self, direction: str = "ingress") -> OperationResult:
        """
        Clear all flow verdicts for a direction.

        Args:
            direction: Traffic direction ("ingress" or "egress")
        """
        gql_direction: str = "INGRESS" if direction.lower() == "ingress" else "EGRESS"
        mutation = """
        mutation ClearFlowVerdicts($direction: GqlDirection!) {
            clearFlowVerdicts(direction: $direction) {
                success
                message
            }
        }
        """
        variables: dict[str, str] = {"direction": gql_direction}
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("clearFlowVerdicts", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    # ========================================================================
    # FIB forwarding
    # ========================================================================

    def set_fib_forwarding(self, interface: str, enabled: bool) -> OperationResult:
        """
        Enable or disable XDP FIB forwarding on an ingress interface.

        Args:
            interface: Name of the ingress interface
            enabled: True to enable FIB forwarding, False to disable
        """
        mutation = """
        mutation SetFibForwarding($input: SetFibForwardingInput!) {
            setFibForwarding(input: $input) {
                success
                message
            }
        }
        """
        variables = {"input": {"interface": interface, "enabled": enabled}}
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("setFibForwarding", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def get_fib_forwarding(self, interface: str) -> bool:
        """
        Query whether XDP FIB forwarding is enabled on a specific interface.
        """
        entries = self.list_fib_forwarding()
        for iface, enabled in entries:
            if iface == interface:
                return enabled
        return False

    def list_fib_forwarding(self) -> list[tuple[str, bool]]:
        """Return [(interface, enabled), ...] for every interface with a FIB config."""
        query = """
        query {
            fibForwarding {
                interface
                enabled
            }
        }
        """
        data = self._execute_graphql(query)
        if "__error__" in data:
            return []
        return [
            (entry.get("interface", ""), entry.get("enabled", False))
            for entry in data.get("fibForwarding", [])
        ]

    # ========================================================================
    # uRPF (unicast Reverse Path Forwarding)
    # ========================================================================

    def set_urpf(self, interface: str, mode: str) -> OperationResult:
        """
        Set the uRPF mode on an ingress interface.

        Args:
            interface: Name of the ingress interface
            mode: One of "OFF", "LOOSE", or "STRICT" (case-insensitive)
        """
        mutation = """
        mutation SetUrpf($input: SetUrpfInput!) {
            setUrpf(input: $input) {
                success
                message
            }
        }
        """
        variables = {"input": {"interface": interface, "mode": mode.upper()}}
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("setUrpf", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def get_urpf(self, interface: str) -> str:
        """Query the uRPF mode for a specific interface. Returns "OFF" if unset."""
        for iface, mode in self.list_urpf():
            if iface == interface:
                return mode
        return "OFF"

    def list_urpf(self) -> list[tuple[str, str]]:
        """Return [(interface, mode), ...] for every interface with uRPF enabled."""
        query = """
        query {
            urpf {
                interface
                mode
            }
        }
        """
        data = self._execute_graphql(query)
        if "__error__" in data:
            return []
        return [
            (entry.get("interface", ""), entry.get("mode", "OFF"))
            for entry in data.get("urpf", [])
        ]

    # ========================================================================
    # Suricata commands
    # ========================================================================

    def suricata_status(self) -> OperationResult:
        """Get Suricata service status. success=True means Suricata is running."""
        query = """
        query {
            suricataStatus {
                success
                message
            }
        }
        """
        data = self._execute_graphql(query)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("suricataStatus", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def deploy_suricata_rules(
        self, rules_text: str, filename: str = "custom.rules"
    ) -> OperationResult:
        """
        Deploy Suricata rules to the server via GraphQL.

        Args:
            rules_text: Suricata rules content
            filename: Target filename in the Suricata rules directory
        """
        mutation = """
        mutation DeploySuricataRules($input: DeploySuricataRulesInput!) {
            deploySuricataRules(input: $input) {
                success
                message
            }
        }
        """
        variables: dict[str, dict[str, str]] = {
            "input": {"rules": rules_text, "filename": filename}
        }
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("deploySuricataRules", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def reload_suricata_rules(self) -> OperationResult:
        """Reload Suricata rules."""
        mutation = """
        mutation {
            reloadSuricataRules {
                success
                message
            }
        }
        """
        data = self._execute_graphql(mutation)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("reloadSuricataRules", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    # ========================================================================
    # IPFIX flow export commands
    # ========================================================================

    def configure_flow_export(
        self,
        enabled: bool,
        collector_host: str = "127.0.0.1",
        collector_port: int = 4739,
        idle_timeout_s: int = 15,
        active_timeout_s: int = 60,
    ) -> OperationResult:
        """Configure IPFIX flow export."""
        mutation = """
        mutation ConfigureFlowExport($input: ConfigureFlowExportInput!) {
            configureFlowExport(input: $input) {
                success
                message
            }
        }
        """
        variables = {
            "input": {
                "enabled": enabled,
                "collectorHost": collector_host,
                "collectorPort": collector_port,
                "idleTimeoutS": idle_timeout_s,
                "activeTimeoutS": active_timeout_s,
            }
        }
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("configureFlowExport", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def get_flow_export_status(self) -> FlowExportStatus:
        """Get current IPFIX flow export status and configuration."""
        query = """
        query {
            flowExportStatus {
                enabled
                collectorHost
                collectorPort
                idleTimeoutS
                activeTimeoutS
                flowsExportedTotal
                activeFlowCount
            }
        }
        """
        data = self._execute_graphql(query)

        if "__error__" in data:
            return FlowExportStatus(
                enabled=False,
                collector_host="",
                collector_port=0,
                idle_timeout_s=0,
                active_timeout_s=0,
                flows_exported_total=0,
                active_flow_count=0,
            )

        d = data.get("flowExportStatus", {})
        return FlowExportStatus.from_json(d)


def create_graphql_policy_client(node: Node) -> GraphQLPolicyClient:
    """
    Create a GraphQLPolicyClient for a node.

    Args:
        node: Node where policy-engine is running

    Returns:
        GraphQLPolicyClient instance
    """
    return GraphQLPolicyClient(node)
