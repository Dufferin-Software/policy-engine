# Copyright (c) Dufferin Software

"""
Policy Controller GraphQL client for multi-node integration tests.

Executes GraphQL queries against the policy-controller HTTP API by running
curl commands on the controller VM via SSH — the same pattern used by
GraphQLPolicyClient for the policy-engine.
"""

import json
import logging
from dataclasses import dataclass
from typing import Any, List, Optional

from ...node import Node

logger: logging.Logger = logging.getLogger(__name__)

_CONTROLLER_URL = "http://127.0.0.1:8443/graphql"


def mint_api_token(
    controller_node: Node,
    name: str,
    *,
    tenant_id: int = 1,
    roles: tuple = ("admin",),
) -> str:
    """
    Mint a bearer token on the controller VM via SSH.

    `policy-controller-mint-token` defaults to **no roles** — a freshly minted
    static token has zero permissions until the caller explicitly opts in (see
    `mint_token.rs` for the reasoning). Netsim's integration tests always want
    a fully-permissioned token to drive the GraphQL surface, so this helper
    defaults `roles=("admin",)`. Pass `tenant_id=` to bind the token to a
    non-default tenant (e.g. the second tenant created by `bootstrap_tenant`).

    The plaintext is printed to stdout by the binary (the confirmation prose
    goes to stderr), so capturing stdout gives the token cleanly. Subsequent
    test runs will reuse the same controller DB; we add a per-call epoch
    suffix to `name` upstream when collisions matter.
    """
    role_args = " ".join(f"--role {r}" for r in roles)
    # Capture stderr alongside stdout so a failed mint surfaces a useful
    # message ("command not found", "database is locked", etc.) instead of
    # an opaque CalledProcessError.
    out: str = controller_node.ssh_command(
        f"sudo policy-controller-mint-token --name '{name}' "
        f"--tenant-id {tenant_id} {role_args} 2>&1",
        timeout=15,
    )
    token: str = ""
    for line in out.strip().splitlines():
        line = line.strip()
        if line.startswith("dsw_"):
            token = line
            break
    if not token:
        raise RuntimeError(
            f"policy-controller-mint-token did not return a dsw_ token; "
            f"output was: {out!r}"
        )
    return token


def bootstrap_tenant(controller_node: Node, slug: str, name: str) -> int:
    """
    Provision a tenant on the controller and return its numeric id.

    Wraps `policy-controller-bootstrap-tenant`, which inserts a `tenants` row
    (idempotent on slug) and seeds the six built-in roles for the new id.
    The id is printed to stdout on its own line so we can pipe it into a
    subsequent `mint_api_token(tenant_id=…)` call.
    """
    out: str = controller_node.ssh_command(
        f"sudo policy-controller-bootstrap-tenant --slug '{slug}' --name '{name}' 2>&1",
        timeout=15,
    )
    for line in out.strip().splitlines():
        line = line.strip()
        if line.isdigit():
            return int(line)
    raise RuntimeError(
        f"policy-controller-bootstrap-tenant did not print a tenant id; "
        f"output was: {out!r}"
    )


@dataclass
class ControlledNode:
    id: str
    status: str
    label: Optional[str] = None
    hostname: Optional[str] = None
    dmi_uuid: Optional[str] = None
    tpm_backed: bool = False
    agent_version: Optional[str] = None
    # Hex-encoded mTLS client cert serial. Populated once the node is approved;
    # None for pending nodes.
    cert_serial: Optional[str] = None
    # ISO-8601 timestamp of cert expiry; populated alongside cert_serial.
    cert_expiry: Optional[str] = None
    # ISO-8601 timestamp of the most recent successful RenewClientCert.
    # None until the first renewal — used by the rotation suite to detect that
    # the agent-side renewal task fired (the cert_serial flip is the canonical
    # signal, but last_renewed_at is more readable in logs/asserts).
    last_renewed_at: Optional[str] = None
    # Operator-configured metrics scrape/forward interval in seconds.
    # None means no override (the agent uses its local default).
    metrics_interval_secs: Optional[int] = None


@dataclass
class IssuedEnrollmentToken:
    """Result of minting a ZTP bootstrap token. The bundle is shown exactly once."""

    token_id: str
    bundle: str  # base64-encoded bootstrap bundle written to /etc/policy-node-agent/bootstrap.bundle
    expires_at: str
    uses_remaining: int


@dataclass
class Ruleset:
    id: str
    name: str
    rules_json: str
    description: Optional[str] = None
    default_action_ingress: Optional[str] = None
    default_action_egress: Optional[str] = None


@dataclass
class NodeInterface:
    node_id: str
    name: str
    # Linux interface index. 0 if the controller has not yet received an
    # interface report from the agent that carried it (older controllers/agents
    # also report 0). Matches `ifindex` on persisted flow events so callers can
    # join (node_id, ifindex) → name.
    ifindex: int = 0
    mac_address: Optional[str] = None
    link_state: str = "unknown"
    addresses_json: str = "[]"
    tag: Optional[str] = None
    xdp_attached: bool = False
    tc_attached: bool = False
    fib_forwarding: bool = False
    urpf_mode: str = "off"
    ingress_default_action: Optional[str] = None
    egress_default_action: Optional[str] = None


@dataclass
class NodeFlowVerdict:
    """A single cached flow verdict entry read live from a node's BPF cache."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    action: str
    expires_ns: str
    expired: bool
    packets: int
    bytes: int


@dataclass
class PersistedEvent:
    """One row from the controller's persisted policy-event store."""

    id: str
    timestamp: str  # ISO-8601 from the controller
    node_id: str
    rule_id: str
    action: str
    verdict: str
    direction: str
    ifindex: int
    proto: int
    src_ip: str
    dst_ip: str
    sport: int
    dport: int
    pkt_len: int
    sni: Optional[str] = None


@dataclass
class OperationResult:
    success: bool
    message: Optional[str] = None


@dataclass
class NodeRuleStats:
    rule_id: str
    direction: str
    packets: int
    bytes: int


@dataclass
class NodeInterfaceStats:
    interface: str
    direction: str
    policy_drops: int
    rx_packets: int
    rx_bytes: int


class ControllerClient:
    """
    GraphQL client for the policy-controller API.

    All requests are executed as curl commands on the controller VM via SSH,
    consistent with the netsim test infrastructure pattern.
    """

    def __init__(
        self,
        node: Node,
        url: str = _CONTROLLER_URL,
        api_token: Optional[str] = None,
    ) -> None:
        self.node: Node = node
        self.url: str = url
        # Bearer token for the controller's REST + GraphQL surface (see
        # policy-engine/docs/event-pipeline-todo.md). If unset, requests go
        # out unauthenticated — which only works against a pre-auth
        # controller build.
        self.api_token: Optional[str] = api_token

    def _auth_header_arg(self) -> str:
        """`-H 'Authorization: Bearer …'` fragment, or empty if no token."""
        if not self.api_token:
            return ""
        return f"-H 'Authorization: Bearer {self.api_token}' "

    def _execute(self, query: str, variables: Optional[dict] = None) -> dict:
        """Run a GraphQL query/mutation via curl on the controller VM."""
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables

        payload_json: str = json.dumps(payload)
        logger.debug(f"[controller] GraphQL: {query[:80]}...")

        cmd: str
        output: str
        # Gated mutations (createRule, attachProgram, …) block for up to
        # DEFAULT_CONFIRM_DEADLINE_MS (30 s) + 1 s buffer on the controller
        # side, so 60 s leaves comfortable headroom without any risk of the
        # SSH channel timing out before the controller responds.
        _SSH_TIMEOUT = 60
        auth = self._auth_header_arg()

        if len(payload_json) > 10000:
            cmd = (
                f"curl -s -X POST -H 'Content-Type: application/json' "
                f"{auth}-d @- {self.url}"
            )
            output = self.node.ssh_command_with_stdin(
                cmd, payload_json, timeout=_SSH_TIMEOUT
            )
        else:
            payload_escaped: str = payload_json.replace("'", "'\\''")
            cmd = (
                f"curl -s -X POST -H 'Content-Type: application/json' "
                f"{auth}-d '{payload_escaped}' {self.url}"
            )
            output = self.node.ssh_command(cmd, timeout=_SSH_TIMEOUT)

        try:
            response = json.loads(output)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse controller GraphQL response: {output!r}")
            raise ValueError(f"Invalid JSON from controller GraphQL: {e}") from e

        if "errors" in response and response["errors"]:
            error_msg = response["errors"][0].get("message", str(response["errors"]))
            raise RuntimeError(f"Controller GraphQL error: {error_msg}")

        return response.get("data", {})

    # ── Nodes ─────────────────────────────────────────────────────────────────

    def list_nodes(self, status: Optional[str] = None) -> List[ControlledNode]:
        """List all controlled nodes, optionally filtered by status string."""
        query = """
        query ListNodes($status: String) {
            nodes(status: $status) {
                id status label hostname dmiUuid tpmBacked agentVersion
                certSerial certExpiry lastRenewedAt metricsIntervalSecs
            }
        }
        """
        data = self._execute(query, {"status": status} if status else None)
        return [
            ControlledNode(
                id=n["id"],
                status=n["status"],
                label=n.get("label"),
                hostname=n.get("hostname"),
                dmi_uuid=n.get("dmiUuid"),
                tpm_backed=n.get("tpmBacked", False),
                agent_version=n.get("agentVersion"),
                cert_serial=n.get("certSerial"),
                cert_expiry=n.get("certExpiry"),
                last_renewed_at=n.get("lastRenewedAt"),
                metrics_interval_secs=n.get("metricsIntervalSecs"),
            )
            for n in data.get("nodes", [])
        ]

    def pending_enrollments(self) -> List[ControlledNode]:
        """Return nodes in pending-enrollment state."""
        query = """
        query {
            pendingEnrollments { id status label hostname dmiUuid tpmBacked agentVersion }
        }
        """
        data = self._execute(query)
        return [
            ControlledNode(
                id=n["id"],
                status=n["status"],
                label=n.get("label"),
                hostname=n.get("hostname"),
                dmi_uuid=n.get("dmiUuid"),
                tpm_backed=n.get("tpmBacked", False),
                agent_version=n.get("agentVersion"),
            )
            for n in data.get("pendingEnrollments", [])
        ]

    def online_nodes(self) -> List[str]:
        """Return IDs of currently-connected agent nodes."""
        data = self._execute("query { onlineNodes }")
        return data.get("onlineNodes", [])

    def approve_enrollment(
        self, node_id: str, label: Optional[str] = None
    ) -> ControlledNode:
        """Approve a pending enrollment, optionally setting a label."""
        query = """
        mutation Approve($nodeId: ID!, $label: String) {
            approveEnrollment(nodeId: $nodeId, label: $label) {
                id status label
            }
        }
        """
        data = self._execute(query, {"nodeId": node_id, "label": label})
        n = data["approveEnrollment"]
        return ControlledNode(id=n["id"], status=n["status"], label=n.get("label"))

    def reject_enrollment(
        self, node_id: str, reason: Optional[str] = None
    ) -> OperationResult:
        """Reject a pending enrollment."""
        query = """
        mutation Reject($nodeId: ID!, $reason: String) {
            rejectEnrollment(nodeId: $nodeId, reason: $reason) { success message }
        }
        """
        data = self._execute(query, {"nodeId": node_id, "reason": reason})
        r = data["rejectEnrollment"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def decommission_node(self, node_id: str) -> OperationResult:
        """Decommission a node (revokes cert, blocks reconnect)."""
        query = """
        mutation Decommission($nodeId: ID!) {
            decommissionNode(nodeId: $nodeId) { success message }
        }
        """
        data = self._execute(query, {"nodeId": node_id})
        r = data["decommissionNode"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def remove_node(self, node_id: str) -> OperationResult:
        """Remove a decommissioned node from the registry."""
        query = """
        mutation Remove($nodeId: ID!) {
            removeNode(nodeId: $nodeId) { success message }
        }
        """
        data = self._execute(query, {"nodeId": node_id})
        r = data["removeNode"]
        return OperationResult(success=r["success"], message=r.get("message"))

    # ── Rulesets ──────────────────────────────────────────────────────────────

    def list_rulesets(self) -> List[Ruleset]:
        """Return all rulesets."""
        query = """
        query {
            rulesets {
                id name description rulesJson
                defaultActionIngress defaultActionEgress
            }
        }
        """
        data = self._execute(query)
        return [
            Ruleset(
                id=rs["id"],
                name=rs["name"],
                rules_json=rs["rulesJson"],
                description=rs.get("description"),
                default_action_ingress=rs.get("defaultActionIngress"),
                default_action_egress=rs.get("defaultActionEgress"),
            )
            for rs in data.get("rulesets", [])
        ]

    def create_ruleset(
        self,
        name: str,
        rules_json: str,
        description: Optional[str] = None,
        default_action_ingress: Optional[str] = None,
        default_action_egress: Optional[str] = None,
    ) -> Ruleset:
        """Create a new ruleset."""
        query = """
        mutation CreateRuleset(
            $name: String!
            $description: String
            $rulesJson: String!
            $defaultActionIngress: String
            $defaultActionEgress: String
        ) {
            createRuleset(
                name: $name
                description: $description
                rulesJson: $rulesJson
                defaultActionIngress: $defaultActionIngress
                defaultActionEgress: $defaultActionEgress
            ) { id name rulesJson defaultActionIngress defaultActionEgress }
        }
        """
        data = self._execute(
            query,
            {
                "name": name,
                "description": description,
                "rulesJson": rules_json,
                "defaultActionIngress": default_action_ingress,
                "defaultActionEgress": default_action_egress,
            },
        )
        rs = data["createRuleset"]
        return Ruleset(
            id=rs["id"],
            name=rs["name"],
            rules_json=rs["rulesJson"],
            default_action_ingress=rs.get("defaultActionIngress"),
            default_action_egress=rs.get("defaultActionEgress"),
        )

    def assign_ruleset(self, node_id: str, ruleset_id: str) -> OperationResult:
        """Assign a ruleset to a node."""
        query = """
        mutation Assign($nodeId: ID!, $rulesetId: ID!) {
            assignRuleset(nodeId: $nodeId, rulesetId: $rulesetId) { success message }
        }
        """
        data = self._execute(query, {"nodeId": node_id, "rulesetId": ruleset_id})
        r = data["assignRuleset"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def push_config(self, node_id: str) -> OperationResult:
        """Force push the assigned ruleset to a specific node."""
        query = """
        mutation Push($nodeId: ID!) {
            pushConfig(nodeId: $nodeId) { success message }
        }
        """
        data = self._execute(query, {"nodeId": node_id})
        r = data["pushConfig"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def push_config_all(self) -> OperationResult:
        """Push config to all currently-online nodes."""
        query = """
        mutation {
            pushConfigAll { success message }
        }
        """
        data = self._execute(query)
        r = data["pushConfigAll"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def attach_program(
        self,
        node_id: str,
        interface_name: str,
        direction: str,
        mode: Optional[str] = None,
    ) -> OperationResult:
        """Attach a BPF program to an interface on a node."""
        query = """
        mutation AttachProgram(
            $nodeId: ID!
            $interfaceName: String!
            $direction: String!
            $mode: String
        ) {
            attachProgram(
                nodeId: $nodeId
                interfaceName: $interfaceName
                direction: $direction
                mode: $mode
            ) { success message }
        }
        """
        data = self._execute(
            query,
            {
                "nodeId": node_id,
                "interfaceName": interface_name,
                "direction": direction,
                "mode": mode,
            },
        )
        r = data["attachProgram"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def detach_program(
        self, node_id: str, interface_name: str, direction: str
    ) -> OperationResult:
        """Detach a BPF program from an interface on a node."""
        query = """
        mutation DetachProgram(
            $nodeId: ID!
            $interfaceName: String!
            $direction: String!
        ) {
            detachProgram(
                nodeId: $nodeId
                interfaceName: $interfaceName
                direction: $direction
            ) { success message }
        }
        """
        data = self._execute(
            query,
            {
                "nodeId": node_id,
                "interfaceName": interface_name,
                "direction": direction,
            },
        )
        r = data["detachProgram"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def set_fib_forwarding(
        self, node_id: str, interface_name: str, enabled: bool
    ) -> OperationResult:
        """Enable or disable XDP FIB forwarding on an interface."""
        query = """
        mutation SetFib($nodeId: ID!, $interfaceName: String!, $enabled: Boolean!) {
            setFibForwarding(nodeId: $nodeId, interfaceName: $interfaceName, enabled: $enabled) {
                success message
            }
        }
        """
        data = self._execute(
            query,
            {"nodeId": node_id, "interfaceName": interface_name, "enabled": enabled},
        )
        r = data["setFibForwarding"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def set_urpf(self, node_id: str, interface_name: str, mode: str) -> OperationResult:
        """Set the uRPF mode ("off"/"loose"/"strict") on an ingress interface."""
        query = """
        mutation SetUrpf($nodeId: ID!, $interfaceName: String!, $mode: String!) {
            setUrpf(nodeId: $nodeId, interfaceName: $interfaceName, mode: $mode) {
                success message
            }
        }
        """
        data = self._execute(
            query,
            {"nodeId": node_id, "interfaceName": interface_name, "mode": mode},
        )
        r = data["setUrpf"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def set_inspect_mode(self, node_id: str, mode: str) -> OperationResult:
        """Set the node-global Suricata inspect mode ("disabled"/"ips"/"ids")."""
        query = """
        mutation SetInspectMode($nodeId: ID!, $mode: String!) {
            setInspectMode(nodeId: $nodeId, mode: $mode) { success message }
        }
        """
        data = self._execute(query, {"nodeId": node_id, "mode": mode})
        r = data["setInspectMode"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def set_inspect_interface(
        self, node_id: str, interface_name: str, enabled: bool
    ) -> OperationResult:
        """Enable or disable Suricata inspection on a single interface."""
        query = """
        mutation SetInspectInterface($nodeId: ID!, $interfaceName: String!, $enabled: Boolean!) {
            setInspectInterface(nodeId: $nodeId, interfaceName: $interfaceName, enabled: $enabled) {
                success message
            }
        }
        """
        data = self._execute(
            query,
            {"nodeId": node_id, "interfaceName": interface_name, "enabled": enabled},
        )
        r = data["setInspectInterface"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def create_suricata_ruleset(self, name: str, content: str) -> dict:
        """Create a fleet Suricata ruleset; returns the created ruleset dict."""
        query = """
        mutation CreateSuricataRuleset($name: String!, $content: String!) {
            createSuricataRuleset(name: $name, content: $content) {
                id name filename sha256 ruleCount assignedNodeIds
            }
        }
        """
        return self._execute(query, {"name": name, "content": content})[
            "createSuricataRuleset"
        ]

    def update_suricata_ruleset(self, ruleset_id: str, content: str) -> dict:
        """Replace a ruleset's content."""
        query = """
        mutation UpdateSuricataRuleset($id: ID!, $content: String!) {
            updateSuricataRuleset(id: $id, content: $content) {
                id name filename sha256 ruleCount
            }
        }
        """
        return self._execute(query, {"id": ruleset_id, "content": content})[
            "updateSuricataRuleset"
        ]

    def delete_suricata_ruleset(self, ruleset_id: str) -> OperationResult:
        query = """
        mutation DeleteSuricataRuleset($id: ID!) {
            deleteSuricataRuleset(id: $id) { success message }
        }
        """
        r = self._execute(query, {"id": ruleset_id})["deleteSuricataRuleset"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def assign_suricata_ruleset(self, node_id: str, ruleset_id: str) -> OperationResult:
        query = """
        mutation AssignSuricataRuleset($nodeId: ID!, $rulesetId: ID!) {
            assignSuricataRuleset(nodeId: $nodeId, rulesetId: $rulesetId) { success message }
        }
        """
        r = self._execute(query, {"nodeId": node_id, "rulesetId": ruleset_id})[
            "assignSuricataRuleset"
        ]
        return OperationResult(success=r["success"], message=r.get("message"))

    def unassign_suricata_ruleset(
        self, node_id: str, ruleset_id: str
    ) -> OperationResult:
        query = """
        mutation UnassignSuricataRuleset($nodeId: ID!, $rulesetId: ID!) {
            unassignSuricataRuleset(nodeId: $nodeId, rulesetId: $rulesetId) { success message }
        }
        """
        r = self._execute(query, {"nodeId": node_id, "rulesetId": ruleset_id})[
            "unassignSuricataRuleset"
        ]
        return OperationResult(success=r["success"], message=r.get("message"))

    def push_suricata_rulesets(self, node_id: str) -> OperationResult:
        query = """
        mutation PushSuricataRulesets($nodeId: ID!) {
            pushSuricataRulesets(nodeId: $nodeId) { success message }
        }
        """
        r = self._execute(query, {"nodeId": node_id})["pushSuricataRulesets"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def node_suricata_rulesets(self, node_id: str) -> List[dict]:
        """Assigned rulesets for a node, each with an ``inSync`` flag."""
        query = """
        query NodeSuricataRulesets($nodeId: ID!) {
            nodeSuricataRulesets(nodeId: $nodeId) {
                id name filename sha256 ruleCount inSync
            }
        }
        """
        return self._execute(query, {"nodeId": node_id})["nodeSuricataRulesets"]

    def suricata_alerts(
        self,
        node_id: Optional[str] = None,
        min_severity: Optional[int] = None,
        signature_id: Optional[int] = None,
        include_acked: bool = False,
        limit: int = 200,
    ) -> List[dict]:
        """Query persisted Suricata alerts (newest first, unacked only by default)."""
        query = """
        query SuricataAlerts($filter: SuricataAlertFilterInput, $limit: Int) {
            suricataAlerts(filter: $filter, limit: $limit) {
                id nodeId timestamp srcIp srcPort destIp destPort
                protocol action signatureId signature category severity acked
            }
        }
        """
        filt: dict = {}
        if node_id is not None:
            filt["nodeId"] = node_id
        if min_severity is not None:
            filt["minSeverity"] = min_severity
        if signature_id is not None:
            filt["signatureId"] = signature_id
        if include_acked:
            filt["includeAcked"] = True
        return self._execute(query, {"filter": filt, "limit": limit})["suricataAlerts"]

    def ack_suricata_alerts(self, node_id: Optional[str] = None) -> OperationResult:
        """Acknowledge all unacked Suricata alerts, optionally scoped to one node.

        Acked alerts stay stored (visible with ``include_acked=True``) until
        the retention sweep deletes them.
        """
        query = """
        mutation AckSuricataAlerts($nodeId: ID) {
            ackSuricataAlerts(nodeId: $nodeId) { success message }
        }
        """
        r = self._execute(query, {"nodeId": node_id})["ackSuricataAlerts"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def clear_suricata_alerts(self, node_id: Optional[str] = None) -> OperationResult:
        """Permanently delete persisted Suricata alerts (admin purge; prefer ack)."""
        query = """
        mutation ClearSuricataAlerts($nodeId: ID) {
            clearSuricataAlerts(nodeId: $nodeId) { success message }
        }
        """
        r = self._execute(query, {"nodeId": node_id})["clearSuricataAlerts"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def node_inspect_state(self, node_id: str) -> dict:
        """Node inspect_mode + capabilities + per-interface inspect flags."""
        query = """
        query NodeInspect($nodeId: ID!) {
            node(id: $nodeId) { inspectMode capabilities }
            nodeInterfaces(nodeId: $nodeId) { name inspectEnabled }
        }
        """
        return self._execute(query, {"nodeId": node_id})

    def set_interface_default_action(
        self,
        node_id: str,
        interface_name: str,
        direction: str,
        action: str,
    ) -> OperationResult:
        """Set the default action for unmatched packets on an interface+direction."""
        query = """
        mutation SetDefault(
            $nodeId: ID!
            $interfaceName: String!
            $direction: String!
            $action: String!
        ) {
            setInterfaceDefaultAction(
                nodeId: $nodeId
                interfaceName: $interfaceName
                direction: $direction
                action: $action
            ) { success message }
        }
        """
        data = self._execute(
            query,
            {
                "nodeId": node_id,
                "interfaceName": interface_name,
                "direction": direction,
                "action": action,
            },
        )
        r = data["setInterfaceDefaultAction"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def label_node(self, node_id: str, label: str) -> OperationResult:
        """Set a human-readable label on a node."""
        query = """
        mutation LabelNode($nodeId: ID!, $label: String!) {
            labelNode(nodeId: $nodeId, label: $label) { success message }
        }
        """
        data = self._execute(query, {"nodeId": node_id, "label": label})
        r = data["labelNode"]
        return OperationResult(success=r["success"], message=r.get("message"))

    # ── Interface queries ─────────────────────────────────────────────────────

    def node_interfaces(self, node_id: str) -> List[NodeInterface]:
        """List all interfaces reported for a node."""
        query = """
        query NodeInterfaces($nodeId: ID!) {
            nodeInterfaces(nodeId: $nodeId) {
                nodeId name ifindex macAddress linkState addressesJson tag
                xdpAttached tcAttached fibForwarding urpfMode
                ingressDefaultAction egressDefaultAction
            }
        }
        """
        data = self._execute(query, {"nodeId": node_id})
        return [
            NodeInterface(
                node_id=i["nodeId"],
                name=i["name"],
                ifindex=int(i.get("ifindex") or 0),
                mac_address=i.get("macAddress"),
                link_state=i.get("linkState", "unknown"),
                addresses_json=i.get("addressesJson", "[]"),
                tag=i.get("tag"),
                xdp_attached=i.get("xdpAttached", False),
                tc_attached=i.get("tcAttached", False),
                fib_forwarding=i.get("fibForwarding", False),
                urpf_mode=i.get("urpfMode", "off"),
                ingress_default_action=i.get("ingressDefaultAction"),
                egress_default_action=i.get("egressDefaultAction"),
            )
            for i in data.get("nodeInterfaces", [])
        ]

    def node_flow_verdicts(
        self,
        node_id: str,
        direction: str = "ingress",
        limit: Optional[int] = None,
    ) -> List[NodeFlowVerdict]:
        """Read a node's live flow verdict cache for one direction.

        Issues an on-demand query to the node's agent, so the node must be
        online. ``limit`` caps the entries (soonest-expiring first; None uses
        the server default of 1000).
        """
        query = """
        query NodeFlowVerdicts($nodeId: ID!, $direction: String!, $limit: Int) {
            nodeFlowVerdicts(nodeId: $nodeId, direction: $direction, limit: $limit) {
                srcIp dstIp srcPort dstPort protocol action
                expiresNs expired packets bytes
            }
        }
        """
        data = self._execute(
            query, {"nodeId": node_id, "direction": direction, "limit": limit}
        )
        return [
            NodeFlowVerdict(
                src_ip=v["srcIp"],
                dst_ip=v["dstIp"],
                src_port=v["srcPort"],
                dst_port=v["dstPort"],
                protocol=v["protocol"],
                action=v["action"],
                expires_ns=v["expiresNs"],
                expired=v["expired"],
                packets=v["packets"],
                bytes=v["bytes"],
            )
            for v in data.get("nodeFlowVerdicts", []) or []
        ]

    def events(
        self,
        node_id: Optional[str] = None,
        rule_id: Optional[str] = None,
        action: Optional[str] = None,
        since_iso: Optional[str] = None,
        limit: int = 100,
    ) -> List[PersistedEvent]:
        """Query the controller's persisted policy-event store.

        `action` is a GraphQL `EventAction` enum value (e.g. "LOG", "DROP",
        "PASS"). `since_iso` accepts any ISO-8601 timestamp the server parses
        as DateTime. Returns newest-first; capped at `limit`.
        """
        query = """
        query Events($filter: EventFilterInput, $limit: Int) {
            events(filter: $filter, limit: $limit) {
                items {
                    id timestamp nodeId ruleId action verdict direction
                    ifindex proto srcIp dstIp sport dport pktLen sni
                }
            }
        }
        """
        filt: dict[str, Any] = {}
        if node_id is not None:
            filt["nodeId"] = node_id
        if rule_id is not None:
            filt["ruleId"] = rule_id
        if action is not None:
            filt["action"] = action
        if since_iso is not None:
            filt["since"] = since_iso
        data = self._execute(query, {"filter": filt if filt else None, "limit": limit})
        return [
            PersistedEvent(
                id=e["id"],
                timestamp=e["timestamp"],
                node_id=e["nodeId"],
                rule_id=e["ruleId"],
                action=e["action"],
                verdict=e["verdict"],
                direction=e["direction"],
                ifindex=int(e.get("ifindex") or 0),
                proto=int(e.get("proto") or 0),
                src_ip=e["srcIp"],
                dst_ip=e["dstIp"],
                sport=int(e.get("sport") or 0),
                dport=int(e.get("dport") or 0),
                pkt_len=int(e.get("pktLen") or 0),
                sni=e.get("sni"),
            )
            for e in data.get("events", {}).get("items", [])
        ]

    # ── Single-rule (gated) operations ────────────────────────────────────────

    def create_rule(
        self,
        node_id: str,
        interface_name: str,
        direction: str,
        src_cidr: Optional[str] = None,
        dst_cidr: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        protocol: Optional[str] = None,
        actions_json: str = '[{"action":"drop","priority":0}]',
    ) -> dict:
        """
        Create a single rule on a node via the gated createRule mutation.

        Unlike assignRuleset/pushConfig, this path goes through the
        controller's PendingRegistry — the controller waits for the agent's
        ConfigConfirm handshake before returning. If the agent cannot
        confirm (e.g. the new rule blackholes the controller path), the
        mutation raises RuntimeError with "BLOCKED_PENDING_CONFIRM" or a
        reverted/abandoned message depending on the outcome.
        """
        query = """
        mutation CreateRule($input: CreateRuleInput!) {
            createRule(input: $input) {
                id nodeId interfaceName direction srcCidr dstCidr
                srcPort dstPort protocol actionsJson
            }
        }
        """
        input_obj: dict[str, Any] = {
            "nodeId": node_id,
            "interfaceName": interface_name,
            "direction": direction,
            "actionsJson": actions_json,
        }
        if src_cidr is not None:
            input_obj["srcCidr"] = src_cidr
        if dst_cidr is not None:
            input_obj["dstCidr"] = dst_cidr
        if src_port is not None:
            input_obj["srcPort"] = src_port
        if dst_port is not None:
            input_obj["dstPort"] = dst_port
        if protocol is not None:
            input_obj["protocol"] = protocol
        data = self._execute(query, {"input": input_obj})
        return data["createRule"]

    def create_rules_multi_node(
        self,
        node_ids: List[str],
        interface_name: str,
        direction: str,
        src_cidr: Optional[str] = None,
        dst_cidr: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        protocol: Optional[str] = None,
        actions_json: str = '[{"action":"drop","priority":0}]',
    ) -> list:
        """Create the same rule on multiple nodes at once."""
        query = """
        mutation CreateMulti($input: CreateRuleMultiNodeInput!) {
            createRulesMultiNode(input: $input) {
                id nodeId interfaceName direction srcCidr dstCidr
                srcPort dstPort protocol actionsJson
            }
        }
        """
        input_obj: dict = {
            "nodeIds": node_ids,
            "interfaceName": interface_name,
            "direction": direction,
            "actionsJson": actions_json,
        }
        if src_cidr is not None:
            input_obj["srcCidr"] = src_cidr
        if dst_cidr is not None:
            input_obj["dstCidr"] = dst_cidr
        if src_port is not None:
            input_obj["srcPort"] = src_port
        if dst_port is not None:
            input_obj["dstPort"] = dst_port
        if protocol is not None:
            input_obj["protocol"] = protocol
        data = self._execute(query, {"input": input_obj})
        return data.get("createRulesMultiNode", [])

    def delete_rule(self, rule_id: str) -> OperationResult:
        """Delete a single rule from the controller (gated — blocks until the node confirms)."""
        query = """
        mutation DeleteRule($ruleId: ID!) {
            deleteRule(ruleId: $ruleId) { success message }
        }
        """
        data = self._execute(query, {"ruleId": rule_id})
        r = data["deleteRule"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def flush_rules(
        self, node_id: str, interface_name: str, direction: str
    ) -> OperationResult:
        """Delete every rule on a single (node, interface, direction).

        Gated — the controller bundles the delete into a single agent push and
        blocks until the agent confirms.
        """
        query = """
        mutation FlushRules($nodeId: ID!, $iface: String!, $dir: String!) {
            flushRules(nodeId: $nodeId, interfaceName: $iface, direction: $dir) {
                success
                message
            }
        }
        """
        data = self._execute(
            query,
            {
                "nodeId": node_id,
                "iface": interface_name,
                "dir": direction,
            },
        )
        r = data["flushRules"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def list_rules_for_node(
        self,
        node_id: str,
        interface_name: Optional[str] = None,
        direction: Optional[str] = None,
    ) -> list:
        """List controller-stored rules for a node (optionally filtered)."""
        query = """
        query Rules($nodeId: ID!, $iface: String, $dir: String) {
            rules(nodeId: $nodeId, interfaceName: $iface, direction: $dir) {
                id nodeId interfaceName direction
                srcCidr dstCidr srcPort dstPort protocol actionsJson
            }
        }
        """
        data = self._execute(
            query,
            {"nodeId": node_id, "iface": interface_name, "dir": direction},
        )
        return data.get("rules", [])

    def node_rule_stats(
        self,
        node_id: str,
        rule_id: str,
        direction: str,
    ) -> Optional[NodeRuleStats]:
        """Return packet/byte counters for a rule from the node's latest metrics snapshot.

        Stats are derived from Prometheus metrics pushed by the agent every 30 s.
        Returns None when no metrics snapshot has been received for the node yet.
        The rule_id must be the controller-assigned string ID (same value returned
        by create_rule).
        """
        query = """
        query NodeRuleStats($nodeId: ID!, $ruleId: ID!, $dir: String!) {
            nodeRuleStats(nodeId: $nodeId, ruleId: $ruleId, direction: $dir) {
                ruleId direction packets bytes
            }
        }
        """
        data = self._execute(
            query, {"nodeId": node_id, "ruleId": rule_id, "dir": direction}
        )
        raw = data.get("nodeRuleStats")
        if raw is None:
            return None
        return NodeRuleStats(
            rule_id=raw["ruleId"],
            direction=raw["direction"],
            packets=raw["packets"],
            bytes=raw["bytes"],
        )

    def node_interface_stats(
        self,
        node_id: str,
        interface_name: str,
        direction: str,
    ) -> Optional[NodeInterfaceStats]:
        """Return traffic counters for an interface from the node's latest metrics snapshot.

        Stats are derived from Prometheus metrics pushed by the agent every 30 s.
        Returns None when no metrics snapshot has been received for the node yet.
        """
        query = """
        query NodeInterfaceStats($nodeId: ID!, $iface: String!, $dir: String!) {
            nodeInterfaceStats(nodeId: $nodeId, interfaceName: $iface, direction: $dir) {
                interface direction policyDrops packets bytes
            }
        }
        """
        data = self._execute(
            query, {"nodeId": node_id, "iface": interface_name, "dir": direction}
        )
        raw = data.get("nodeInterfaceStats")
        if raw is None:
            return None
        return NodeInterfaceStats(
            interface=raw["interface"],
            direction=raw["direction"],
            policy_drops=raw["policyDrops"],
            rx_packets=raw["packets"],
            rx_bytes=raw["bytes"],
        )

    def refresh_node_metrics(self, node_id: str) -> OperationResult:
        """Ask the controller to request an immediate metrics push from the node.

        Sends a MetricsQuery message to the connected agent, waking its metrics
        forwarder immediately rather than waiting for the next 30-second tick.
        Returns an error result if the node is not currently connected.
        """
        query = """
        mutation RefreshNodeMetrics($nodeId: ID!) {
            refreshNodeMetrics(nodeId: $nodeId) { success message }
        }
        """
        data = self._execute(query, {"nodeId": node_id})
        r = data["refreshNodeMetrics"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def clear_interface_stats(
        self,
        node_id: str,
        interface_name: str,
        direction: Optional[str] = None,
    ) -> OperationResult:
        """Clear all stats (global + ethertype) for one interface on a node.

        Fire-and-forget: the controller pushes a ClearStats message to the agent
        and returns ok once delivered. ``direction`` is "ingress"/"egress"; pass
        None to clear both directions.
        """
        query = """
        mutation ClearInterfaceStats($nodeId: ID!, $iface: String!, $dir: String) {
            clearInterfaceStats(nodeId: $nodeId, interfaceName: $iface, direction: $dir) {
                success message
            }
        }
        """
        data = self._execute(
            query, {"nodeId": node_id, "iface": interface_name, "dir": direction}
        )
        r = data["clearInterfaceStats"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def clear_all_interface_stats(self, node_id: str) -> OperationResult:
        """Clear interface stats for every attached interface on a node."""
        query = """
        mutation ClearAllInterfaceStats($nodeId: ID!) {
            clearAllInterfaceStats(nodeId: $nodeId) { success message }
        }
        """
        data = self._execute(query, {"nodeId": node_id})
        r = data["clearAllInterfaceStats"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def clear_rule_stats(
        self,
        node_id: str,
        rule_id: str,
        direction: Optional[str] = None,
    ) -> OperationResult:
        """Clear stats for a single policy rule on a node.

        ``rule_id`` is the controller-assigned string ID (same value returned by
        create_rule). ``direction`` is "ingress"/"egress"; pass None for both.
        """
        query = """
        mutation ClearRuleStats($nodeId: ID!, $ruleId: ID!, $dir: String) {
            clearRuleStats(nodeId: $nodeId, ruleId: $ruleId, direction: $dir) {
                success message
            }
        }
        """
        data = self._execute(
            query, {"nodeId": node_id, "ruleId": rule_id, "dir": direction}
        )
        r = data["clearRuleStats"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def clear_all_policy_stats(self, node_id: str) -> OperationResult:
        """Clear stats for every policy rule on a node (both directions)."""
        query = """
        mutation ClearAllPolicyStats($nodeId: ID!) {
            clearAllPolicyStats(nodeId: $nodeId) { success message }
        }
        """
        data = self._execute(query, {"nodeId": node_id})
        r = data["clearAllPolicyStats"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def clear_all_stats(self, node_id: str) -> OperationResult:
        """Clear ALL stats on a node — every interface and every rule counter."""
        query = """
        mutation ClearAllStats($nodeId: ID!) {
            clearAllStats(nodeId: $nodeId) { success message }
        }
        """
        data = self._execute(query, {"nodeId": node_id})
        r = data["clearAllStats"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def set_node_metrics_interval(
        self,
        node_id: str,
        seconds: Optional[int],
    ) -> OperationResult:
        """Set the node's metrics scrape/forward interval (seconds).

        Pass None to clear the override so the agent reverts to its local
        default. Persisted on the controller and re-sent to the agent on each
        (re)connect; applied live to the running metrics forwarder.
        """
        query = """
        mutation SetNodeMetricsInterval($nodeId: ID!, $seconds: Int) {
            setNodeMetricsInterval(nodeId: $nodeId, seconds: $seconds) {
                success message
            }
        }
        """
        data = self._execute(query, {"nodeId": node_id, "seconds": seconds})
        r = data["setNodeMetricsInterval"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def node_metrics_interval(self, node_id: str) -> Optional[int]:
        """Return the node's configured metrics interval (seconds), or None."""
        for n in self.list_nodes():
            if n.id == node_id:
                return n.metrics_interval_secs
        return None

    def node_last_seen(self, node_id: str) -> Optional[str]:
        """Return the lastSeen timestamp (ISO-8601 string) for the node, or None."""
        query = """
        query NodeLastSeen($nodeId: ID!) {
            node(id: $nodeId) { lastSeen }
        }
        """
        data = self._execute(query, {"nodeId": node_id})
        node = data.get("node")
        if node is None:
            return None
        return node.get("lastSeen")

    def pending_generation(self, node_id: str) -> Optional[dict]:
        """Return the in-flight pending generation for a node, if any."""
        query = """
        query Pending($nodeId: ID!) {
            pendingGeneration(nodeId: $nodeId) {
                generationId nodeId opKind issuedAt
            }
        }
        """
        data = self._execute(query, {"nodeId": node_id})
        return data.get("pendingGeneration")

    # ── ZTP enrollment tokens ─────────────────────────────────────────────────

    def create_enrollment_token(
        self,
        enrollment_url: str,
        controller_url: str,
        ttl_seconds: int,
        max_uses: int,
        cidr_scope: Optional[str] = None,
        fleet_label: Optional[str] = None,
    ) -> IssuedEnrollmentToken:
        """Mint a ZTP bootstrap token; the bundle is returned exactly once."""
        query = """
        mutation CreateEnrollmentToken(
            $enrollmentUrl: String!
            $controllerUrl: String!
            $ttlSeconds: Int!
            $maxUses: Int!
            $cidrScope: String
            $fleetLabel: String
        ) {
            createEnrollmentToken(
                enrollmentUrl: $enrollmentUrl
                controllerUrl: $controllerUrl
                ttlSeconds: $ttlSeconds
                maxUses: $maxUses
                cidrScope: $cidrScope
                fleetLabel: $fleetLabel
            ) { tokenId bundle expiresAt usesRemaining }
        }
        """
        data = self._execute(
            query,
            {
                "enrollmentUrl": enrollment_url,
                "controllerUrl": controller_url,
                "ttlSeconds": ttl_seconds,
                "maxUses": max_uses,
                "cidrScope": cidr_scope,
                "fleetLabel": fleet_label,
            },
        )
        t = data["createEnrollmentToken"]
        return IssuedEnrollmentToken(
            token_id=t["tokenId"],
            bundle=t["bundle"],
            expires_at=t["expiresAt"],
            uses_remaining=t["usesRemaining"],
        )

    # ── CA cert ───────────────────────────────────────────────────────────────

    def ca_cert_pem(self) -> str:
        """Retrieve the controller CA certificate in PEM format."""
        data = self._execute("query { caCertPem }")
        return data["caCertPem"]

    # ── Health check ──────────────────────────────────────────────────────────

    def is_healthy(self) -> bool:
        """Return True if the controller HTTP API is responding."""
        try:
            out: str = self.node.ssh_command(
                "curl -s -o /dev/null -w '%{http_code}' "
                "--max-time 2 http://127.0.0.1:8443/health 2>/dev/null || true",
                timeout=10,
            )
            return out.strip() == "200"
        except Exception:
            return False
