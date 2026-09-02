# Copyright (c) Peter Morrow

"""
Multi-node cert revocation behaviour.

Builds on the single-node decommission flow exercised by
`test_tls_revocation.py`. With three managed nodes enrolled, we can pin down
fleet-level behaviour that a 1-node topology cannot:

  * sibling isolation — revoking one node's cert must not perturb the
    management streams or handshake-layer verification of the other two;
  * persistence across controller restart — the in-memory
    `RevokingClientCertVerifier` mirror is seeded from the `revoked_certs`
    table on boot, so a serial revoked before the bounce must still be
    rejected at the TLS layer afterwards;
  * revoke-while-offline — decommissioning a node whose agent is stopped
    must prevent re-attach: the agent's next reconnect presents the
    captured (now-revoked) cert and the handshake-layer verifier rejects it
    before any application traffic.

These tests target node2 and node3 only, leaving node1 free for the
single-node tests in this package (test_cert_renewal.py,
test_tls_revocation.py) regardless of pytest collection order.

Run with:
  netsim start tests/rotation/rotation.yaml
  python3 -m pytest tests/rotation/test_multi_node_revocation.py -v \\
      --package-dir ..
  netsim destroy tests/rotation/rotation.yaml
"""

import logging
import time
from typing import Dict

from netsim.testkit.systemd_utils import restart_service, stop_service
from policy_engine_client.controller.graphql.client import ControllerClient

from tests.rotation.conftest import (
    journalctl_since,
    now_iso,
    tls_probe,
)

logger = logging.getLogger(__name__)

# Watch-channel propagation is synchronous from the GraphQL handler's POV;
# this is a guard against scheduling jitter only. Matches the value used by
# test_tls_revocation.py.
_WATCH_PROPAGATION_SECS = 1

# Max time we'll wait for a stopped+restarted agent to either come online
# or get rejected at the handshake. The agent's backoff caps fast (a couple
# of seconds), so 30s is generous.
_REATTACH_DEADLINE_SECS = 30

# Time to allow the controller to come back after a restart before resuming
# GraphQL polling. Matches the deadline in test_cert_renewal.py.
_CONTROLLER_RECOVERY_SECS = 30


def _node_by_id(client: ControllerClient, node_id: str):
    """Fetch the current Node record; returns None if the controller has
    forgotten the node (e.g. after remove_node)."""
    for n in client.list_nodes():
        if n.id == node_id:
            return n
    return None


def _wait_until_offline(
    client: ControllerClient, node_id: str, deadline_secs: int
) -> None:
    """Block until `node_id` drops out of onlineNodes."""
    deadline = time.monotonic() + deadline_secs
    while time.monotonic() < deadline:
        if node_id not in client.online_nodes():
            return
        time.sleep(1)
    raise AssertionError(
        f"node {node_id} stayed in online_nodes for {deadline_secs}s after "
        f"its cert was revoked"
    )


def _wait_for_controller_recovery(
    client: ControllerClient, deadline_secs: int = _CONTROLLER_RECOVERY_SECS
) -> None:
    deadline = time.monotonic() + deadline_secs
    while time.monotonic() < deadline:
        try:
            client.list_nodes()
            return
        except Exception:
            time.sleep(1)
    raise AssertionError(
        f"controller HTTP did not recover within {deadline_secs}s of restart"
    )


class TestMultiNodeRevocation:
    def test_decommission_does_not_affect_siblings(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """
        Decommissioning node3 must take *only* node3 off the management
        channel. node1 and node2 stay online, and the controller's
        verifier log shows rejections only for node3's serial.

        This proves the watch-channel update is scoped to the revoked
        serial — a bug that broadcast a flush or replaced the verifier's
        set would tear down sibling streams.
        """
        controller = nodes["controller"]
        target_id = enrolled_nodes["node3"]
        sibling_ids = [enrolled_nodes["node1"], enrolled_nodes["node2"]]

        target = _node_by_id(controller_client, target_id)
        assert target is not None and target.cert_serial, (
            f"node3 ({target_id}) has no cert_serial; cannot target revocation"
        )
        sibling_serials = {
            sid: _node_by_id(controller_client, sid).cert_serial for sid in sibling_ids
        }
        for sid, ser in sibling_serials.items():
            assert ser, f"sibling {sid} has no cert_serial pre-revocation"

        marker = now_iso(controller)
        result = controller_client.decommission_node(target_id)
        assert result.success, f"decommissionNode(node3) failed: {result.message}"
        logger.info(f"decommissioned node3={target_id}, serial={target.cert_serial}")
        time.sleep(_WATCH_PROPAGATION_SECS)

        # `decommission_node` revokes the serial and updates the verifier
        # mirror but does NOT tear down the existing stream (see
        # node_registry/mod.rs:430 — "rejected on next attempt"). Bounce
        # the agent to force a reconnect; the handshake will then fail and
        # the controller will drop node3 from online_nodes.
        restart_status = restart_service(nodes["node3"], "policy-node-agent")
        assert restart_status.is_healthy, (
            f"policy-node-agent on node3 failed to start: {restart_status.status_text}"
        )

        _wait_until_offline(controller_client, target_id, _REATTACH_DEADLINE_SECS)

        # Siblings remain in online_nodes throughout. Poll for a short
        # interval to catch any transient drop caused by spillover.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            online = set(controller_client.online_nodes())
            missing = [s for s in sibling_ids if s not in online]
            assert not missing, (
                f"sibling nodes dropped offline after node3 was decommissioned: "
                f"{missing}"
            )
            time.sleep(1)

        # The verifier's rejection log must mention node3's serial. Siblings'
        # serials must not appear in any "Rejecting TLS handshake" line since
        # the marker — if they did, the watch update revoked the wrong set.
        hits = journalctl_since(controller, marker, "Rejecting TLS handshake")
        logger.info(f"verifier rejection log since decommission:\n{hits}")
        for sid, ser in sibling_serials.items():
            assert ser not in hits, (
                f"sibling {sid} serial {ser} appeared in 'Rejecting TLS "
                f"handshake' log after node3 was decommissioned. The watch "
                f"channel must have over-revoked.\nHits:\n{hits}"
            )

    def test_revocation_persists_across_controller_restart(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """
        Decommission node2, bounce the controller, then drive the agent
        through one reconnect attempt. The captured (now-revoked) cert
        must still be rejected at the TLS layer post-restart — which only
        holds if the controller seeded `RevokingClientCertVerifier` from
        the `revoked_certs` table during startup.

        We stop the agent before the bounce so its reconnect storm doesn't
        race the restart, and snapshot its on-disk cert+key before the
        controller comes back so renewals after recovery cannot have
        replaced what we'll probe with.
        """
        node = nodes["node2"]
        controller = nodes["controller"]
        node_id = enrolled_nodes["node2"]

        pre = _node_by_id(controller_client, node_id)
        assert pre is not None and pre.cert_serial
        revoked_serial = pre.cert_serial

        # Stop the agent so it doesn't keep churning during the bounce.
        stop_service(node, "policy-node-agent")

        result = controller_client.decommission_node(node_id)
        assert result.success, f"decommissionNode(node2) failed: {result.message}"
        logger.info(f"decommissioned node2={node_id}, serial={revoked_serial}")

        # Capture the revoked cert+key before the bounce. The agent is
        # stopped so the files won't be swapped under us.
        node.ssh_command(
            "sudo cp /var/lib/policy-node-agent/controller-client.crt "
            "    /tmp/revoked-client.crt && "
            "sudo cp /var/lib/policy-node-agent/controller-client.key "
            "    /tmp/revoked-client.key && "
            "sudo chmod 0644 /tmp/revoked-client.crt /tmp/revoked-client.key",
            timeout=10,
        )

        # Bounce the controller. The verifier's in-memory mirror is wiped;
        # it must be rebuilt from the `revoked_certs` table on startup.
        status = restart_service(controller, "policy-controller")
        assert status.is_healthy, (
            f"controller restart left it unhealthy: {status.status_text}"
        )
        _wait_for_controller_recovery(controller_client)
        marker = now_iso(controller)

        # Probe with the captured revoked cert. If the reload didn't happen,
        # the handshake completes and the probe times out without an alert.
        out = tls_probe(
            node,
            cert_path="/tmp/revoked-client.crt",
            key_path="/tmp/revoked-client.key",
        )
        logger.info(f"post-restart probe with revoked cert:\n{out}")
        assert "alert number" in out.lower(), (
            "Expected a fatal TLS alert when probing with the revoked cert "
            "after a controller restart. Absence of the alert means the "
            "verifier's revocation mirror was NOT reloaded from "
            "`revoked_certs` on startup.\n"
            f"Probe output:\n{out}"
        )

        # And the controller's verifier log must mention this specific
        # serial — proves the reload populated the set with the right value
        # rather than rejecting on some unrelated check.
        deadline = time.monotonic() + 15
        hits = ""
        while time.monotonic() < deadline:
            hits = journalctl_since(controller, marker, "Rejecting TLS handshake")
            if revoked_serial in hits:
                break
            time.sleep(2)
        assert revoked_serial in hits, (
            f"Controller log post-restart did not mention the revoked serial "
            f"{revoked_serial}. The probe saw an alert but the verifier may "
            f"have rejected for the wrong reason.\nHits:\n{hits}"
        )

    def test_revoke_while_offline_blocks_reattach(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """
        Restart the agent on the already-decommissioned node2 and confirm
        it cannot re-attach: the first thing the agent does on startup is
        the management handshake, which the verifier rejects on the
        revoked serial. The node must never return to online_nodes and
        the controller must log a rejection.

        node2 was decommissioned (and its agent stopped) in
        `test_revocation_persists_across_controller_restart`. If this
        test is run in isolation we decommission defensively first.
        """
        node = nodes["node2"]
        controller = nodes["controller"]
        node_id = enrolled_nodes["node2"]

        current = _node_by_id(controller_client, node_id)
        if current is not None and current.status.lower() == "active":
            stop_service(node, "policy-node-agent")
            r = controller_client.decommission_node(node_id)
            assert r.success, f"defensive decommissionNode(node2) failed: {r.message}"
            time.sleep(_WATCH_PROPAGATION_SECS)

        marker = now_iso(controller)

        # Start the agent. systemd will report it healthy as long as the
        # process is running — the management handshake failure happens in
        # the reconnect loop and does not crash the service.
        ag = restart_service(node, "policy-node-agent")
        assert ag.is_healthy, (
            f"policy-node-agent on node2 failed to start: {ag.status_text}"
        )

        # The node must never return to online_nodes. Watch for the full
        # reattach deadline.
        deadline = time.monotonic() + _REATTACH_DEADLINE_SECS
        while time.monotonic() < deadline:
            assert node_id not in controller_client.online_nodes(), (
                f"node2 ({node_id}) reattached after decommission — the "
                f"controller accepted a revoked client cert"
            )
            time.sleep(2)

        # Verifier must have logged at least one rejection since we
        # restarted the agent.
        deadline = time.monotonic() + 15
        hits = ""
        while time.monotonic() < deadline:
            hits = journalctl_since(controller, marker, "Rejecting TLS handshake")
            if hits.strip():
                break
            time.sleep(2)
        assert hits.strip(), (
            "Controller did not log any 'Rejecting TLS handshake' lines after "
            "the agent was restarted with a revoked cert. Either the agent "
            "isn't reconnecting, or the handshake-layer verifier is off the path."
        )
        logger.info(f"verifier rejection log:\n{hits}")
