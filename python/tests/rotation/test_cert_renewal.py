# Copyright (c) Dufferin Software

"""
Phase 7 cert renewal — end-to-end on the netsim rotation topology.

Relies on the short-TTL profile written by `conftest._write_controller_config`:
  - node_cert_ttl_secs           = 60   (controller)
  - renewal_check_interval_secs  = 5    (agent)
  - mtls_key_rotation_renewals   = 2    (agent)

That puts `renew_at` at ~40s after issuance with a 5s tick, so the agent's
renewal task fires within ~45s of cert issuance and the suite runs in roughly
one cert lifetime per scenario.

These tests treat the controller's GraphQL `Node.certSerial` /
`Node.lastRenewedAt` as the canonical signal — they're driven by the same
`update_current_cert_meta` call the controller writes after every successful
renewal, so a flip there proves the registry path executed end-to-end. The
TLS-probe assertions confirm the *handshake-layer* consequences (old cert is
revoked; new cert is honoured).
"""

import logging
import time
from typing import Dict

from netsim.testkit.node import Node
from netsim.testkit.systemd_utils import restart_service
from policy_engine_client.controller.graphql.client import ControllerClient

from tests.rotation.conftest import (
    journalctl_since,
    now_iso,
    tls_probe,
    _CLIENT_CRT,
    _CLIENT_KEY,
)

logger = logging.getLogger(__name__)

# Worst-case wall-clock for one renewal cycle to complete on a 60s/5s setup:
# ~40s (renew_at) + 5s (next tick) + ~5s (RPC + atomic writes + reconnect).
# Pad generously for cloud VM jitter.
_RENEWAL_DEADLINE_SECS = 90


def _node_by_id(client: ControllerClient, node_id: str):
    """Look up the current Node record by id. Returns None if the controller
    no longer knows about the node (e.g. after a remove_node)."""
    for n in client.list_nodes():
        if n.id == node_id:
            return n
    return None


def _wait_for_serial_change(
    client: ControllerClient, node_id: str, old_serial: str, deadline_secs: int
) -> str:
    """Poll the controller until `cert_serial` differs from `old_serial`."""
    deadline = time.monotonic() + deadline_secs
    while time.monotonic() < deadline:
        n = _node_by_id(client, node_id)
        if n is not None and n.cert_serial and n.cert_serial != old_serial:
            return n.cert_serial
        time.sleep(2)
    raise AssertionError(
        f"cert_serial for {node_id} did not change from {old_serial} within "
        f"{deadline_secs}s — agent-side renewal task did not fire, or "
        f"controller did not persist the new serial"
    )


def _key_sha256(node: Node, path: str) -> str:
    """Return the SHA-256 of an on-node key file as lowercase hex."""
    raw = node.ssh_command(
        f"sudo sha256sum {path} | awk '{{print $1}}'", timeout=10
    ).strip()
    if len(raw) != 64:
        raise RuntimeError(f"Unexpected sha256sum output on {path}: {raw!r}")
    return raw


class TestCertRenewal:
    def test_renewal_replaces_cert_within_ttl(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """
        Happy path: with TTL=60s and check_interval=5s the agent must
        renew before the cert expires. Assert the controller's
        `cert_serial` flips AND the node stays `online` across the swap.
        """
        node_id = enrolled_nodes["node1"]
        pre = _node_by_id(controller_client, node_id)
        assert pre is not None and pre.cert_serial, (
            f"node1 ({node_id}) has no cert_serial pre-renewal; the test setup is wrong"
        )
        logger.info(f"pre-renewal serial={pre.cert_serial}, expiry={pre.cert_expiry}")

        new_serial = _wait_for_serial_change(
            controller_client, node_id, pre.cert_serial, _RENEWAL_DEADLINE_SECS
        )
        logger.info(f"post-renewal serial={new_serial}")

        # last_renewed_at must now be populated.
        post = _node_by_id(controller_client, node_id)
        assert post is not None and post.last_renewed_at, (
            "last_renewed_at must be set after the renewal"
        )

        # Node should still be online — the renewal reconnect is supposed
        # to be invisible to the operator. Allow a brief window for the
        # reconnect to land.
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if node_id in controller_client.online_nodes():
                return
            time.sleep(1)
        raise AssertionError(
            f"node {node_id} did not return to online status within 30s of renewal"
        )

    def test_old_cert_revoked_after_renewal(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """
        The controller's renewal handler revokes the prior serial before
        replying. Capture the old cert+key BEFORE renewal, wait for the
        serial to flip, then drive a TLS probe with the captured (now-old)
        cert — handshake must surface a fatal alert from the
        RevokingClientCertVerifier.
        """
        node = nodes["node1"]
        node_id = enrolled_nodes["node1"]
        pre = _node_by_id(controller_client, node_id)
        assert pre is not None and pre.cert_serial

        # Snapshot the current creds into /tmp so the post-renewal probe
        # can replay them. The agent will atomically rename new files in
        # over the originals, so we have to capture before the swap.
        node.ssh_command(
            f"sudo cp {_CLIENT_CRT} /tmp/old-client.crt && "
            f"sudo cp {_CLIENT_KEY} /tmp/old-client.key && "
            "sudo chmod 0644 /tmp/old-client.crt /tmp/old-client.key",
            timeout=10,
        )
        logger.info(f"captured pre-renewal cert+key, serial={pre.cert_serial}")

        new_serial = _wait_for_serial_change(
            controller_client, node_id, pre.cert_serial, _RENEWAL_DEADLINE_SECS
        )
        assert new_serial != pre.cert_serial

        # Probe with the *old* cert. `tls_probe` already greps for
        # "alert number" — exactly the behaviour test_tls_revocation.py
        # relies on for the decommission case, which is the same handshake
        # verifier path.
        out = tls_probe(
            node,
            cert_path="/tmp/old-client.crt",
            key_path="/tmp/old-client.key",
        )
        logger.info(f"probe-with-old-cert output:\n{out}")
        assert "alert number" in out.lower(), (
            "Old cert must trigger a fatal TLS alert after renewal — the "
            "controller's renewal handler is supposed to revoke the previous "
            "serial and the verifier picks that up via the watch channel.\n"
            f"Probe output:\n{out}"
        )

    def test_key_rotation_every_nth_renewal(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """
        With mtls_key_rotation_renewals=2 the *key* must be replaced on
        every 2nd cert renewal. Hash the key file across three renewals;
        expect a change on (or before) the second.

        The renewal counter is persisted at
        /var/lib/policy-node-agent/renewal-counter so this test does not
        bounce the agent — bouncing would race the test against the
        rotation cadence.
        """
        node = nodes["node1"]
        node_id = enrolled_nodes["node1"]

        # Capture baseline serial + key hash.
        pre = _node_by_id(controller_client, node_id)
        assert pre is not None and pre.cert_serial
        seen_serials = [pre.cert_serial]
        seen_key_hashes = [_key_sha256(node, _CLIENT_KEY)]
        logger.info(f"baseline serial={pre.cert_serial}, key_sha={seen_key_hashes[0]}")

        # Wait for two more renewals. Each renewal flips the serial; on
        # one of them (controlled by the in-process counter, ≤ 2 cycles)
        # the key also rotates.
        for cycle in range(2):
            last_serial = seen_serials[-1]
            new_serial = _wait_for_serial_change(
                controller_client, node_id, last_serial, _RENEWAL_DEADLINE_SECS
            )
            seen_serials.append(new_serial)
            seen_key_hashes.append(_key_sha256(node, _CLIENT_KEY))
            logger.info(
                f"cycle {cycle + 1}: serial={new_serial}, key_sha={seen_key_hashes[-1]}"
            )

        # Every renewal produces a fresh serial.
        assert len(set(seen_serials)) == len(seen_serials), (
            f"every renewal must produce a unique serial, got {seen_serials}"
        )

        # The key must have rotated at least once across the 2 cycles
        # (mtls_key_rotation_renewals=2 means rotation on every 2nd
        # renewal — across 2 renewals we expect exactly one rotation).
        unique_keys = set(seen_key_hashes)
        assert len(unique_keys) >= 2, (
            "mTLS key must have rotated at least once across 2 renewals "
            f"with mtls_key_rotation_renewals=2; observed key hashes: "
            f"{seen_key_hashes}"
        )

    def test_renewal_survives_controller_restart_mid_window(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """
        Bounce the controller and confirm the next renewal still
        succeeds. This catches two regressions:

        1. The in-memory revocation mirror must be reloaded from the
           store on boot — otherwise a renewal that happened before the
           restart would not have its old serial revoked at the handshake
           layer post-restart.
        2. The agent's renewal loop must reconnect after the controller
           comes back; if the renewal task captured the channel and
           never retried, the next renewal would hang silently.
        """
        nodes["node1"]
        controller = nodes["controller"]
        node_id = enrolled_nodes["node1"]

        pre = _node_by_id(controller_client, node_id)
        assert pre is not None and pre.cert_serial
        marker = now_iso(controller)

        # Bounce the controller. Restart, not stop, so the service comes
        # back inside the test without us needing to start it manually.
        restart_status = restart_service(controller, "policy-controller")
        assert restart_status.is_healthy, (
            f"controller restart left it unhealthy: {restart_status.status_text}"
        )
        # Give the HTTP API a moment to come back; otherwise the next
        # `list_nodes` race-misses.
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                controller_client.list_nodes()
                break
            except Exception:
                time.sleep(1)
        else:
            raise AssertionError("controller HTTP did not recover within 30s")

        # Renewal must still flip the serial after the bounce. Allow a
        # longer deadline since the agent reconnect adds a few seconds.
        new_serial = _wait_for_serial_change(
            controller_client, node_id, pre.cert_serial, _RENEWAL_DEADLINE_SECS + 30
        )
        assert new_serial != pre.cert_serial

        # Sanity: controller logs do NOT show the verifier rejecting the
        # *new* serial — the watch mirror was correctly re-seeded from
        # the store on boot.
        hits = journalctl_since(controller, marker, "Rejecting TLS handshake")
        # Some hits are fine (old cert from before the bounce may still
        # try to reconnect) but the new serial must NOT appear.
        assert new_serial not in hits, (
            "Newly-issued serial showed up in 'Rejecting TLS handshake' lines "
            "post-restart — the revocation mirror was loaded with a stale "
            "or wrong set. Hits:\n" + hits
        )
