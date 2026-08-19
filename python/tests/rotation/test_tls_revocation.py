# Copyright (c) Dufferin Software

"""
Phase 7 (track #2): revocation at the TLS handshake.

After a node is decommissioned the controller's *handshake-layer* client-cert
verifier must reject the agent's old cert. The existing application-layer
check in `grpc/management.rs` will also reject the connection — what we need
to confirm is that the new check sits *underneath* gRPC and runs before any
application data is exchanged.

We prove this two ways from a single decommission event:

1. **TLS-level probe.** Run `openssl s_client` from the node with the agent's
   own credentials, then attempt a read from the socket. In TLS 1.3 the
   server validates the client cert *after* it sends its own Finished, so
   the client sees the handshake "succeed" — the fatal alert only arrives on
   the next read. By doing that read explicitly (and matching for an
   `alert`/`SSL alert` token in the openssl output) we observe the alert
   that the application layer would never produce.

2. **Controller log probe.** The verifier logs a single
   `"Rejecting TLS handshake — client cert serial …"` line via the `log`
   facade. journalctl-grepping for that message after the agent reconnects
   confirms the verifier — not the app-layer check — fired.

Run with:
  netsim start tests/rotation/rotation.yaml
  python3 -m pytest tests/rotation/ -v \\
      --package-dir ..
  netsim destroy tests/rotation/rotation.yaml
"""

import logging
import time
from typing import Dict


from netsim.testkit.node import Node
from netsim.testkit.systemd_utils import restart_service, stop_service
from policy_engine_client.controller.graphql.client import ControllerClient

logger = logging.getLogger(__name__)

_CLIENT_CRT = "/var/lib/policy-node-agent/controller-client.crt"
_CLIENT_KEY = "/var/lib/policy-node-agent/controller-client.key"
_CA_CRT = "/var/lib/policy-node-agent/controller-ca.crt"


def _tls_probe(node: Node) -> str:
    """
    Drive a single mTLS handshake and one post-handshake read against the
    controller's management port.

    `-ign_eof` keeps openssl alive after stdin closes so it can observe a
    fatal alert that the server sends after validating the client cert.
    `timeout 5` bounds the wait when the server is *not* alerting (i.e. the
    pre-decommission baseline, where the next thing on the wire would be a
    gRPC frame).
    """
    return node.ssh_command(
        " ".join(
            [
                "timeout 5 sudo openssl s_client",
                "-connect policy-controller:7777",
                "-servername policy-controller",
                "-alpn h2",
                f"-CAfile {_CA_CRT}",
                f"-cert {_CLIENT_CRT}",
                f"-key {_CLIENT_KEY}",
                "-ign_eof",
                "</dev/null 2>&1",
                "; echo EXIT=$?",
            ]
        ),
        timeout=30,
    )


def _journalctl_since(controller: Node, since_iso: str, pattern: str) -> str:
    """
    Grep the controller's journal for `pattern` since `since_iso`. Returns
    matching lines (possibly empty).
    """
    return controller.ssh_command(
        "sudo journalctl -u policy-controller "
        f"--since '{since_iso}' --no-pager | grep -F '{pattern}' || true",
        timeout=15,
    )


def _now_iso(controller: Node) -> str:
    """Capture the controller's clock as a journalctl-compatible timestamp."""
    return controller.ssh_command("date -u +'%Y-%m-%d %H:%M:%S'", timeout=10).strip()


class TestTlsHandshakeRevocation:
    def test_pre_decommission_handshake_succeeds(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """
        Baseline: with the agent enrolled and Active, the probe completes the
        handshake and stalls waiting for application data — no TLS alert. The
        `timeout 5` wrapper bounds the wait, so we expect EXIT=124 *and* no
        `alert` marker in the output.
        """
        node = nodes["node1"]
        out = _tls_probe(node)
        logger.info(f"pre-decommission probe:\n{out}")

        assert "EXIT=124" in out, (
            f"Expected the pre-decommission probe to hit the 5s timeout "
            f"(handshake OK, server speaks HTTP/2 SETTINGS, no alert). "
            f"Got:\n{out}"
        )
        # `alert number` is openssl's marker for a TLS alert reception — it is
        # only emitted when an alert is actually read off the wire. Other
        # substrings like 'tlsv1' or 'ssl' appear in the harmless handshake
        # banner and must not be used as alert signals.
        assert "alert number" not in out.lower(), (
            f"Pre-decommission probe saw a TLS alert it should not have:\n{out}"
        )

    def test_post_decommission_handshake_rejected_at_tls_layer(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """
        Core Phase 7 assertion: after decommission, the openssl probe receives
        a fatal TLS alert *before* any application data, AND the controller
        log contains the verifier's rejection line. Either signal in isolation
        could be explained by app-layer behavior; both together pin the
        rejection to the handshake-layer verifier.
        """
        node = nodes["node1"]
        controller = nodes["controller"]
        node_id = enrolled_nodes["node1"]

        # Stop the agent so its reconnect loop doesn't race the probe.
        stop_service(node, "policy-node-agent")

        pre = {n.id: n for n in controller_client.list_nodes()}[node_id]
        assert pre.cert_serial, (
            f"node1 ({node_id}) has no recorded cert_serial; revocation "
            f"would have no serial to target"
        )

        marker = _now_iso(controller)
        result = controller_client.decommission_node(node_id)
        assert result.success, f"decommissionNode failed: {result.message}"
        logger.info(f"Decommissioned {node_id} (serial={pre.cert_serial})")

        # Watch-channel propagation is synchronous from the GraphQL handler's
        # POV; this sleep is a guard against scheduling jitter only.
        time.sleep(1)

        # ── (1) Direct TLS probe must observe a fatal alert ─────────────
        out = _tls_probe(node)
        logger.info(f"post-decommission probe:\n{out}")
        # `alert number` is openssl's distinctive marker for "received a TLS
        # alert from the peer"; absent in any clean-handshake output.
        assert "alert number" in out.lower(), (
            f"Expected a fatal TLS alert in the openssl output after "
            f"decommission, got:\n{out}"
        )

        # ── (2) Controller journal must show the verifier rejection ─────
        # Restart the real agent so the controller's verifier sees its
        # presented (now-revoked) cert and emits the WARN line. This catches
        # cases where the agent retries on a path that bypasses the verifier.
        restart_service(node, "policy-node-agent")
        deadline = time.monotonic() + 30
        hits = ""
        while time.monotonic() < deadline:
            hits = _journalctl_since(controller, marker, "Rejecting TLS handshake")
            if hits.strip():
                break
            time.sleep(2)
        assert hits.strip(), (
            f"Controller log did not contain the verifier's rejection line "
            f"after decommission. journalctl since {marker} returned nothing "
            f"matching 'Rejecting TLS handshake'. This means the app-layer "
            f"check is rejecting the cert but the handshake-layer verifier "
            f"is not on the path."
        )
        logger.info(f"verifier rejection logged on controller:\n{hits}")
