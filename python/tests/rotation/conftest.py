# Copyright (c) Peter Morrow

"""
Fixtures for the credential-rotation suite.

Topology: 1 controller VM + 1 managed node (node1) on a shared management net.

The rotation suite exercises the credential lifecycle on the management
channel: revocation at the TLS handshake (Phase 7 track #2 of
docs/enrollment-crypto.md), and — over time — cert renewal and CA rotation.
The fixtures mirror tests/multi_node/conftest.py but are scoped down to a
single managed node since credential lifecycle is per-node.
"""

import ipaddress
import logging
import time
from typing import Dict, List

import pytest

from netsim.testkit.node import Node
from netsim.testkit.systemd_utils import restart_service, stop_service
from policy_engine_client.controller.graphql.client import (
    ControllerClient,
    mint_api_token,
)

logger = logging.getLogger(__name__)

_CONTROLLER_HTTP_TIMEOUT = 60
_ENROLLMENT_TIMEOUT = 120
_ACTIVE_TIMEOUT = 60
_POLL_INTERVAL = 2

_MANAGED_NODES = ["node1", "node2", "node3"]

# Short cert TTL used across the rotation suite so renewal e2e tests complete
# in seconds rather than days. The minimum the controller's config validator
# accepts is 10s (see fleet/controller/src/config.rs:MIN_NODE_CERT_TTL_SECS);
# 60s gives the 2/3 renewal window (~40s) enough headroom to fit comfortably
# inside an 8-minute pytest timeout while still leaving room for the agent to
# pick up the renew_at trigger on a 5s tick.
_TEST_NODE_CERT_TTL_SECS = 60
_TEST_RENEWAL_CHECK_INTERVAL_SECS = 5
# Rotate the *key* every 2 renewals (vs. prod default 4) so
# test_key_rotation_every_nth_renewal can observe a rotation in a short run.
_TEST_KEY_ROTATION_RENEWALS = 2


def _write_controller_config(controller: Node) -> None:
    """
    Overwrite /etc/policy-controller/config.toml with a short-TTL profile.

    Done before `controller_service` starts the daemon so the first issued
    server cert and every subsequent issued node cert are minted with the
    test TTL. Without this the controller would mint 90-day certs from the
    DEB defaults and renewal would never trigger inside the test run.
    """
    controller.ssh_command("sudo mkdir -p /etc/policy-controller", timeout=10)
    body = f"node_cert_ttl_secs = {_TEST_NODE_CERT_TTL_SECS}\n"
    controller.ssh_command_with_stdin(
        "sudo tee /etc/policy-controller/config.toml > /dev/null",
        body,
        timeout=10,
    )
    controller.ssh_command(
        "sudo chmod 0644 /etc/policy-controller/config.toml", timeout=10
    )


def _wait_for_controller_http(
    controller: Node, timeout: int = _CONTROLLER_HTTP_TIMEOUT
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            out = controller.ssh_command(
                "curl -s -o /dev/null -w '%{http_code}' "
                "--max-time 2 http://127.0.0.1:8443/health 2>/dev/null || true",
                timeout=10,
            )
            if out.strip() == "200":
                logger.info("policy-controller HTTP API is ready")
                return
        except Exception:
            pass
        time.sleep(_POLL_INTERVAL)
    pytest.fail(f"policy-controller HTTP API did not become ready within {timeout}s")


def _wait_for_active_by_hostname(
    client: ControllerClient,
    expected_hostnames: List[str],
    timeout: int = _ENROLLMENT_TIMEOUT,
) -> Dict[str, str]:
    deadline = time.monotonic() + timeout
    needed = set(expected_hostnames)
    while time.monotonic() < deadline:
        try:
            active = client.list_nodes(status="active")
            by_host = {n.hostname: n.id for n in active if n.hostname in needed}
            if needed.issubset(by_host.keys()):
                return by_host
        except Exception as e:
            logger.debug(f"poll error: {e}")
        time.sleep(_POLL_INTERVAL)
    pytest.fail(
        f"Hostnames {expected_hostnames} did not become Active within {timeout}s"
    )


def _wait_for_online(
    client: ControllerClient, ids: List[str], timeout: int = _ACTIVE_TIMEOUT
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            online = set(client.online_nodes())
            if all(nid in online for nid in ids):
                return
        except Exception as e:
            logger.debug(f"poll error: {e}")
        time.sleep(_POLL_INTERVAL)
    pytest.fail(f"Nodes {ids} did not come online within {timeout}s")


def _get_mgmt_ip(node: Node, topology) -> str:
    topo_node = topology.get_node(node.name)
    mgmt_net = topology.get_network(topo_node.networks[0])
    net = ipaddress.IPv4Network(mgmt_net.subnet, strict=False)
    out = node.ssh_command(
        "ip -4 addr show | awk '/inet / {print $2}' | cut -d/ -f1",
        timeout=10,
    ).strip()
    for s in out.splitlines():
        try:
            a = ipaddress.IPv4Address(s.strip())
            if a in net:
                return str(a)
        except ValueError:
            continue
    pytest.fail(f"No mgmt IP for {node.name}")


def _write_agent_config(node: Node) -> None:
    node.ssh_command("sudo mkdir -p /etc/policy-node-agent", timeout=10)
    # Lower the renewal-check interval and key-rotation cadence so renewal
    # tests observe behaviour within a few minutes. Prod defaults
    # (3600s / every 4 renewals) would never trigger inside a test window.
    body = (
        'local_server_url = "http://127.0.0.1:8080/graphql"\n'
        f"renewal_check_interval_secs = {_TEST_RENEWAL_CHECK_INTERVAL_SECS}\n"
        f"mtls_key_rotation_renewals = {_TEST_KEY_ROTATION_RENEWALS}\n"
    )
    node.ssh_command_with_stdin(
        "sudo tee /etc/policy-node-agent/config.toml > /dev/null",
        body,
        timeout=10,
    )


def _write_hosts_entry(node: Node, controller_ip: str) -> None:
    entry = f"{controller_ip} policy-controller"
    for target in ["/etc/hosts", "/etc/cloud/templates/hosts.debian.tmpl"]:
        node.ssh_command(
            f"sudo sed -i '/\\bpolicy-controller\\b/d' {target}", timeout=10
        )
        node.ssh_command(
            f"echo '{entry}' | sudo tee -a {target} > /dev/null", timeout=10
        )


def _write_bootstrap_bundle(node: Node, bundle_b64: str) -> None:
    node.ssh_command("sudo mkdir -p /etc/policy-node-agent", timeout=10)
    node.ssh_command_with_stdin(
        "sudo tee /etc/policy-node-agent/bootstrap.bundle > /dev/null",
        bundle_b64,
        timeout=10,
    )
    node.ssh_command(
        "sudo chmod 0644 /etc/policy-node-agent/bootstrap.bundle", timeout=10
    )


@pytest.fixture(scope="package")
def controller_service(nodes, install_user_packages):
    controller = nodes["controller"]
    check = controller.ssh_command(
        "systemctl cat policy-controller.service >/dev/null 2>&1 && echo EXISTS || echo MISSING"
    )
    if "MISSING" in check:
        pytest.skip(
            "policy-controller.service not installed (check 'packages' in the topology yaml)"
        )
    # Drop short-TTL config *before* starting the service so the very first
    # node cert is minted with the test TTL.
    _write_controller_config(controller)
    status = restart_service(controller, "policy-controller")
    if not status.is_healthy:
        pytest.fail(f"Failed to start policy-controller: {status.status_text}")
    _wait_for_controller_http(controller)
    yield status
    try:
        stop_service(controller, "policy-controller")
    except Exception as e:
        logger.warning(f"stop policy-controller: {e}")


@pytest.fixture(scope="package")
def controller_api_token(nodes, controller_service) -> str:
    """Mint a bearer token for this test package via SSH."""
    import time

    return mint_api_token(nodes["controller"], f"netsim-rotation-{int(time.time())}")


@pytest.fixture(scope="package")
def controller_client(
    nodes, controller_service, controller_api_token
) -> ControllerClient:
    return ControllerClient(nodes["controller"], api_token=controller_api_token)


@pytest.fixture(scope="package")
def node_services(
    nodes, topology, controller_client, install_user_packages, configure_node_interfaces
):
    controller_ip = _get_mgmt_ip(nodes["controller"], topology)
    logger.info(f"Controller mgmt IP: {controller_ip}")

    issued = controller_client.create_enrollment_token(
        enrollment_url="https://policy-controller:7776",
        controller_url="https://policy-controller:7777",
        ttl_seconds=3600,
        max_uses=len(_MANAGED_NODES),
        fleet_label="netsim-rotation",
    )
    logger.info(f"Minted ZTP bundle (token_id={issued.token_id})")

    for name in _MANAGED_NODES:
        node = nodes[name]
        for svc in ("policy-engine", "policy-node-agent"):
            check = node.ssh_command(
                f"systemctl cat {svc}.service >/dev/null 2>&1 && echo EXISTS || echo MISSING"
            )
            if "MISSING" in check:
                pytest.skip(f"{svc}.service not installed on {name}")
        _write_hosts_entry(node, controller_ip)
        _write_agent_config(node)
        _write_bootstrap_bundle(node, issued.bundle)
        pe = restart_service(node, "policy-engine")
        if not pe.is_healthy:
            pytest.fail(f"policy-engine on {name}: {pe.status_text}")
        ag = restart_service(node, "policy-node-agent")
        if not ag.is_healthy:
            pytest.fail(f"policy-node-agent on {name}: {ag.status_text}")
    yield
    for name in reversed(_MANAGED_NODES):
        node = nodes[name]
        for svc in ("policy-node-agent", "policy-engine"):
            try:
                stop_service(node, svc)
            except Exception as e:
                logger.warning(f"stop {svc} on {name}: {e}")


# ── Shared TLS / journal probes ───────────────────────────────────────────────
#
# These were originally inlined in test_tls_revocation.py; the renewal suite
# also needs them, so they live here. Both files import via
# `from tests.rotation.conftest import ...` (pytest exposes conftest helpers
# this way as long as the file is on the import path).

_CLIENT_CRT = "/var/lib/policy-node-agent/controller-client.crt"
_CLIENT_KEY = "/var/lib/policy-node-agent/controller-client.key"
_CA_CRT = "/var/lib/policy-node-agent/controller-ca.crt"


def tls_probe(
    node: Node,
    cert_path: str = _CLIENT_CRT,
    key_path: str = _CLIENT_KEY,
    ca_path: str = _CA_CRT,
) -> str:
    """
    Drive a single mTLS handshake + one post-handshake read against the
    controller management port.

    Defaults probe with the *current* on-disk creds. Callers can supply
    explicit paths to probe with a previously-captured (now-revoked) cert
    — used by `test_old_cert_revoked_after_renewal`.

    `timeout 5` bounds the wait when the server is *not* alerting (the
    healthy pre-revocation baseline).
    """
    return node.ssh_command(
        " ".join(
            [
                "timeout 5 sudo openssl s_client",
                "-connect policy-controller:7777",
                "-servername policy-controller",
                "-alpn h2",
                f"-CAfile {ca_path}",
                f"-cert {cert_path}",
                f"-key {key_path}",
                "-ign_eof",
                "</dev/null 2>&1",
                "; echo EXIT=$?",
            ]
        ),
        timeout=30,
    )


def journalctl_since(controller: Node, since_iso: str, pattern: str) -> str:
    """Grep the controller's journal for `pattern` since `since_iso`."""
    return controller.ssh_command(
        "sudo journalctl -u policy-controller "
        f"--since '{since_iso}' --no-pager | grep -F '{pattern}' || true",
        timeout=15,
    )


def now_iso(controller: Node) -> str:
    """Capture the controller's clock as a journalctl-compatible timestamp."""
    return controller.ssh_command("date -u +'%Y-%m-%d %H:%M:%S'", timeout=10).strip()


@pytest.fixture(scope="package")
def enrolled_nodes(nodes, controller_client, node_services) -> Dict[str, str]:
    vm_hostnames: Dict[str, str] = {
        n: nodes[n].ssh_command("hostname", timeout=10).strip() for n in _MANAGED_NODES
    }
    by_host = _wait_for_active_by_hostname(
        controller_client, list(vm_hostnames.values())
    )
    approved = {vm: by_host[h] for vm, h in vm_hostnames.items()}
    for vm, nid in approved.items():
        controller_client.label_node(nid, vm)
        logger.info(f"ZTP-enrolled {vm} → {nid}")
    _wait_for_online(controller_client, list(approved.values()))
    return approved
