# Copyright (c) Peter Morrow

"""
Fixtures for the consolidated SNI matching suite.

This suite replaces the older `policy_sanity/test_sni_matching.py` (which
exercised TCP rules with plain SYNs and therefore never actually parsed
an SNI) and `tests/quic_sni_matching/` (QUIC ingress only).  Coverage
goals:

* Real on-the-wire TLS ClientHellos (scapy-crafted) on the TCP path.
* Real on-the-wire QUIC v1 and v2 Initials (aioquic) on the UDP path.
* Both ingress (XDP) and egress (TC) where the test calls for it; each
  test attaches the direction it cares about explicitly so we don't pay
  for direction parametrisation we don't use.

Sender scripts deploy to whichever node originates the traffic for the
test in question.  Both TCP and QUIC senders live under this directory
and are pushed to the chosen node by the sender fixtures below.
"""

import base64
import logging
import time
from pathlib import Path
from typing import Callable, Iterator, Union

import netaddr
import pytest

from netsim.testkit.systemd_utils import restart_service, stop_service
from policy_engine_client.engine.cli.client import PolicyClient, PolicyAction
from policy_engine_client.engine.graphql.client import GraphQLPolicyClient

logger = logging.getLogger(__name__)

AnyPolicyClient = Union[PolicyClient, GraphQLPolicyClient]

_POLICY_ENGINE_URL = "http://127.0.0.1:8080/graphql"
_HTTP_READY_TIMEOUT = 30
_HTTP_READY_INTERVAL = 0.5

_TLS_SCRIPT_LOCAL = Path(__file__).parent / "tls_sni_send.py"
_QUIC_SCRIPT_LOCAL = Path(__file__).parent / "quic_sni_send.py"
_TLS_SCRIPT_REMOTE = "/usr/local/bin/tls_sni_send.py"
_QUIC_SCRIPT_REMOTE = "/usr/local/bin/quic_sni_send.py"

# Passive TCP listener used by the scapy TLS sender so the kernel three-way
# handshake completes and the ClientHello segment actually leaves the NIC.
# The listener accept-and-closes on every connection — we never need to
# answer the TLS handshake; the BPF SNI inspector runs on the data segment
# regardless.
_LISTENER_SCRIPT = """
import socket, sys
port = int(sys.argv[1])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port))
s.listen(128)
while True:
    try:
        c, _ = s.accept()
        try:
            c.recv(4096)
        except OSError:
            pass
        c.close()
    except KeyboardInterrupt:
        break
"""
_LISTENER_REMOTE = "/usr/local/bin/sni_tcp_listener.py"


# ============================================================================
# Policy engine service (server)
# ============================================================================


def _wait_for_policy_engine_http(server, timeout: int = _HTTP_READY_TIMEOUT) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            out = server.ssh_command(
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"--max-time 2 {_POLICY_ENGINE_URL} 2>/dev/null || true",
                timeout=10,
            )
            if out.strip() and out.strip() != "000":
                return
        except Exception:
            pass
        time.sleep(_HTTP_READY_INTERVAL)
    pytest.fail(f"policy-engine HTTP server did not become ready within {timeout}s")


@pytest.fixture(scope="package")
def policy_engine_service(nodes, install_user_packages):
    server = nodes["server"]
    check = server.ssh_command(
        "systemctl cat policy-engine.service >/dev/null 2>&1 && echo EXISTS || echo MISSING"
    )
    if "MISSING" in check:
        pytest.skip(
            "policy-engine.service not installed (check 'packages' in the topology yaml)"
        )

    # Suricata can saturate the VM if unconfigured — stop it for the duration.
    try:
        server.ssh_command(
            "sudo systemctl stop suricata 2>/dev/null || true && "
            "sudo systemctl disable suricata 2>/dev/null || true",
            timeout=15,
        )
    except Exception:
        pass

    status = restart_service(server, "policy-engine")
    if not status.is_healthy:
        pytest.fail(f"Failed to start policy-engine: {status.status_text}")
    _wait_for_policy_engine_http(server)

    yield status

    try:
        stop_service(server, "policy-engine")
    except Exception as e:
        logger.warning(f"Failed to stop policy-engine: {e}")


# ============================================================================
# Client parameterisation (cli / graphql)
# ============================================================================


@pytest.fixture(scope="module", params=["cli", "graphql"], ids=["cli", "graphql"])
def client_type(request):
    return request.param


@pytest.fixture(scope="package")
def cli_policy_client(nodes, policy_engine_service):
    return PolicyClient(nodes["server"])


@pytest.fixture(scope="package")
def graphql_policy_client(nodes, policy_engine_service):
    return GraphQLPolicyClient(nodes["server"])


@pytest.fixture(scope="module")
def policy_client(
    client_type, cli_policy_client, graphql_policy_client
) -> AnyPolicyClient:
    if client_type == "cli":
        return cli_policy_client
    return graphql_policy_client


# ============================================================================
# Interfaces & addresses
# ============================================================================


@pytest.fixture(scope="package")
def server_interface(node_interfaces):
    return node_interfaces["server"]["net1"]


@pytest.fixture(scope="package")
def client_interface(node_interfaces):
    return node_interfaces["client"]["net1"]


@pytest.fixture(scope="package")
def server_ip_v4(server_interface) -> netaddr.IPAddress:
    ip = server_interface.get_ip_address()
    if ip is None:
        pytest.skip("No IPv4 address configured on server interface")
    return ip


@pytest.fixture(scope="package")
def client_ip_v4(client_interface) -> netaddr.IPAddress:
    ip = client_interface.get_ip_address()
    if ip is None:
        pytest.skip("No IPv4 address configured on client interface")
    return ip


@pytest.fixture(scope="package")
def server_network_v4(server_interface):
    network = server_interface.get_ipv4_network()
    if network is None:
        pytest.skip("No IPv4 address configured on server interface")
    return str(network)


@pytest.fixture(scope="package")
def client_network_v4(client_interface):
    network = client_interface.get_ipv4_network()
    if network is None:
        pytest.skip("No IPv4 address configured on client interface")
    return str(network)


# ============================================================================
# Attach / detach
# ============================================================================


@pytest.fixture(scope="function")
def attached_egress(policy_client, server_interface, configure_node_interfaces):
    iface = server_interface.if_name
    result = policy_client.attach_egress(iface)
    if not result.success:
        pytest.fail(f"Failed to attach egress: {result.message}")
    yield iface
    try:
        policy_client.detach_egress(iface)
    except Exception as e:
        logger.warning(f"Failed to detach egress: {e}")


@pytest.fixture(scope="function")
def attached_ingress(policy_client, server_interface, configure_node_interfaces):
    iface = server_interface.if_name
    result = policy_client.attach_ingress(iface)
    if not result.success:
        pytest.fail(f"Failed to attach ingress: {result.message}")
    yield iface
    try:
        policy_client.detach_ingress(iface)
    except Exception as e:
        logger.warning(f"Failed to detach ingress: {e}")


@pytest.fixture(scope="function")
def clean_egress_rules(policy_client, server_interface):
    iface = server_interface.if_name
    policy_client.flush_rules(direction="egress")
    policy_client.clear_flow_verdicts(direction="egress")
    policy_client.set_default_action(
        PolicyAction.PASS, direction="egress", interface=iface
    )
    yield
    policy_client.flush_rules(direction="egress")
    policy_client.clear_flow_verdicts(direction="egress")
    policy_client.set_default_action(
        PolicyAction.PASS, direction="egress", interface=iface
    )


@pytest.fixture(scope="function")
def clean_ingress_rules(policy_client, server_interface):
    iface = server_interface.if_name
    policy_client.flush_rules(direction="ingress")
    policy_client.clear_flow_verdicts(direction="ingress")
    policy_client.set_default_action(
        PolicyAction.PASS, direction="ingress", interface=iface
    )
    yield
    policy_client.flush_rules(direction="ingress")
    policy_client.clear_flow_verdicts(direction="ingress")
    policy_client.set_default_action(
        PolicyAction.PASS, direction="ingress", interface=iface
    )


# ============================================================================
# Package installs on each node
# ============================================================================


@pytest.fixture(scope="package")
def scapy_installed(nodes, install_packages):
    """Install python3-scapy on the server so it can craft TLS ClientHellos."""
    install_packages("server", ["python3-scapy"])
    yield


@pytest.fixture(scope="package")
def aioquic_installed(nodes, install_packages):
    """Install python3-aioquic on the server for the QUIC Initial sender."""
    install_packages("server", ["python3-aioquic"])
    yield


@pytest.fixture(scope="package")
def bpftool_installed(nodes, install_packages):
    install_packages("server", ["bpftool"])
    yield


# ============================================================================
# Script deployment helpers
# ============================================================================


def _push_script(node, local_path: Path, remote_path: str) -> None:
    encoded = base64.b64encode(local_path.read_bytes()).decode()
    node.ssh_command(
        f"echo '{encoded}' | base64 -d | sudo tee {remote_path} >/dev/null && "
        f"sudo chmod +x {remote_path}"
    )


def _push_inline(node, content: str, remote_path: str) -> None:
    encoded = base64.b64encode(content.encode()).decode()
    node.ssh_command(
        f"echo '{encoded}' | base64 -d | sudo tee {remote_path} >/dev/null && "
        f"sudo chmod +x {remote_path}"
    )


# ============================================================================
# TCP TLS listener on the client (passive, for egress-direction tests)
# ============================================================================


@pytest.fixture(scope="package")
def tcp_sni_listener(nodes):
    """
    Start a passive TCP accept-and-close listener on the client node on
    a handful of common TLS ports.  The scapy TLS sender connects to one
    of these so the kernel completes the 3WHS and the ClientHello data
    segment actually leaves the server NIC for the TC inspector to see.
    """
    client = nodes["client"]
    _push_inline(client, _LISTENER_SCRIPT, _LISTENER_REMOTE)

    # Run a listener per port we use in tests.  443 and 8443 cover everything
    # the current suite needs; add more here when tests grow.
    pids = []
    for port in (443, 8443):
        out = client.ssh_command(
            f"sudo bash -c 'nohup python3 {_LISTENER_REMOTE} {port} "
            f">/tmp/sni_listener_{port}.log 2>&1 & echo $!'",
            timeout=10,
        )
        pid = out.strip().splitlines()[-1]
        pids.append((port, pid))
        logger.info(f"started TCP SNI listener on client:{port} pid={pid}")

    # Give the listeners a moment to bind.
    time.sleep(0.5)

    yield

    for port, pid in pids:
        try:
            client.ssh_command(f"sudo kill {pid} 2>/dev/null || true")
        except Exception:
            pass


# ============================================================================
# Sender callables
# ============================================================================


@pytest.fixture(scope="package")
def tls_sender(nodes, scapy_installed) -> Iterator[Callable]:
    """
    Return a callable that runs the scapy TLS ClientHello sender on the
    server (egress origin).  Returns the script's stdout for diagnostics.
    """
    server = nodes["server"]
    _push_script(server, _TLS_SCRIPT_LOCAL, _TLS_SCRIPT_REMOTE)

    def _send(
        target_ip,
        target_port: int,
        sni: str,
        *,
        pad_to: int = 0,
        src_port: int = 0,
    ) -> str:
        cmd = f"python3 {_TLS_SCRIPT_REMOTE} {target_ip} {target_port} {sni}"
        if pad_to:
            cmd += f" --pad-to {pad_to}"
        if src_port:
            cmd += f" --src-port {src_port}"
        out = server.ssh_command(cmd, timeout=15)
        logger.info(f"tls_sni_send: {out.strip()}")
        return out

    yield _send


@pytest.fixture(scope="package")
def quic_sender(nodes, aioquic_installed) -> Iterator[Callable]:
    """
    Return a callable that runs the QUIC Initial sender on the server
    (egress origin).  Supports v1 and v2 via the `version` kwarg.
    """
    server = nodes["server"]
    _push_script(server, _QUIC_SCRIPT_LOCAL, _QUIC_SCRIPT_REMOTE)

    def _send(
        target_ip,
        target_port: int,
        sni: str,
        *,
        version: str = "v1",
        src_port: int = 0,
    ) -> str:
        cmd = (
            f"python3 {_QUIC_SCRIPT_REMOTE} {target_ip} {target_port} {sni} "
            f"--version {version}"
        )
        if src_port:
            cmd += f" --src-port {src_port}"
        out = server.ssh_command(cmd, timeout=15)
        logger.info(f"quic_sni_send: {out.strip()}")
        return out

    yield _send


@pytest.fixture(scope="package")
def quic_sender_ingress(nodes, install_packages) -> Iterator[Callable]:
    """
    Variant of `quic_sender` that runs from the *client* node (server-side
    XDP ingress inspector under test).  Kept separate so the ingress fixture
    only installs aioquic where it's needed.
    """
    install_packages("client", ["python3-aioquic"])
    client = nodes["client"]
    _push_script(client, _QUIC_SCRIPT_LOCAL, _QUIC_SCRIPT_REMOTE)

    def _send(
        target_ip,
        target_port: int,
        sni: str,
        *,
        version: str = "v1",
        src_port: int = 0,
    ) -> str:
        cmd = (
            f"python3 {_QUIC_SCRIPT_REMOTE} {target_ip} {target_port} {sni} "
            f"--version {version}"
        )
        if src_port:
            cmd += f" --src-port {src_port}"
        out = client.ssh_command(cmd, timeout=15)
        logger.info(f"quic_sni_send (ingress): {out.strip()}")
        return out

    yield _send
