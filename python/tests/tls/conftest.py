# Copyright (c) Dufferin Software

"""
Fixtures for the TLS test package.

Uses a proper two-cert PKI so that rustls/webpki cert validation works:

  CA cert  — self-signed, CA:TRUE, used by clients (--cacert / --tls-ca-cert)
  Server cert — signed by the CA, SAN=IP:127.0.0.1, used by policy-engine

A self-signed cert that is both root CA and server leaf is rejected by
rustls/webpki even with basicConstraints=CA:TRUE; a proper two-cert chain is
required.

Also writes a minimal systemd drop-in that strips all CLI args from ExecStart
so that no inherited flags (e.g. --port 8080 from the installed unit) override
the config file.  Both the config file and drop-in are removed on teardown.
"""

import logging
import time
from typing import Union

import pytest

from netsim.testkit.systemd_utils import restart_service, stop_service
from policy_engine_client.engine.cli.client import PolicyClient
from policy_engine_client.engine.graphql.client import GraphQLPolicyClient

logger = logging.getLogger(__name__)

# HTTPS port used for TLS tests — deliberately different from the default
# HTTP port (8080) so that any stale plain-HTTP listener does not interfere.
_TLS_PORT = 8443

# CA cert used by clients for verification.
_TLS_CA_CERT_PATH = "/etc/policy-engine/tls-ca.crt"
_TLS_CA_KEY_PATH = "/etc/policy-engine/tls-ca.key"

# Server cert + key used by policy-engine.
_TLS_CERT_PATH = "/etc/policy-engine/tls-test.crt"
_TLS_KEY_PATH = "/etc/policy-engine/tls-test.key"

# Config file written by the test fixture to configure TLS.
_CONFIG_FILE = "/etc/policy-engine/config.toml"

# Systemd drop-in that strips inherited CLI args so the config file wins.
_SYSTEMD_OVERRIDE_DIR = "/etc/systemd/system/policy-engine.service.d"
_SYSTEMD_OVERRIDE_FILE = f"{_SYSTEMD_OVERRIDE_DIR}/tls-test.conf"

_HTTPS_READY_TIMEOUT = 30
_HTTPS_READY_INTERVAL = 0.5


def _wait_for_policy_engine_https(
    server, ca_cert_path: str, port: int, timeout: int = _HTTPS_READY_TIMEOUT
) -> None:
    """
    Block until the policy-engine HTTPS server is accepting TLS connections.

    Uses curl with --cacert so the CA certificate is verified.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            out = server.ssh_command(
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"--cacert {ca_cert_path} "
                f"--max-time 2 https://127.0.0.1:{port}/health 2>/dev/null || true",
                timeout=10,
            )
            if out.strip() and out.strip() != "000":
                logger.info(f"policy-engine HTTPS server ready on port {port}")
                return
        except Exception:
            pass
        time.sleep(_HTTPS_READY_INTERVAL)
    pytest.fail(f"policy-engine HTTPS server did not become ready within {timeout}s")


@pytest.fixture(scope="package")
def tls_certs(nodes, install_user_packages):
    """
    Generate a two-cert PKI on the server node:

      - A self-signed EC CA certificate (CA:TRUE) used by clients for
        verification (--cacert / --tls-ca-cert).
      - A server certificate signed by that CA, with SAN=IP:127.0.0.1,
        used by policy-engine for TLS.

    A proper CA→server chain is required because rustls/webpki does not
    allow a single self-signed cert to act as both trust anchor and end entity,
    even when basicConstraints=CA:TRUE is present.

    Depends on install_user_packages to ensure /etc/policy-engine/ exists.

    Yields (ca_cert_path, server_cert_path, server_key_path).
    """
    server = nodes["server"]

    server.ssh_command("sudo mkdir -p /etc/policy-engine", timeout=10)

    # Single compound command: generate CA, then generate and sign server cert.
    server.ssh_command(
        # Step 1: CA key + self-signed CA cert (no SAN needed on the CA cert).
        f"sudo openssl ecparam -name P-256 -genkey -noout -out {_TLS_CA_KEY_PATH} && "
        f"sudo openssl req -x509 -new -key {_TLS_CA_KEY_PATH} -sha256 -days 365 "
        f"  -subj '/CN=Policy Engine Test CA' "
        f"  -addext 'basicConstraints=critical,CA:TRUE' "
        f"  -addext 'keyUsage=critical,keyCertSign,digitalSignature' "
        f"  -out {_TLS_CA_CERT_PATH} && "
        # Step 2: Server key + CSR.
        f"sudo openssl ecparam -name P-256 -genkey -noout -out {_TLS_KEY_PATH} && "
        f"sudo openssl req -new -key {_TLS_KEY_PATH} -subj '/CN=127.0.0.1' "
        f"  -out /tmp/pe-server.csr && "
        # Step 3: Sign server cert with CA; embed SAN extension.
        f"printf '[ext]\\nsubjectAltName=IP:127.0.0.1\\n' | "
        f"sudo tee /tmp/pe-server.ext > /dev/null && "
        f"sudo openssl x509 -req -in /tmp/pe-server.csr "
        f"  -CA {_TLS_CA_CERT_PATH} -CAkey {_TLS_CA_KEY_PATH} "
        f"  -CAcreateserial -days 365 -sha256 "
        f"  -extfile /tmp/pe-server.ext -extensions ext "
        f"  -out {_TLS_CERT_PATH} && "
        # Permissions + cleanup.
        f"sudo chmod 600 {_TLS_KEY_PATH} {_TLS_CA_KEY_PATH} && "
        f"sudo chmod 644 {_TLS_CERT_PATH} {_TLS_CA_CERT_PATH} && "
        f"sudo rm -f /tmp/pe-server.csr /tmp/pe-server.ext "
        f"  {_TLS_CA_CERT_PATH[:-4]}.srl",
        timeout=30,
    )
    logger.info(
        f"Generated CA cert at {_TLS_CA_CERT_PATH}, server cert at {_TLS_CERT_PATH}"
    )

    yield _TLS_CA_CERT_PATH, _TLS_CERT_PATH, _TLS_KEY_PATH

    server.ssh_command(
        f"sudo rm -f {_TLS_CA_CERT_PATH} {_TLS_CA_KEY_PATH} "
        f"  {_TLS_CERT_PATH} {_TLS_KEY_PATH} || true",
        timeout=10,
    )


@pytest.fixture(scope="package")
def policy_engine_tls(nodes, tls_certs):
    """
    Start policy-engine with TLS enabled on _TLS_PORT.

    Writes /etc/policy-engine/config.toml with the [server] section using the
    server cert and key.  Writes a systemd drop-in that resets ExecStart to
    just the binary so no inherited CLI args (e.g. --port 8080) override the
    config file.

    Yields a dict: {"cert": ca_cert_path, "port": port}.
    "cert" is the CA cert path — use it with --cacert / --tls-ca-cert.
    """
    server = nodes["server"]
    ca_cert_path, server_cert_path, server_key_path = tls_certs

    check = server.ssh_command(
        "systemctl cat policy-engine.service >/dev/null 2>&1 && echo EXISTS || echo MISSING"
    )
    if "MISSING" in check:
        pytest.skip(
            "policy-engine.service not installed (check 'packages' in the topology yaml)"
        )

    # Stop Suricata to prevent crash-loops on VMs that have it pre-installed.
    try:
        server.ssh_command(
            "sudo systemctl stop suricata 2>/dev/null || true && "
            "sudo systemctl disable suricata 2>/dev/null || true",
            timeout=15,
        )
    except Exception:
        pass

    # Write the config file — server uses its own cert/key.
    config_toml = (
        "[server]\n"
        f"port     = {_TLS_PORT}\n"
        f'tls_cert = "{server_cert_path}"\n'
        f'tls_key  = "{server_key_path}"\n'
    )
    server.ssh_command("sudo mkdir -p /etc/policy-engine", timeout=10)
    server.ssh_command_with_stdin(
        f"sudo tee {_CONFIG_FILE}",
        config_toml,
        timeout=10,
    )
    logger.info(f"Wrote TLS config to {_CONFIG_FILE}")

    # Drop-in that resets ExecStart to the bare binary so no inherited CLI
    # args (e.g. --port 8080) can override the config file.
    binary = server.ssh_command(
        "systemctl cat policy-engine.service "
        "| grep '^ExecStart=' "
        "| sed 's/ExecStart=//' "
        "| awk '{print $1}'",
        timeout=10,
    ).strip()
    if not binary:
        binary = server.ssh_command("which policy-engine", timeout=10).strip()

    override = "[Service]\nExecStart=\nExecStart={binary}\n".format(binary=binary)
    server.ssh_command(f"sudo mkdir -p {_SYSTEMD_OVERRIDE_DIR}", timeout=10)
    server.ssh_command_with_stdin(
        f"sudo tee {_SYSTEMD_OVERRIDE_FILE}",
        override,
        timeout=10,
    )
    server.ssh_command("sudo systemctl daemon-reload", timeout=15)

    status = restart_service(server, "policy-engine")
    if not status.is_healthy:
        pytest.fail(f"Failed to start policy-engine with TLS: {status.status_text}")

    _wait_for_policy_engine_https(server, ca_cert_path, _TLS_PORT)

    yield {"cert": ca_cert_path, "port": _TLS_PORT}

    try:
        stop_service(server, "policy-engine")
    except Exception as e:
        logger.warning(f"Failed to stop policy-engine: {e}")

    # Remove the config file and drop-in so other test packages start clean.
    server.ssh_command(
        f"sudo rm -f {_CONFIG_FILE} {_SYSTEMD_OVERRIDE_FILE} && "
        f"sudo systemctl daemon-reload || true",
        timeout=15,
    )


@pytest.fixture(scope="package")
def cli_tls_policy_client(nodes, policy_engine_tls):
    """CLI PolicyClient that connects over HTTPS with the test CA cert."""
    server = nodes["server"]
    return PolicyClient(
        server,
        server_url=f"https://127.0.0.1:{policy_engine_tls['port']}/graphql",
        tls_ca_cert=policy_engine_tls["cert"],
    )


@pytest.fixture(scope="package")
def graphql_tls_policy_client(nodes, policy_engine_tls):
    """GraphQL PolicyClient that connects over HTTPS with the test CA cert."""
    server = nodes["server"]
    return GraphQLPolicyClient(
        server,
        server_url=f"https://127.0.0.1:{policy_engine_tls['port']}/graphql",
        tls_ca_cert=policy_engine_tls["cert"],
    )


AnyPolicyClient = Union[PolicyClient, GraphQLPolicyClient]


@pytest.fixture(scope="module", params=["cli", "graphql"], ids=["cli", "graphql"])
def client_type(request):
    """Parameterized fixture: each test module runs once with CLI, once with GraphQL."""
    return request.param


@pytest.fixture(scope="module")
def policy_client(
    client_type, cli_tls_policy_client, graphql_tls_policy_client
) -> AnyPolicyClient:
    """Returns the TLS-enabled CLI or GraphQL client based on client_type."""
    if client_type == "cli":
        return cli_tls_policy_client
    return graphql_tls_policy_client


@pytest.fixture(scope="package")
def server_interface(node_interfaces):
    """Server's data interface on net1."""
    return node_interfaces["server"]["net1"]


@pytest.fixture(scope="package")
def websocket_installed(nodes, install_packages):
    """Ensure python3-websocket is available on the server node."""
    install_packages("server", ["python3-websocket"])
    yield
