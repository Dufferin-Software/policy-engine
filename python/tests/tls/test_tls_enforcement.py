# Copyright (c) Dufferin Software

"""
TLS enforcement tests.

These tests use raw curl and policy-client invocations to verify that the
policy-engine server correctly enforces TLS transport security:

  - Plain HTTP connections to the HTTPS port must be refused.
  - HTTPS connections without the CA cert must fail certificate verification.
  - HTTPS connections with the CA cert (or -k) must succeed.
  - The policy-client CLI honours --tls-ca-cert and --tls-insecure.
  - The WebSocket event stream is accessible over WSS.

None of these tests depend on the parameterised policy_client fixture; they
exercise the transport layer directly via SSH commands.
"""

import logging


logger = logging.getLogger(__name__)


class TestTlsEnforcement:
    """Verify that the policy-engine server enforces TLS correctly."""

    def test_plain_http_rejected(self, nodes, policy_engine_tls):
        """
        Plain HTTP connections to the HTTPS port must fail.

        When actix-web binds with bind_rustls_0_23 the port speaks TLS only.
        A clear-text HTTP request triggers a TLS parse error on the server side
        and curl exits non-zero.
        """
        server = nodes["server"]
        port = policy_engine_tls["port"]

        result = server.ssh_command(
            f"curl -s http://127.0.0.1:{port}/health --max-time 5 2>&1 || echo CURL_FAILED",
            timeout=15,
        )
        assert "CURL_FAILED" in result, (
            f"Plain HTTP to TLS port {port} should have failed, got: {result!r}"
        )

    def test_https_with_ca_cert_succeeds(self, nodes, policy_engine_tls):
        """HTTPS with the correct CA cert must return HTTP 200 from /health."""
        server = nodes["server"]
        port = policy_engine_tls["port"]
        cert = policy_engine_tls["cert"]

        code = server.ssh_command(
            f"curl -s -o /dev/null -w '%{{http_code}}' "
            f"--cacert {cert} "
            f"--max-time 5 https://127.0.0.1:{port}/health",
            timeout=15,
        ).strip()
        assert code == "200", f"Expected HTTP 200 with valid CA cert, got: {code!r}"

    def test_https_rejected_without_cert(self, nodes, policy_engine_tls):
        """
        HTTPS without supplying a CA cert must fail with a certificate
        verification error, not a connection error.

        curl exits with code 60 (SSL peer certificate or SSH remote key was
        not OK) for self-signed certs when no --cacert is provided.
        """
        server = nodes["server"]
        port = policy_engine_tls["port"]

        result = server.ssh_command(
            f"curl -sv https://127.0.0.1:{port}/health --max-time 5 2>&1 || echo CURL_FAILED",
            timeout=15,
        )
        assert "CURL_FAILED" in result, (
            f"HTTPS without CA cert should have failed, got: {result!r}"
        )
        assert any(
            phrase in result
            for phrase in ("certificate", "SSL", "verify", "self-signed", "self signed")
        ), f"Expected a TLS cert verification error, got: {result!r}"

    def test_https_insecure_flag_succeeds(self, nodes, policy_engine_tls):
        """HTTPS with -k (skip verification) must succeed for self-signed certs."""
        server = nodes["server"]
        port = policy_engine_tls["port"]

        code = server.ssh_command(
            f"curl -sk -o /dev/null -w '%{{http_code}}' "
            f"--max-time 5 https://127.0.0.1:{port}/health",
            timeout=15,
        ).strip()
        assert code == "200", f"Expected HTTP 200 with -k, got: {code!r}"

    def test_cli_client_with_ca_cert_succeeds(self, nodes, policy_engine_tls):
        """policy-client --tls-ca-cert must connect and return server status."""
        server = nodes["server"]
        port = policy_engine_tls["port"]
        cert = policy_engine_tls["cert"]

        output = server.ssh_command(
            f"policy-client --json "
            f"--server https://127.0.0.1:{port}/graphql "
            f"--tls-ca-cert {cert} "
            f"status",
            timeout=15,
        )
        assert "version" in output, f"Expected server status JSON, got: {output!r}"

    def test_cli_client_without_cert_fails(self, nodes, policy_engine_tls):
        """
        policy-client without any TLS cert options must fail when connecting to
        a server that presents a self-signed certificate.

        In --json mode policy-client reports errors as JSON and exits 0, so we
        accept either a non-zero exit (CLI_FAILED) or a JSON failure response
        as evidence that the TLS verification was rejected.
        """
        server = nodes["server"]
        port = policy_engine_tls["port"]

        result = server.ssh_command(
            f"policy-client --json "
            f"--server https://127.0.0.1:{port}/graphql "
            f"status 2>&1 || echo CLI_FAILED",
            timeout=15,
        )
        failed = "CLI_FAILED" in result or '"success": false' in result
        assert failed, (
            f"policy-client without TLS args should have failed, got: {result!r}"
        )

    def test_cli_client_insecure_flag_succeeds(self, nodes, policy_engine_tls):
        """policy-client --tls-insecure must succeed despite a self-signed cert."""
        server = nodes["server"]
        port = policy_engine_tls["port"]

        output = server.ssh_command(
            f"policy-client --json "
            f"--server https://127.0.0.1:{port}/graphql "
            f"--tls-insecure "
            f"status",
            timeout=15,
        )
        assert "version" in output, f"Expected server status JSON, got: {output!r}"

    def test_wss_events_stream(self, nodes, policy_engine_tls, websocket_installed):
        """
        The /ws/events WebSocket endpoint must be reachable over WSS.

        When the HTTP server uses TLS every endpoint — including the WebSocket
        upgrade — is served over the same TLS port.  We verify that the
        WebSocket handshake completes successfully using the test CA cert.
        """
        server = nodes["server"]
        port = policy_engine_tls["port"]
        cert = policy_engine_tls["cert"]

        output = server.ssh_command(
            f'python3 -c "'
            f"import websocket; "
            f"ws = websocket.WebSocket(sslopt={{'ca_certs': '{cert}'}}); "
            f"ws.connect('wss://127.0.0.1:{port}/ws/events', timeout=5); "
            f"ws.close(); "
            f"print('WSS_OK')\"",
            timeout=20,
        )
        assert "WSS_OK" in output, f"WSS connection failed: {output!r}"
