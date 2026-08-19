# Copyright (c) Dufferin Software

"""
Controller WebSocket bearer-auth tests.

`/ws/events` and `/ws/rule-events` accept the same `dsw_…` token as the
REST + GraphQL surface, but browsers can't set custom headers on a WS
connect, so the token rides in the query string (`?token=dsw_…`).

These tests exercise the auth gate via curl with WebSocket upgrade
headers — curl returns the response status code (101 on accepted
upgrade, 401 on auth failure) without needing a real WS client on the
controller VM.
"""

import logging

import pytest

from netsim.testkit.node import Node

logger = logging.getLogger(__name__)

_CONTROLLER_URL = "http://127.0.0.1:8443"
_WS_PATHS = ["/ws/events", "/ws/rule-events"]


def _ws_upgrade_status(controller: Node, url: str) -> str:
    """
    Send a WebSocket upgrade request via curl and return the HTTP status
    code. We don't actually drive the WS protocol — just observe the
    status line on the upgrade handshake.

    Implementation note: on a successful upgrade the server sends `101
    Switching Protocols` and then keeps the TCP connection open forever
    waiting for WS frames. The old `-o /dev/null -w '%{http_code}'` form
    relied on curl exiting 0 after --max-time, which curl >= 7.85 no
    longer does (it always exits 28 on timeout). Instead, pipe `-i`
    output through `head -1` so the pipe closes as soon as the status
    line lands, curl gets SIGPIPE, and we get the code with no timeout
    games. `set +o pipefail` keeps the shell pipeline's exit status from
    surfacing curl's death from SIGPIPE.
    """
    cmd = (
        "set +o pipefail; "
        "curl -s -i --max-time 5 "
        "-H 'Connection: Upgrade' -H 'Upgrade: websocket' "
        "-H 'Sec-WebSocket-Version: 13' "
        "-H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' "
        f"{url!r} | head -1 | awk '{{print $2}}'"
    )
    return controller.ssh_command(cmd, timeout=10).strip()


class TestControllerWsAuth:
    """Auth gate on the controller's WebSocket endpoints."""

    @pytest.mark.parametrize("path", _WS_PATHS)
    def test_missing_token_returns_401(
        self, nodes, controller_service, controller_api_token, path
    ):
        """No `?token=…` → 401, no WS upgrade."""
        controller = nodes["controller"]
        url = f"{_CONTROLLER_URL}{path}"
        assert _ws_upgrade_status(controller, url) == "401"

    @pytest.mark.parametrize("path", _WS_PATHS)
    def test_invalid_token_returns_401(
        self, nodes, controller_service, controller_api_token, path
    ):
        """`?token=dsw_garbage` → 401."""
        controller = nodes["controller"]
        url = f"{_CONTROLLER_URL}{path}?token=dsw_garbage"
        assert _ws_upgrade_status(controller, url) == "401"

    @pytest.mark.parametrize("path", _WS_PATHS)
    def test_valid_token_upgrades(
        self, nodes, controller_service, controller_api_token, path
    ):
        """A real `dsw_…` minted by the fixture → 101 Switching Protocols."""
        controller = nodes["controller"]
        url = f"{_CONTROLLER_URL}{path}?token={controller_api_token}"
        assert _ws_upgrade_status(controller, url) == "101"
