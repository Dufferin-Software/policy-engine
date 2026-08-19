# Copyright (c) Dufferin Software

"""
Fleet IPS/IDS: named Suricata ruleset distribution and drift reconcile.

Creates a fleet ruleset, assigns it to two capable nodes, and verifies the
materialised fleet-<name>.rules file lands on both (byte-verbatim, sha256
matches). Then updates the content and confirms drift reconvergence, and
unassigns to confirm the file is removed while node-local rule files are
never touched.

Run with:
  netsim start tests/fleet_ips_ids/fleet_ips_ids.yaml
  python3 -m pytest tests/fleet_ips_ids/test_ruleset_distribution.py -v --package-dir ..
  netsim destroy tests/fleet_ips_ids/fleet_ips_ids.yaml
"""

import hashlib
import logging
import time

import pytest

logger = logging.getLogger(__name__)

_RULES_DIR = "/etc/suricata/rules/policy-engine"
_SETTLE_SECS = 30
_POLL = 2


def _read_remote_file(node, path):
    out = node.ssh_command(f"sudo cat {path} 2>/dev/null || true", timeout=10)
    return out


def _file_exists(node, path):
    out = node.ssh_command(
        f"sudo test -f {path} && echo YES || echo NO", timeout=10
    ).strip()
    return out.endswith("YES")


def _wait_in_sync(client, node_id, ruleset_name, timeout=_SETTLE_SECS):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for rs in client.node_suricata_rulesets(node_id):
            if rs["name"] == ruleset_name and rs["inSync"]:
                return
        time.sleep(_POLL)
    raise AssertionError(
        f"ruleset {ruleset_name} not inSync on {node_id} within {timeout}s"
    )


@pytest.fixture
def ruleset(controller_client):
    content = 'alert tcp any any -> any any (msg:"fleet base"; sid:9200001; rev:1;)\n'
    rs = controller_client.create_suricata_ruleset("base", content)
    yield rs, content
    controller_client.delete_suricata_ruleset(rs["id"])


def test_ruleset_distributes_to_capable_nodes(
    nodes, controller_client, enrolled_nodes, ruleset
):
    rs, content = ruleset
    filename = rs["filename"]
    assert filename == "fleet-base.rules"
    expected_sha = hashlib.sha256(content.encode()).hexdigest()
    assert rs["sha256"] == expected_sha

    # Drop a node-local rule file that the controller must never touch.
    for vm in ("node1", "node2"):
        nodes[vm].ssh_command(
            f"sudo mkdir -p {_RULES_DIR} && "
            f"echo '# local' | sudo tee {_RULES_DIR}/custom.rules >/dev/null",
            timeout=10,
        )

    for vm in ("node1", "node2"):
        r = controller_client.assign_suricata_ruleset(enrolled_nodes[vm], rs["id"])
        assert r.success, r.message

    for vm in ("node1", "node2"):
        _wait_in_sync(controller_client, enrolled_nodes[vm], "base")
        got = _read_remote_file(nodes[vm], f"{_RULES_DIR}/{filename}")
        assert got == content, f"{vm}: fleet file content mismatch"
        assert hashlib.sha256(got.encode()).hexdigest() == expected_sha
        # Local file untouched.
        assert _file_exists(nodes[vm], f"{_RULES_DIR}/custom.rules")

    # Update content → drift push reconverges both nodes.
    new_content = (
        content
        + 'alert udp any any -> any any (msg:"fleet extra"; sid:9200002; rev:1;)\n'
    )
    controller_client.update_suricata_ruleset(rs["id"], new_content)
    for vm in ("node1", "node2"):
        deadline = time.monotonic() + _SETTLE_SECS
        while time.monotonic() < deadline:
            if _read_remote_file(nodes[vm], f"{_RULES_DIR}/{filename}") == new_content:
                break
            time.sleep(_POLL)
        assert _read_remote_file(nodes[vm], f"{_RULES_DIR}/{filename}") == new_content

    # Unassign from node1 → its fleet file is removed, local file stays.
    controller_client.unassign_suricata_ruleset(enrolled_nodes["node1"], rs["id"])
    deadline = time.monotonic() + _SETTLE_SECS
    while time.monotonic() < deadline:
        if not _file_exists(nodes["node1"], f"{_RULES_DIR}/{filename}"):
            break
        time.sleep(_POLL)
    assert not _file_exists(nodes["node1"], f"{_RULES_DIR}/{filename}")
    assert _file_exists(nodes["node1"], f"{_RULES_DIR}/custom.rules")
    # node2 still has it.
    assert _file_exists(nodes["node2"], f"{_RULES_DIR}/{filename}")
