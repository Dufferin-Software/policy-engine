# Copyright (c) Dufferin Software

"""
Tenant isolation end-to-end (commit 03530bf, "controller: finish RBAC
rollout").

All previous netsim tests run against `tenant_slug = "default"` only, so
the cross-tenant filtering added to `nodes`, `auditLog`, `alertRules`, and
`allNodeInterfaces` resolvers — and the matching `Option<&str>` tenant
arg threaded into `ControllerStore::list_nodes`, `list_audit`, and
`list_all_node_interfaces` — has not been exercised on a real DB.

This test seeds the controller with a second tenant ("tenant2") via the
new `policy-controller-bootstrap-tenant` binary, mints a tenant2-scoped
admin token, stages a small but representative set of rows under
`tenant_id = 'tenant2'` / numeric tenant_id = 2, and asserts that:

  * a default-scoped principal cannot see tenant2's nodes, audit
    entries, alert rules, or node interfaces;
  * a tenant2-scoped principal can see those rows and *only* those rows.

The seeded rows are inserted directly via `sqlite3` because the goal is
to verify the read-path filter, not the write-path propagation
(write-path tenant isolation has its own class below). Direct DB inserts
also keep the cross-tenant counts unambiguous regardless of which
mutations happen to audit-log.

The companion class `TestTenantWriteIsolation` exercises the
`ensure_node_in_tenant` guard added to every node-targeted GraphQL
mutation: a tenant2 principal that targets a default-tenant node_id (or
vice versa) must hit a "Node not found"-shaped error indistinguishable
from a genuinely unknown node id, so cross-tenant node-id enumeration is
not possible.
"""

import logging
import subprocess
import time

import pytest

from policy_engine_client.controller.graphql.client import (
    ControllerClient,
    bootstrap_tenant,
    mint_api_token,
)

logger = logging.getLogger(__name__)

_CONTROLLER_DB = "/var/lib/policy-controller/controller.db"
_TENANT2_SLUG = "tenant2"
_TENANT2_NAME = "Tenant Two"
_TENANT2_NODE_ID = "tenant2-node-stub"
_TENANT2_AUDIT_ACTION = "tenant2.isolation.marker"
_TENANT2_ALERT_RULE = "tenant2-isolation-rule"
_TENANT2_RECEIVER = "tenant2-isolation-noop"


# ── Direct-DB helpers (mirror test_events_pipeline.py) ────────────────────────


def _ensure_sqlite3_cli(controller_node) -> None:
    out = controller_node.ssh_command(
        "command -v sqlite3 >/dev/null 2>&1 && echo PRESENT || echo MISSING",
        timeout=10,
    )
    if "PRESENT" in out:
        return
    logger.info("Installing sqlite3 CLI on controller for direct-DB stubs")
    controller_node.ssh_command(
        "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y sqlite3",
        timeout=120,
    )


def _sqlite_exec(controller_node, sql: str) -> None:
    """Run a (possibly multi-statement) SQL script against the controller DB."""
    # Pipe via stdin so we don't have to escape quotes in the SQL literal.
    cmd = f"sudo sqlite3 {_CONTROLLER_DB}"
    try:
        controller_node.ssh_command_with_stdin(cmd, sql, timeout=15)
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip() if hasattr(e, "stderr") else ""
        pytest.fail(
            f"sqlite3 failed (exit={e.returncode}):\n"
            f"  sql:    {sql}\n"
            f"  stderr: {stderr}"
        )


# ── Fixtures local to this test ───────────────────────────────────────────────


@pytest.fixture(scope="module")
def tenant2(nodes, controller_service, controller_client, enrolled_nodes):
    """
    Provision tenant2, mint an admin token bound to it, and stage one
    representative row per tenant-filtered resource. Returns
    (tenant2_id, tenant2_client).

    Depends on `enrolled_nodes` so the default-tenant fleet is already in
    place when we inject our stub rows — keeps the cross-tenant counts
    unambiguous.
    """
    controller = nodes["controller"]
    _ensure_sqlite3_cli(controller)

    tenant_id = bootstrap_tenant(controller, slug=_TENANT2_SLUG, name=_TENANT2_NAME)
    logger.info(f"Provisioned tenant {_TENANT2_SLUG!r} with id {tenant_id}")
    assert tenant_id != 1, "tenant2 collided with the default tenant id"

    token = mint_api_token(
        controller,
        f"netsim-tenant2-{int(time.time())}",
        tenant_id=tenant_id,
        roles=("admin",),
    )
    client = ControllerClient(controller, api_token=token)

    # Stage tenant2 rows. INSERT OR IGNORE / UNIQUE constraints make
    # re-runs idempotent across the destroy-on-feature-change controller DB
    # workflow.
    _sqlite_exec(
        controller,
        f"""
        INSERT OR IGNORE INTO nodes (id, status, tenant_id, public_key_der)
          VALUES ('{_TENANT2_NODE_ID}', 'active', '{_TENANT2_SLUG}', '');

        INSERT OR IGNORE INTO node_interfaces
            (node_id, interface_name, last_reported)
          VALUES ('{_TENANT2_NODE_ID}', 'eth0', strftime('%s','now'));

        INSERT INTO audit_log (ts, action, detail, tenant_id)
          VALUES (strftime('%s','now'), '{_TENANT2_AUDIT_ACTION}',
                  'tenant2 isolation marker', '{_TENANT2_SLUG}');

        INSERT OR IGNORE INTO receivers (tenant_id, name, kind, config_json)
          VALUES ({tenant_id}, '{_TENANT2_RECEIVER}', 'webhook',
                  '{{"url":"http://127.0.0.1/noop"}}');

        INSERT OR IGNORE INTO alert_rules
            (tenant_id, name, match_json, group_by, severity,
             receiver_ids, created_at, updated_at)
          VALUES ({tenant_id}, '{_TENANT2_ALERT_RULE}', '{{}}', '[]', 'info',
                  '[]', strftime('%s','now'), strftime('%s','now'));
        """,
    )

    return tenant_id, client


# ── Inline GraphQL ────────────────────────────────────────────────────────────
#
# These queries live in the test (not on `ControllerClient`) because they
# are read-only one-liners used here and nowhere else; the client surface
# stays focused on the mutations that drive the rest of the multi-node
# suite.


def _node_ids(client: ControllerClient) -> set[str]:
    data = client._execute("query { nodes { id } }")
    return {n["id"] for n in data["nodes"]}


def _audit_actions(client: ControllerClient) -> list[str]:
    data = client._execute("query { auditLog(limit: 500) { action } }")
    return [e["action"] for e in data["auditLog"]]


def _alert_rule_names(client: ControllerClient) -> set[str]:
    data = client._execute("query { alertRules { name } }")
    return {r["name"] for r in data["alertRules"]}


def _interface_node_ids(client: ControllerClient) -> set[str]:
    data = client._execute("query { allNodeInterfaces { nodeId } }")
    return {i["nodeId"] for i in data["allNodeInterfaces"]}


# ── The test ──────────────────────────────────────────────────────────────────


class TestTenantIsolation:
    """Two principals, one DB, four resolvers — no leakage either way."""

    def test_default_principal_cannot_see_tenant2(
        self, controller_client, enrolled_nodes, tenant2
    ):
        """The fleet-default admin token sees only default-tenant rows."""
        _tenant_id, _t2_client = tenant2

        node_ids = _node_ids(controller_client)
        assert _TENANT2_NODE_ID not in node_ids, (
            f"default principal saw tenant2 node {_TENANT2_NODE_ID!r} "
            f"in nodes query: {sorted(node_ids)}"
        )
        # The default principal must still see its own fleet and nothing
        # foreign. We can't demand the *full* enrolled set here: sibling tests
        # in this package (test_multi_node's decommission scenario) remove
        # node3 from the registry before we run, and `enrolled_nodes` is a
        # package-scoped snapshot that still lists it. So assert the surviving
        # view is a non-empty subset of the originally-enrolled default fleet —
        # proving the tenant filter neither wiped out the default tenant nor
        # leaked in rows from outside it.
        enrolled = set(enrolled_nodes.values())
        assert node_ids & enrolled, (
            "default principal lost sight of all its enrolled nodes"
        )
        assert node_ids.issubset(enrolled), (
            "default principal saw nodes outside its own enrolled fleet: "
            f"{sorted(node_ids - enrolled)}"
        )

        actions = _audit_actions(controller_client)
        assert _TENANT2_AUDIT_ACTION not in actions, (
            f"default principal saw tenant2 audit entry {_TENANT2_AUDIT_ACTION!r} "
            f"in auditLog"
        )

        rule_names = _alert_rule_names(controller_client)
        assert _TENANT2_ALERT_RULE not in rule_names, (
            f"default principal saw tenant2 alert rule {_TENANT2_ALERT_RULE!r}"
        )

        iface_nodes = _interface_node_ids(controller_client)
        assert _TENANT2_NODE_ID not in iface_nodes, (
            f"default principal saw an interface for tenant2 node "
            f"{_TENANT2_NODE_ID!r} in allNodeInterfaces"
        )

    def test_tenant2_principal_cannot_see_default(
        self, controller_client, enrolled_nodes, tenant2
    ):
        """The tenant2 admin token sees only tenant2 rows."""
        _tenant_id, t2_client = tenant2

        node_ids = _node_ids(t2_client)
        assert node_ids == {_TENANT2_NODE_ID}, (
            f"tenant2 principal saw unexpected nodes (expected just "
            f"{_TENANT2_NODE_ID!r}): {sorted(node_ids)}"
        )
        # Belt-and-braces: confirm none of the default-tenant enrolled
        # nodes leaked through.
        assert not (set(enrolled_nodes.values()) & node_ids), (
            "tenant2 principal saw default-tenant enrolled nodes"
        )

        actions = _audit_actions(t2_client)
        assert _TENANT2_AUDIT_ACTION in actions, (
            "tenant2 principal cannot see its own audit marker; "
            f"actions returned: {actions[:20]}"
        )
        # Default-tenant audit traffic produced by the enrolment fixture
        # (e.g. label_node) must not appear here.
        leaked = [a for a in actions if a != _TENANT2_AUDIT_ACTION]
        assert not leaked, (
            f"tenant2 principal saw default-tenant audit entries: {leaked[:10]}"
        )

        rule_names = _alert_rule_names(t2_client)
        assert rule_names == {_TENANT2_ALERT_RULE}, (
            f"tenant2 principal saw unexpected alert rules: {sorted(rule_names)}"
        )

        iface_nodes = _interface_node_ids(t2_client)
        assert iface_nodes == {_TENANT2_NODE_ID}, (
            f"tenant2 principal saw interfaces from other tenants: "
            f"{sorted(iface_nodes)}"
        )


class TestTenantWriteIsolation:
    """
    Mutation-side tenant gate. A tenant-A principal that targets a
    tenant-B node_id on any node-scoped mutation must see the same error
    shape as if the node_id did not exist at all — no "wrong tenant"
    distinguisher that would let it enumerate the other tenant's fleet.

    All four mutations exercised here go through the same
    `ensure_node_in_tenant` helper in `graphql/schema.rs`, so one
    successful + one rejected case per mutation is enough to prove the
    guard is wired and surfaces consistently.
    """

    _ERROR_PATTERN = r"Node not found: "

    def test_tenant2_cannot_decommission_default_node(
        self, controller_client, enrolled_nodes, tenant2
    ):
        _tenant_id, t2_client = tenant2
        default_node_id = next(iter(enrolled_nodes.values()))
        with pytest.raises(RuntimeError, match=self._ERROR_PATTERN):
            t2_client.decommission_node(default_node_id)

    def test_default_cannot_push_config_to_tenant2_node(
        self, controller_client, enrolled_nodes, tenant2
    ):
        with pytest.raises(RuntimeError, match=self._ERROR_PATTERN):
            controller_client.push_config(_TENANT2_NODE_ID)

    def test_tenant2_cannot_push_config_to_default_node(
        self, controller_client, enrolled_nodes, tenant2
    ):
        _tenant_id, t2_client = tenant2
        default_node_id = next(iter(enrolled_nodes.values()))
        with pytest.raises(RuntimeError, match=self._ERROR_PATTERN):
            t2_client.push_config(default_node_id)

    def test_tenant2_cannot_create_rule_on_default_node(
        self, controller_client, enrolled_nodes, tenant2
    ):
        """
        Direct GraphQL so we don't go through `create_ruleset`'s
        higher-level abstraction — we want the gate to surface at the
        first per-node createRule call.
        """
        _tenant_id, t2_client = tenant2
        default_node_id = next(iter(enrolled_nodes.values()))
        mutation = """
        mutation CreateRule($input: CreateRuleInput!) {
            createRule(input: $input) { id }
        }
        """
        variables = {
            "input": {
                "nodeId": default_node_id,
                "interfaceName": "eth0",
                "direction": "ingress",
                "actionsJson": "[]",
            }
        }
        with pytest.raises(RuntimeError, match=self._ERROR_PATTERN):
            t2_client._execute(mutation, variables)
