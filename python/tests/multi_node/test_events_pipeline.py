# Copyright (c) Dufferin Software

"""
Events pipeline + node-identity integration tests.

Traffic shape across the suite: install a log-only ICMP ingress rule on
node1, ping from node2, poll the controller's persisted-events store and
metrics. The shared `_log_ingress_session` context manager owns the
attach + create-rule + detach + delete-rule dance so each test reads
linearly.

Controller-DB poking: TestEventRetention writes directly to the
`tenants` table because there is no GraphQL/REST mutation for
retention_s yet. The `sqlite3` CLI is *not* a runtime dep of
policy-controller (it statically links sqlx), so the test installs the
package on demand via `_ensure_sqlite3_cli` the first time it needs to
run a query. The retention_s value is restored in `finally` so the
short retention window doesn't leak into later tests in the package.

Wall-clock: TestEventRetention waits up to ~90 s for one full retention
sweep cycle (interval is hardcoded at 60 s in
fleet/controller/src/event_pipeline/retention.rs).
"""

import contextlib
import json
import logging
import re
import subprocess
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List

import pytest

from policy_engine_client.controller.graphql.client import (
    ControllerClient,
    PersistedEvent,
)
from tests.multi_node.helpers import (
    data_iface,
    delete_controller_rules,
    flush_ingress_rules,
    get_data_ip,
    read_sysfs_ifindex,
    send_icmp,
    wait_for_node_ready,
)

logger = logging.getLogger(__name__)

_SETTLE_SECS = 3
_POLL_INTERVAL = 1
_EVENT_WAIT_TIMEOUT = 30  # controller flushes forwarded events in batches
_INTERFACE_REPORT_TIMEOUT = 60  # first InterfaceReport after enrollment


# ── Shared helpers ────────────────────────────────────────────────────────────


def _wait_for_interfaces_reported(
    client: ControllerClient,
    node_id: str,
    iface_name: str,
    timeout: int = _INTERFACE_REPORT_TIMEOUT,
) -> int:
    """Poll the controller until it has an ifindex>0 for (node_id, iface_name).

    First InterfaceReport lands shortly after enrollment but isn't synchronous
    with it. Returns the reported ifindex.
    """
    deadline = time.monotonic() + timeout
    last_seen: list = []
    while time.monotonic() < deadline:
        try:
            ifaces = client.node_interfaces(node_id)
            last_seen = ifaces
            for i in ifaces:
                if i.name == iface_name and i.ifindex > 0:
                    return i.ifindex
        except Exception as e:
            logger.debug(f"interfaces poll error: {e}")
        time.sleep(_POLL_INTERVAL)
    pytest.fail(
        f"Controller never reported ifindex>0 for ({node_id}, {iface_name}) "
        f"within {timeout}s; last_seen={[(i.name, i.ifindex) for i in last_seen]}"
    )


def _wait_for_events(
    client: ControllerClient,
    node_id: str,
    since_iso: str,
    min_count: int = 1,
    timeout: int = _EVENT_WAIT_TIMEOUT,
) -> List[PersistedEvent]:
    """Poll events() until at least `min_count` events arrive for node_id."""
    deadline = time.monotonic() + timeout
    last: List[PersistedEvent] = []
    while time.monotonic() < deadline:
        try:
            evs = client.events(node_id=node_id, since_iso=since_iso, limit=200)
            last = evs
            if len(evs) >= min_count:
                return evs
        except Exception as e:
            logger.debug(f"events poll error: {e}")
        time.sleep(_POLL_INTERVAL)
    pytest.fail(
        f"Expected ≥{min_count} events for node {node_id} since {since_iso}, "
        f"got {len(last)} after {timeout}s"
    )


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestNodeIdentity:
    """Phases 1 & 2: every enrolled node reports hostname and dmi_uuid."""

    def test_every_node_has_hostname(
        self,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        by_id = {n.id: n for n in controller_client.list_nodes()}
        for vm_name, node_id in enrolled_nodes.items():
            n = by_id.get(node_id)
            assert n is not None, f"{vm_name} ({node_id}) missing from list_nodes"
            assert n.hostname, (
                f"{vm_name} ({node_id}) has empty hostname — the controller "
                f"never received it (check AgentHello) or COALESCE wiped it"
            )
            logger.info(f"{vm_name}: hostname={n.hostname!r}")

    def test_every_node_has_dmi_uuid(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """
        Regression test for the DynamicUser/DAC bug: the agent must be able
        to read /sys/class/dmi/id/product_uuid and the controller must
        persist it across AgentHello updates.

        Skips a node if the host kernel itself can't read product_uuid
        (uncommon, but possible in stripped-down VMs).
        """
        by_id = {n.id: n for n in controller_client.list_nodes()}
        for vm_name, node_id in enrolled_nodes.items():
            host_uuid = (
                nodes[vm_name]
                .ssh_command(
                    "sudo cat /sys/class/dmi/id/product_uuid 2>/dev/null || true",
                    timeout=10,
                )
                .strip()
            )
            if not host_uuid:
                pytest.skip(
                    f"{vm_name} has no product_uuid available even to root — "
                    f"nothing to compare against"
                )

            n = by_id.get(node_id)
            assert n is not None
            assert n.dmi_uuid, (
                f"{vm_name} ({node_id}) has empty dmi_uuid on the controller "
                f"but the host exposes {host_uuid!r} — agent likely lacks "
                f"CAP_DAC_READ_SEARCH or the controller is overwriting the "
                f"value with NULL on AgentHello"
            )
            assert n.dmi_uuid.lower() == host_uuid.lower(), (
                f"{vm_name}: controller dmi_uuid={n.dmi_uuid!r} != "
                f"host product_uuid={host_uuid!r}"
            )
            logger.info(f"{vm_name}: dmi_uuid={n.dmi_uuid}")


class TestInterfaceIfindex:
    """Phase 4 (server side): controller persists ifindex from InterfaceReport."""

    def test_data_interface_ifindex_matches_sysfs(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """For every managed node, the controller's NodeInterface.ifindex for
        the data NIC must match /sys/class/net/<iface>/ifindex on the host."""
        for vm_name, node_id in enrolled_nodes.items():
            node = nodes[vm_name]
            iface = data_iface(node)
            sysfs_ifindex = read_sysfs_ifindex(node, iface)
            controller_ifindex = _wait_for_interfaces_reported(
                controller_client, node_id, iface
            )
            assert controller_ifindex == sysfs_ifindex, (
                f"[{vm_name}] controller ifindex={controller_ifindex} for "
                f"{iface}, but sysfs reports {sysfs_ifindex}"
            )
            logger.info(
                f"{vm_name}: {iface} ifindex={sysfs_ifindex} (controller agrees)"
            )


class TestEventStreamPipeline:
    """
    Phase 4 (event side): events forwarded by the agent carry the right
    ifindex so the UI's (node_id, ifindex) → name join is correct.

    Plan:
      1. Attach ingress on node1, install a log-only ICMP rule.
      2. Capture a timestamp, ping node1 from node2.
      3. Poll the controller's persisted events store.
      4. Assert: events exist for node1; ifindex matches node1's data NIC;
         action is LOG; direction is INGRESS.
    """

    def test_log_events_tagged_with_correct_ifindex(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        node1 = nodes["node1"]
        node2 = nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        iface1 = data_iface(node1)
        iface2 = data_iface(node2)
        node1_ip = get_data_ip(node1)

        expected_ifindex = _wait_for_interfaces_reported(
            controller_client, node1_id, iface1
        )

        wait_for_node_ready(controller_client, node1_id)
        controller_client.attach_program(
            node_id=node1_id, interface_name=iface1, direction="ingress"
        )
        time.sleep(_SETTLE_SECS)
        flush_ingress_rules(node1)
        delete_controller_rules(controller_client, node1_id, iface1, "ingress")

        rule = controller_client.create_rule(
            node_id=node1_id,
            interface_name=iface1,
            direction="ingress",
            protocol="icmp",
            actions_json='[{"action":"log","priority":0}]',
        )
        assert rule.get("id"), f"createRule returned no id: {rule}"
        rule_id = rule["id"]
        logger.info(f"[node1] log-ICMP rule id={rule_id}")
        time.sleep(_SETTLE_SECS)

        # Pre-traffic high-water mark — only count events newer than this.
        # Controller stores DateTime in UTC; use a slightly-padded ISO string.
        from datetime import datetime, timedelta, timezone

        since_iso = (datetime.now(timezone.utc) - timedelta(seconds=2)).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        ).rstrip("0").rstrip(".") + "Z"

        try:
            ping = send_icmp(node2, node1_ip, iface2, count=5)
            logger.info(f"[log-rule] ping: sent={ping['sent']} recv={ping['received']}")
            assert ping["received"] > 0, (
                f"log-only rule must not drop traffic; got {ping}"
            )

            evs = _wait_for_events(controller_client, node1_id, since_iso, min_count=1)

            # Filter to ICMP-from-node2-to-node1 to ignore unrelated background
            # traffic the agent might also have logged.
            node2_ip = get_data_ip(node2)
            relevant = [e for e in evs if e.src_ip == node2_ip and e.dst_ip == node1_ip]
            assert relevant, (
                f"No events matching {node2_ip} → {node1_ip} found; got "
                f"{[(e.src_ip, e.dst_ip, e.action, e.ifindex) for e in evs]}"
            )

            for e in relevant:
                assert e.node_id == node1_id, (
                    f"event.node_id={e.node_id} != node1_id={node1_id}"
                )
                assert e.ifindex == expected_ifindex, (
                    f"event.ifindex={e.ifindex} != expected {expected_ifindex} "
                    f"({iface1}); the agent's per-event ifindex tagging is wrong"
                )
                assert e.direction.lower() == "ingress", (
                    f"event.direction={e.direction!r}, expected INGRESS"
                )
                assert e.action.lower() == "log", (
                    f"event.action={e.action!r}, expected LOG"
                )
            logger.info(
                f"verified {len(relevant)} forwarded events carry ifindex={expected_ifindex}"
            )
        finally:
            flush_ingress_rules(node1)
            delete_controller_rules(controller_client, node1_id, iface1, "ingress")
            wait_for_node_ready(controller_client, node1_id)
            try:
                controller_client.detach_program(
                    node_id=node1_id, interface_name=iface1, direction="ingress"
                )
            except Exception as e:
                logger.warning(f"detach_program cleanup failed: {e}")


# ── Helpers for manual-verification-checklist tests #6 and #7 ─────────────────

_CONTROLLER_DB = "/var/lib/policy-controller/controller.db"
_RETENTION_SWEEP_SECS = 60  # hardcoded in event_pipeline/retention.rs


def _controller_curl(controller_node, path: str, api_token: str | None = None) -> str:
    """GET a controller HTTP path over loopback via curl-on-ssh."""
    auth = f"-H 'Authorization: Bearer {api_token}' " if api_token else ""
    return controller_node.ssh_command(
        f"curl -s --max-time 10 {auth}'http://127.0.0.1:8443{path}'",
        timeout=20,
    )


def _read_retention_pruned_metric(controller_node, tenant: str = "default") -> int:
    """Parse `event_retention_pruned_total{tenant="<tenant>"} <n>` out of /metrics."""
    body = _controller_curl(controller_node, "/metrics")
    pat = re.compile(
        rf'^event_retention_pruned_total\{{tenant="{re.escape(tenant)}"\}}\s+(\d+)',
        re.MULTILINE,
    )
    m = pat.search(body)
    if not m:
        pytest.fail(
            f"event_retention_pruned_total{{tenant={tenant!r}}} not found in /metrics; "
            f"sample:\n{body[:500]}"
        )
    return int(m.group(1))


def _ensure_sqlite3_cli(controller_node) -> None:
    """
    The policy-controller statically links sqlx, so the `sqlite3` shell binary
    isn't a package dependency. Install it on demand when a test needs to peek
    at or poke the controller DB directly. Idempotent.
    """
    out = controller_node.ssh_command(
        "command -v sqlite3 >/dev/null 2>&1 && echo PRESENT || echo MISSING",
        timeout=10,
    )
    if "PRESENT" in out:
        return
    logger.info("Installing sqlite3 CLI on controller for direct-DB test helpers")
    controller_node.ssh_command(
        "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y sqlite3",
        timeout=120,
    )


def _run_sqlite(controller_node, sql: str) -> str:
    """Run `sqlite3 controller.db "<sql>"` and surface stderr on failure."""
    cmd = f'sudo sqlite3 {_CONTROLLER_DB} "{sql}"'
    try:
        return controller_node.ssh_command(cmd, timeout=15).strip()
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip() if hasattr(e, "stderr") else ""
        pytest.fail(
            f"sqlite3 failed (exit={e.returncode}) on controller:\n"
            f"  cmd:    {cmd}\n"
            f"  stdout: {(e.output or '').strip()}\n"
            f"  stderr: {stderr}"
        )


def _sqlite_scalar(controller_node, sql: str) -> str:
    """Run a single-value SQL query against the controller DB and return it as a string."""
    return _run_sqlite(controller_node, sql)


def _set_tenant_retention(controller_node, tenant: str, retention_s: int) -> None:
    _run_sqlite(
        controller_node,
        f"UPDATE tenants SET retention_s = {int(retention_s)} WHERE slug = '{tenant}';",
    )


@contextlib.contextmanager
def _log_ingress_session(controller_client: ControllerClient, node, node_id: str):
    """
    Attach ingress + install a log-only ICMP rule on `node`; yield the rule_id
    and the data interface name. On exit, flush rules and detach.

    Mirrors the setup used by TestEventStreamPipeline above so the two new
    tests in this file (#6 retention, #7 GraphQL cursor) don't have to
    duplicate the dance.
    """
    iface = data_iface(node)
    wait_for_node_ready(controller_client, node_id)
    controller_client.attach_program(
        node_id=node_id, interface_name=iface, direction="ingress"
    )
    time.sleep(_SETTLE_SECS)
    flush_ingress_rules(node)
    delete_controller_rules(controller_client, node_id, iface, "ingress")
    rule = controller_client.create_rule(
        node_id=node_id,
        interface_name=iface,
        direction="ingress",
        protocol="icmp",
        actions_json='[{"action":"log","priority":0}]',
    )
    assert rule.get("id"), f"createRule returned no id: {rule}"
    time.sleep(_SETTLE_SECS)
    try:
        yield rule["id"], iface
    finally:
        flush_ingress_rules(node)
        delete_controller_rules(controller_client, node_id, iface, "ingress")
        wait_for_node_ready(controller_client, node_id)
        try:
            controller_client.detach_program(
                node_id=node_id, interface_name=iface, direction="ingress"
            )
        except Exception as e:
            logger.warning(f"detach_program cleanup failed: {e}")


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestEventsGraphqlQuery:
    """
    Manual verification checklist #7 (docs/event-pipeline-todo.md):

        GraphQL playground: run
            { events(limit: 3) { items { id action srcIp dstIp } nextCursor } }

    Exercises the cursor-paginated GraphQL surface end-to-end and cross-checks
    it against the REST table-shape endpoint that Grafana Infinity consumes.
    """

    def test_cursor_pagination_and_rest_parity(
        self,
        nodes,
        controller_client: ControllerClient,
        controller_api_token: str,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        node1 = nodes["node1"]
        node2 = nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        node1_ip = get_data_ip(node1)
        iface2 = data_iface(node2)

        with _log_ingress_session(controller_client, node1, node1_id):
            since_iso = (datetime.now(timezone.utc) - timedelta(seconds=2)).strftime(
                "%Y-%m-%dT%H:%M:%S.%f"
            ).rstrip("0").rstrip(".") + "Z"

            ping = send_icmp(node2, node1_ip, iface2, count=8)
            assert ping["received"] > 0, f"log rule must not drop traffic: {ping}"

            # Need enough events to force pagination at limit=3.
            _wait_for_events(controller_client, node1_id, since_iso, min_count=4)

            query = """
            query EventsPage($filter: EventFilterInput, $limit: Int, $cursor: String) {
                events(filter: $filter, limit: $limit, cursor: $cursor) {
                    items { id action srcIp dstIp }
                    nextCursor
                }
            }
            """
            filt = {"nodeId": node1_id, "since": since_iso}

            # Page 1: small limit, expect a continuation cursor.
            data1 = controller_client._execute(
                query, {"filter": filt, "limit": 3, "cursor": None}
            )
            page1 = data1["events"]
            assert len(page1["items"]) == 3, f"page1 wanted 3 items, got {page1}"
            assert page1["nextCursor"], (
                f"nextCursor missing on page 1 — pagination broken: {page1}"
            )
            for item in page1["items"]:
                assert item["id"], f"empty id in {item}"
                assert item["action"].lower() == "log", item
                assert item["srcIp"] and item["dstIp"], item

            # Page 2: continuation must not repeat any id from page 1.
            data2 = controller_client._execute(
                query,
                {"filter": filt, "limit": 100, "cursor": page1["nextCursor"]},
            )
            page2 = data2["events"]
            page1_ids = {it["id"] for it in page1["items"]}
            page2_ids = {it["id"] for it in page2["items"]}
            overlap = page1_ids & page2_ids
            assert not overlap, f"cursor returned overlapping ids: {overlap}"

            # REST parity: the same filter via /api/v1/events should return at
            # least as many rows as the union of the two GraphQL pages.
            rest_body = _controller_curl(
                nodes["controller"],
                f"/api/v1/events?node_id={node1_id}&since={since_iso}&limit=500",
                api_token=controller_api_token,
            )
            rest = json.loads(rest_body)
            assert "columns" in rest and "rows" in rest, (
                f"REST shape unexpected (want columns+rows): {rest_body[:300]}"
            )
            rest_count = len(rest["rows"])
            gql_total = len(page1["items"]) + len(page2["items"])
            assert rest_count >= gql_total, (
                f"REST returned {rest_count} rows but GraphQL paged through "
                f"{gql_total}; the two endpoints should agree on the same filter"
            )
            logger.info(
                f"GraphQL pagination ok: page1=3 page2={len(page2['items'])} "
                f"REST rows={rest_count}"
            )


class TestEventRetention:
    """
    Manual verification checklist #6 (docs/event-pipeline-todo.md):

        Set tenant retention_s to a small value, wait one sweep, confirm
        event_retention_pruned_total increments and old rows are gone.

    The retention sweep interval is hardcoded at 60 s in
    event_pipeline/retention.rs, so this test takes ~90 s to allow for at
    most one full sweep cycle plus the post-DELETE chunk loop. There is no
    GraphQL/REST mutation for tenant.retention_s yet, so we poke the
    `tenants` table directly via sqlite3 over SSH and restore the original
    value in `finally` so subsequent tests in the package aren't affected.
    """

    def test_retention_sweep_prunes_old_rows(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        controller = nodes["controller"]
        node1 = nodes["node1"]
        node2 = nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        node1_ip = get_data_ip(node1)
        iface2 = data_iface(node2)

        _ensure_sqlite3_cli(controller)

        original_retention = int(
            _sqlite_scalar(
                controller, "SELECT retention_s FROM tenants WHERE slug='default';"
            )
        )
        logger.info(
            f"Original tenants.retention_s for 'default' = {original_retention}"
        )

        try:
            with _log_ingress_session(controller_client, node1, node1_id):
                since_iso = (
                    datetime.now(timezone.utc) - timedelta(seconds=2)
                ).strftime("%Y-%m-%dT%H:%M:%S.%f").rstrip("0").rstrip(".") + "Z"

                ping = send_icmp(node2, node1_ip, iface2, count=10)
                assert ping["received"] > 0, ping
                _wait_for_events(controller_client, node1_id, since_iso, min_count=3)

                rows_before = int(
                    _sqlite_scalar(controller, "SELECT count(*) FROM events;")
                )
                pruned_before = _read_retention_pruned_metric(controller)
                assert rows_before > 0, "no events present to prune"
                logger.info(
                    f"Pre-sweep: events.count={rows_before}, "
                    f"event_retention_pruned_total={pruned_before}"
                )

                # Shrink retention so everything older than 1 s is eligible.
                _set_tenant_retention(controller, "default", 1)

                # Sweep runs every 60 s; allow one full cycle + chunk loop slack.
                wait_secs = _RETENTION_SWEEP_SECS + 30
                logger.info(f"Waiting up to {wait_secs}s for retention sweep")
                deadline = time.monotonic() + wait_secs
                pruned_after = pruned_before
                rows_after = rows_before
                while time.monotonic() < deadline:
                    pruned_after = _read_retention_pruned_metric(controller)
                    rows_after = int(
                        _sqlite_scalar(controller, "SELECT count(*) FROM events;")
                    )
                    if pruned_after > pruned_before and rows_after < rows_before:
                        break
                    time.sleep(3)

                assert pruned_after > pruned_before, (
                    f"event_retention_pruned_total did not increment "
                    f"({pruned_before} → {pruned_after}) within {wait_secs}s — "
                    f"the retention task is not running or not picking up the new retention_s"
                )
                assert rows_after < rows_before, (
                    f"events table did not shrink ({rows_before} → {rows_after}); "
                    f"the DELETE never landed even though the counter moved"
                )
                logger.info(
                    f"Retention sweep verified: rows {rows_before}→{rows_after}, "
                    f"pruned counter {pruned_before}→{pruned_after}"
                )
        finally:
            _set_tenant_retention(controller, "default", original_retention)
            logger.info(f"Restored tenants.retention_s = {original_retention}")
