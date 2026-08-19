# Copyright (c) Dufferin Software

"""
Policy operation smoke tests over TLS.

Each test in this module runs twice — once against the CLI client
(policy-client --tls-ca-cert) and once against the GraphQL client
(curl --cacert) — via the parameterised policy_client fixture defined in
conftest.py.

The goal is to confirm that the full policy management API works correctly
when the transport is HTTPS rather than plain HTTP.
"""

import logging


from policy_engine_client.engine.cli.client import (
    AddRuleOptions,
    IngressMode,
    PolicyAction,
)

logger = logging.getLogger(__name__)


class TestPolicyOpsOverTls:
    """Smoke-test the policy API across both CLI and GraphQL clients over TLS."""

    def test_server_status(self, policy_client):
        """Server status query must succeed over TLS."""
        status = policy_client.status()
        assert status is not None

    def test_attach_and_detach_ingress(self, policy_client, server_interface):
        """Attach and detach XDP ingress over TLS; verify via list_interfaces."""
        iface = server_interface.if_name

        result = policy_client.attach_ingress(iface, IngressMode.AUTO)
        assert result.success, f"attach_ingress failed: {result.message}"

        try:
            interfaces = policy_client.list_interfaces()
            attached = [
                i
                for i in interfaces
                if i.interface == iface and i.direction == "ingress"
            ]
            assert len(attached) == 1, (
                f"Expected ingress attached to {iface}, got: {interfaces}"
            )
        finally:
            policy_client.detach_ingress(iface)

    def test_add_and_delete_rule(self, policy_client, server_interface):
        """Add a rule and delete it over TLS; verify list_rules reflects the change."""
        iface = server_interface.if_name
        rule_id = 9001

        result = policy_client.attach_ingress(iface, IngressMode.AUTO)
        assert result.success, f"attach_ingress failed: {result.message}"
        try:
            opts = AddRuleOptions(
                interface=iface,
                src="198.51.100.0/24",
                actions=[(PolicyAction.DROP, 0)],
                rule_id=rule_id,
            )
            add_result = policy_client.add_rule(opts, direction="ingress")
            assert add_result.success, f"add_rule failed: {add_result.message}"

            rules = policy_client.list_rules(direction="ingress")
            rule_ids = [r.rule_id for r in rules]
            assert rule_id in rule_ids, f"Rule {rule_id} not found in rules: {rule_ids}"

            del_result = policy_client.delete_rule(
                iface, rule_id=rule_id, direction="ingress"
            )
            assert del_result.success, f"delete_rule failed: {del_result.message}"

            rules_after = policy_client.list_rules(direction="ingress")
            rule_ids_after = [r.rule_id for r in rules_after]
            assert rule_id not in rule_ids_after, (
                f"Rule {rule_id} still present after deletion: {rule_ids_after}"
            )
        finally:
            policy_client.flush_rules(direction="ingress")
            policy_client.detach_ingress(iface)

    def test_default_action_change(self, policy_client, server_interface):
        """Changing the default action over TLS must persist and be reversible."""
        iface = server_interface.if_name

        result = policy_client.attach_ingress(iface, IngressMode.AUTO)
        assert result.success, f"attach_ingress failed: {result.message}"
        try:
            r = policy_client.set_default_action(
                PolicyAction.DROP, direction="ingress", interface=iface
            )
            assert r.success, f"set_default_action(DROP) failed: {r.message}"

            r = policy_client.set_default_action(
                PolicyAction.PASS, direction="ingress", interface=iface
            )
            assert r.success, f"set_default_action(PASS) failed: {r.message}"
        finally:
            policy_client.set_default_action(
                PolicyAction.PASS, direction="ingress", interface=iface
            )
            policy_client.detach_ingress(iface)
