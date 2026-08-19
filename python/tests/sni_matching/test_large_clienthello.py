# Copyright (c) Dufferin Software

"""
Large-ClientHello path: ``bpf_skb_pull_data`` and ``SNI_PULL_MAX``.

Modern TLS 1.3 ClientHellos pushing post-quantum key shares (e.g.
``X25519MLKEM768``) routinely run ~2 KiB.  On TC egress the kernel hands
BPF a single super-skb whose linear region is only ~50–60 bytes; the
rest lives in paged fragments.  ``tc_sni_inspect`` calls
``bpf_skb_pull_data(ctx, min(ctx->len, SNI_PULL_MAX))`` (currently 4 KiB
— see ``policy_common.h``) before parsing so the ``server_name``
extension is reachable via direct packet access.

This test pads a synthetic ClientHello past the linear region but well
under ``SNI_PULL_MAX`` and asserts the inspector still matches.  XDP
ingress doesn't need a pull — it sees raw frames — but TC egress is
where the pathology lives.
"""

import logging
import time

import pytest

from policy_engine_client.engine.cli.client import AddRuleOptions
from tests.sni_matching.helpers import rule_packets

logger = logging.getLogger(__name__)

_DPORT = 443

# Target ClientHello size on the wire.  Comfortably bigger than the
# typical skb linear region (~60 B) and big enough to land the
# ``server_name`` extension past it, but well under ``SNI_PULL_MAX``
# (4 KiB) so the inspector should still resolve.
_LARGE_CH_SIZE = 2400


@pytest.mark.usefixtures("tcp_sni_listener")
class TestLargeClientHello:
    def test_2kb_clienthello_still_matches(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
        tls_sender,
        client_ip_v4,
        server_network_v4,
    ):
        """A ~2 KiB padded ClientHello must still match by SNI.

        Failure mode this catches: a regression in ``bpf_skb_pull_data``
        or a tightened ``SNI_PULL_MAX`` would cause the parser to bail
        before reaching the ``server_name`` extension, and rule_stats
        would stay flat.
        """
        sni = "pq-sized.example"
        rule_id = 940_001
        r = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="tcp",
                dport=_DPORT,
                actions=[("log", 0)],
                sni=sni,
                rule_id=rule_id,
            ),
            direction="egress",
        )
        assert r.success, f"add_rule failed: {r.message}"
        policy_client.clear_rule_stats(rule_id=rule_id, direction="egress")

        tls_sender(
            str(client_ip_v4),
            _DPORT,
            sni,
            pad_to=_LARGE_CH_SIZE,
        )

        time.sleep(0.5)
        count = rule_packets(policy_client, rule_id)
        logger.info(f"large-CH rule_stats packets: {count}")
        assert count >= 1, (
            f"Padded ClientHello ({_LARGE_CH_SIZE} B) did not match — "
            "bpf_skb_pull_data may not be pulling enough, or SNI_PULL_MAX "
            "has regressed.  Check tc_sni_inspect."
        )
