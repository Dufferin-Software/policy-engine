# Copyright (c) Dufferin Software

"""
Rule installation / deletion performance tests.

These tests measure time and memory usage for installing large numbers of rules.
They are kept in a separate suite so that policy_sanity runs remain fast.

Run with:
    pytest tests/policy_performance/ -v
Or using the performance marker:
    pytest -m performance -v
"""

import logging
import time

import pytest

from policy_engine_client.engine.cli.client import AddRuleOptions
from policy_engine_client.engine.graphql.client import GraphQLPolicyClient

logger = logging.getLogger(__name__)


# ============================================================================
# Rule Installation Performance Tests
# ============================================================================


class TestRuleInstallationPerformance:
    """
    Performance tests for rule installation.

    These tests measure the time and memory usage for installing large numbers
    of rules. Useful for benchmarking and identifying if a bulk rule installation
    API would be beneficial.

    Run with: pytest -m performance -v
    Or for a specific test: pytest -k test_ipv4_rule_installation_performance -v
    """

    NUM_RULES = 1000  # Number of rules to install in each test

    def _get_memory_usage_kb(self, nodes) -> int:
        """Get the policy-engine process memory usage in KB from the server node."""
        server = nodes["server"]
        # Get RSS (Resident Set Size) of the policy-engine process
        try:
            output = server.ssh_command(
                "ps -o rss= -C policy-engine 2>/dev/null | head -1",
                timeout=5,
            )
            if output.strip():
                return int(output.strip())
        except Exception:
            pass
        return 0

    def _get_bpf_kernel_memory_kb(self, nodes) -> int:
        """Estimate kernel memory used by BPF maps/programs for this policy_engine instance in KB.

        This attempts to sum the approximate bytes allocated for pinned maps under
        /sys/fs/bpf/policy_engine by parsing `bpftool map show` output on the server.
        The result is an estimate; if bpftool or parsing is unavailable we return 0.
        """
        server = nodes["server"]

        # Simpler: find the policy-engine process cgroup and read its memory.stat
        # Return the sum of 'kernel' and 'slab' fields (in KB).
        cmd = (
            "pid=$(pgrep -x policy-engine | head -1); "
            'if [ -z "$pid" ]; then echo 0; exit 0; fi; '
            "cpath=$(awk -F: '{print $3}' /proc/$pid/cgroup | tail -1); "
            "if [ -f /sys/fs/cgroup${cpath}/memory.stat ]; then f=/sys/fs/cgroup${cpath}/memory.stat; "
            "elif [ -f /sys/fs/cgroup/memory${cpath}/memory.stat ]; then f=/sys/fs/cgroup/memory${cpath}/memory.stat; "
            "else echo 0; exit 0; fi; "
            "awk '/^kernel /{k=$2} /^slab /{s=$2} END{print int(((k?k:0)+(s?s:0))/1024)}' $f"
        )

        try:
            output = server.ssh_command(cmd, timeout=10)
            if output and output.strip():
                try:
                    return int(output.strip())
                except Exception:
                    pass
        except Exception:
            pass

        return 0

    def _generate_ipv4_prefix(self, index: int) -> str:
        """Generate a unique IPv4 /32 prefix from an index."""
        # Use 10.x.x.x range to generate unique addresses
        # index 0-255: 10.0.0.x
        # index 256-65535: 10.0.x.x
        # index 65536+: 10.x.x.x
        octet1 = 10
        octet2 = (index >> 16) & 0xFF
        octet3 = (index >> 8) & 0xFF
        octet4 = index & 0xFF
        return f"{octet1}.{octet2}.{octet3}.{octet4}/32"

    def _generate_ipv6_prefix(self, index: int) -> str:
        """Generate a unique IPv6 /128 prefix from an index."""
        # Use 2001:db8::/32 documentation range
        # Format: 2001:db8:XXXX:XXXX::1/128
        high = (index >> 16) & 0xFFFF
        low = index & 0xFFFF
        return f"2001:db8:{high:04x}:{low:04x}::1/128"

    def test_ipv4_rule_installation_performance(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        bpftool_installed,
    ):
        """Test performance of installing many IPv4 rules."""
        num_rules = self.NUM_RULES

        # Get initial memory usage
        initial_memory_kb = self._get_memory_usage_kb(nodes)
        initial_kernel_kb = self._get_bpf_kernel_memory_kb(nodes)
        logger.info(f"Initial memory usage: {initial_memory_kb} KB")
        logger.info(f"Initial BPF kernel memory (est): {initial_kernel_kb} KB")

        # Track individual rule installation times
        install_times = []
        failed_rules = 0

        logger.info(f"Starting installation of {num_rules} IPv4 rules...")
        total_start = time.perf_counter()

        for i in range(num_rules):
            prefix = self._generate_ipv4_prefix(i)
            options = AddRuleOptions(
                interface=attached_ingress,
                rule_id=200000 + i,
                src=prefix,
                dst="0.0.0.0/0",
                protocol="any",
                dport=(i % 65535) + 1,
                actions=[("pass", 0)],
            )

            rule_start = time.perf_counter()
            result = policy_client.add_rule(options, timeout=60)
            rule_elapsed = time.perf_counter() - rule_start
            install_times.append(rule_elapsed)

            if not result.success:
                failed_rules += 1
                if failed_rules <= 5:  # Only log first few failures
                    logger.warning(f"Rule {i} failed: {result.message}")

            # Log progress every 1000 rules
            if (i + 1) % 1000 == 0:
                elapsed = time.perf_counter() - total_start
                rate = (i + 1) / elapsed
                logger.info(
                    f"Progress: {i + 1}/{num_rules} rules installed "
                    f"({elapsed:.2f}s, {rate:.1f} rules/sec)"
                )

        total_elapsed = time.perf_counter() - total_start

        # Get final memory usage
        final_memory_kb = self._get_memory_usage_kb(nodes)
        final_kernel_kb = self._get_bpf_kernel_memory_kb(nodes)
        memory_delta_kb = final_memory_kb - initial_memory_kb
        kernel_delta_kb = final_kernel_kb - initial_kernel_kb

        # Calculate statistics
        avg_time_ms = (sum(install_times) / len(install_times)) * 1000
        min_time_ms = min(install_times) * 1000
        max_time_ms = max(install_times) * 1000
        rules_per_sec = num_rules / total_elapsed

        # Sort for percentiles
        sorted_times = sorted(install_times)
        p50_ms = sorted_times[len(sorted_times) // 2] * 1000
        p95_ms = sorted_times[int(len(sorted_times) * 0.95)] * 1000
        p99_ms = sorted_times[int(len(sorted_times) * 0.99)] * 1000

        logger.info("=" * 60)
        logger.info("IPv4 Rule Installation Performance Results")
        logger.info("=" * 60)
        logger.info(f"Total rules:        {num_rules}")
        logger.info(f"Failed rules:       {failed_rules}")
        logger.info(f"Total time:         {total_elapsed:.2f} seconds")
        logger.info(f"Rules per second:   {rules_per_sec:.1f}")
        logger.info(f"Avg install time:   {avg_time_ms:.3f} ms")
        logger.info(f"Min install time:   {min_time_ms:.3f} ms")
        logger.info(f"Max install time:   {max_time_ms:.3f} ms")
        logger.info(f"P50 install time:   {p50_ms:.3f} ms")
        logger.info(f"P95 install time:   {p95_ms:.3f} ms")
        logger.info(f"P99 install time:   {p99_ms:.3f} ms")
        logger.info(f"Initial memory:     {initial_memory_kb} KB")
        logger.info(f"Final memory:       {final_memory_kb} KB")
        logger.info(
            f"Memory delta:       {memory_delta_kb} KB ({memory_delta_kb / 1024:.2f} MB)"
        )
        logger.info(f"Final BPF kernel memory (est): {final_kernel_kb} KB")
        logger.info(
            f"BPF kernel memory delta (est): {kernel_delta_kb} KB ({kernel_delta_kb / 1024:.2f} MB)"
        )
        logger.info(f"Memory per rule:    {memory_delta_kb / num_rules:.2f} KB")
        logger.info("=" * 60)

        assert failed_rules == 0, f"Failed rules: {failed_rules}"

    def test_ipv6_rule_installation_performance(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        bpftool_installed,
    ):
        """Test performance of installing many IPv6 rules."""
        num_rules = self.NUM_RULES

        # Get initial memory usage
        initial_memory_kb = self._get_memory_usage_kb(nodes)
        initial_kernel_kb = self._get_bpf_kernel_memory_kb(nodes)
        logger.info(f"Initial memory usage: {initial_memory_kb} KB")
        logger.info(f"Initial BPF kernel memory (est): {initial_kernel_kb} KB")

        # Track individual rule installation times
        install_times = []
        failed_rules = 0

        logger.info(f"Starting installation of {num_rules} IPv6 rules...")
        total_start = time.perf_counter()

        for i in range(num_rules):
            prefix = self._generate_ipv6_prefix(i)
            options = AddRuleOptions(
                interface=attached_ingress,
                rule_id=300000 + i,
                src=prefix,
                dst="::/0",
                protocol="any",
                dport=(i % 65535) + 1,
                actions=[("pass", 0)],
            )

            rule_start = time.perf_counter()
            result = policy_client.add_rule(options, timeout=60)
            rule_elapsed = time.perf_counter() - rule_start
            install_times.append(rule_elapsed)

            if not result.success:
                failed_rules += 1
                if failed_rules <= 5:
                    logger.warning(f"Rule {i} failed: {result.message}")

            # Log progress every 1000 rules
            if (i + 1) % 1000 == 0:
                elapsed = time.perf_counter() - total_start
                rate = (i + 1) / elapsed
                logger.info(
                    f"Progress: {i + 1}/{num_rules} rules installed "
                    f"({elapsed:.2f}s, {rate:.1f} rules/sec)"
                )

        total_elapsed = time.perf_counter() - total_start

        # Get final memory usage
        final_memory_kb = self._get_memory_usage_kb(nodes)
        final_kernel_kb = self._get_bpf_kernel_memory_kb(nodes)
        memory_delta_kb = final_memory_kb - initial_memory_kb
        kernel_delta_kb = final_kernel_kb - initial_kernel_kb

        # Calculate statistics
        avg_time_ms = (sum(install_times) / len(install_times)) * 1000
        min_time_ms = min(install_times) * 1000
        max_time_ms = max(install_times) * 1000
        rules_per_sec = num_rules / total_elapsed

        # Sort for percentiles
        sorted_times = sorted(install_times)
        p50_ms = sorted_times[len(sorted_times) // 2] * 1000
        p95_ms = sorted_times[int(len(sorted_times) * 0.95)] * 1000
        p99_ms = sorted_times[int(len(sorted_times) * 0.99)] * 1000

        logger.info("=" * 60)
        logger.info("IPv6 Rule Installation Performance Results")
        logger.info("=" * 60)
        logger.info(f"Total rules:        {num_rules}")
        logger.info(f"Failed rules:       {failed_rules}")
        logger.info(f"Total time:         {total_elapsed:.2f} seconds")
        logger.info(f"Rules per second:   {rules_per_sec:.1f}")
        logger.info(f"Avg install time:   {avg_time_ms:.3f} ms")
        logger.info(f"Min install time:   {min_time_ms:.3f} ms")
        logger.info(f"Max install time:   {max_time_ms:.3f} ms")
        logger.info(f"P50 install time:   {p50_ms:.3f} ms")
        logger.info(f"P95 install time:   {p95_ms:.3f} ms")
        logger.info(f"P99 install time:   {p99_ms:.3f} ms")
        logger.info(f"Initial memory:     {initial_memory_kb} KB")
        logger.info(f"Final memory:       {final_memory_kb} KB")
        logger.info(
            f"Memory delta:       {memory_delta_kb} KB ({memory_delta_kb / 1024:.2f} MB)"
        )
        logger.info(f"Final BPF kernel memory (est): {final_kernel_kb} KB")
        logger.info(
            f"BPF kernel memory delta (est): {kernel_delta_kb} KB ({kernel_delta_kb / 1024:.2f} MB)"
        )
        logger.info(f"Memory per rule:    {memory_delta_kb / num_rules:.2f} KB")
        logger.info("=" * 60)

        assert failed_rules == 0, f"Failed rules: {failed_rules}"

    def test_mixed_v4_v6_rule_installation_performance(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        bpftool_installed,
    ):
        """Test performance of installing mixed IPv4 and IPv6 rules (alternating)."""
        num_rules = self.NUM_RULES

        # Get initial memory usage
        initial_memory_kb = self._get_memory_usage_kb(nodes)
        initial_kernel_kb = self._get_bpf_kernel_memory_kb(nodes)
        logger.info(f"Initial memory usage: {initial_memory_kb} KB")
        logger.info(f"Initial BPF kernel memory (est): {initial_kernel_kb} KB")

        # Track individual rule installation times separately
        ipv4_times = []
        ipv6_times = []
        failed_rules = 0

        logger.info(f"Starting installation of {num_rules} mixed IPv4/IPv6 rules...")
        total_start = time.perf_counter()

        for i in range(num_rules):
            is_ipv6 = i % 2 == 1  # Alternate between v4 and v6

            if is_ipv6:
                prefix = self._generate_ipv6_prefix(i // 2)
                options = AddRuleOptions(
                    interface=attached_ingress,
                    rule_id=400000 + i,
                    src=prefix,
                    dst="::/0",
                    protocol="any",
                    dport=(i % 65535) + 1,
                    actions=[("pass", 0)],
                )
            else:
                prefix = self._generate_ipv4_prefix(i // 2)
                options = AddRuleOptions(
                    interface=attached_ingress,
                    rule_id=400000 + i,
                    src=prefix,
                    dst="0.0.0.0/0",
                    protocol="any",
                    dport=(i % 65535) + 1,
                    actions=[("pass", 0)],
                )

            rule_start = time.perf_counter()
            result = policy_client.add_rule(options, timeout=60)
            rule_elapsed = time.perf_counter() - rule_start

            if is_ipv6:
                ipv6_times.append(rule_elapsed)
            else:
                ipv4_times.append(rule_elapsed)

            if not result.success:
                failed_rules += 1
                if failed_rules <= 5:
                    logger.warning(
                        f"Rule {i} ({'v6' if is_ipv6 else 'v4'}) failed: {result.message}"
                    )

            # Log progress every 1000 rules
            if (i + 1) % 1000 == 0:
                elapsed = time.perf_counter() - total_start
                rate = (i + 1) / elapsed
                logger.info(
                    f"Progress: {i + 1}/{num_rules} rules installed "
                    f"({elapsed:.2f}s, {rate:.1f} rules/sec)"
                )

        total_elapsed = time.perf_counter() - total_start

        # Get final memory usage
        final_memory_kb = self._get_memory_usage_kb(nodes)
        final_kernel_kb = self._get_bpf_kernel_memory_kb(nodes)
        memory_delta_kb = final_memory_kb - initial_memory_kb
        kernel_delta_kb = final_kernel_kb - initial_kernel_kb

        # Calculate statistics for combined
        all_times = ipv4_times + ipv6_times
        avg_time_ms = (sum(all_times) / len(all_times)) * 1000
        min_time_ms = min(all_times) * 1000
        max_time_ms = max(all_times) * 1000
        rules_per_sec = num_rules / total_elapsed

        # IPv4 specific stats
        ipv4_avg_ms = (sum(ipv4_times) / len(ipv4_times)) * 1000 if ipv4_times else 0
        ipv6_avg_ms = (sum(ipv6_times) / len(ipv6_times)) * 1000 if ipv6_times else 0

        # Sort for percentiles
        sorted_times = sorted(all_times)
        p50_ms = sorted_times[len(sorted_times) // 2] * 1000
        p95_ms = sorted_times[int(len(sorted_times) * 0.95)] * 1000
        p99_ms = sorted_times[int(len(sorted_times) * 0.99)] * 1000

        logger.info("=" * 60)
        logger.info("Mixed IPv4/IPv6 Rule Installation Performance Results")
        logger.info("=" * 60)
        logger.info(
            f"Total rules:        {num_rules} ({len(ipv4_times)} v4, {len(ipv6_times)} v6)"
        )
        logger.info(f"Failed rules:       {failed_rules}")
        logger.info(f"Total time:         {total_elapsed:.2f} seconds")
        logger.info(f"Rules per second:   {rules_per_sec:.1f}")
        logger.info(f"Avg install time:   {avg_time_ms:.3f} ms (combined)")
        logger.info(f"  IPv4 avg time:    {ipv4_avg_ms:.3f} ms")
        logger.info(f"  IPv6 avg time:    {ipv6_avg_ms:.3f} ms")
        logger.info(f"Min install time:   {min_time_ms:.3f} ms")
        logger.info(f"Max install time:   {max_time_ms:.3f} ms")
        logger.info(f"P50 install time:   {p50_ms:.3f} ms")
        logger.info(f"P95 install time:   {p95_ms:.3f} ms")
        logger.info(f"P99 install time:   {p99_ms:.3f} ms")
        logger.info(f"Initial memory:     {initial_memory_kb} KB")
        logger.info(f"Final memory:       {final_memory_kb} KB")
        logger.info(
            f"Memory delta:       {memory_delta_kb} KB ({memory_delta_kb / 1024:.2f} MB)"
        )
        logger.info(f"Final BPF kernel memory (est): {final_kernel_kb} KB")
        logger.info(
            f"BPF kernel memory delta (est): {kernel_delta_kb} KB ({kernel_delta_kb / 1024:.2f} MB)"
        )
        logger.info(f"Memory per rule:    {memory_delta_kb / num_rules:.2f} KB")
        logger.info("=" * 60)

        assert failed_rules == 0, f"Failed rules: {failed_rules}"

    def test_rule_deletion_performance(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_rules,
        bpftool_installed,
    ):
        """Test performance of deleting many rules after installation."""
        num_rules = self.NUM_RULES

        # First, install the rules
        logger.info(f"Installing {num_rules} IPv4 rules for deletion test...")
        install_start = time.perf_counter()

        for i in range(num_rules):
            prefix = self._generate_ipv4_prefix(i)
            options = AddRuleOptions(
                interface=attached_ingress,
                rule_id=500000 + i,
                src=prefix,
                dst="0.0.0.0/0",
                protocol="any",
                dport=(i % 65535) + 1,
                actions=[("pass", 0)],
            )
            policy_client.add_rule(options)

            if (i + 1) % 2000 == 0:
                logger.info(f"Installed {i + 1}/{num_rules} rules...")

        install_elapsed = time.perf_counter() - install_start
        logger.info(f"Installation complete in {install_elapsed:.2f}s")

        # Get memory before deletion
        memory_before_delete_kb = self._get_memory_usage_kb(nodes)
        kernel_before_delete_kb = self._get_bpf_kernel_memory_kb(nodes)

        # Now time the deletions
        delete_times = []
        failed_deletes = 0

        logger.info(f"Starting deletion of {num_rules} rules...")
        delete_start = time.perf_counter()

        for i in range(num_rules):
            rule_id = 500000 + i

            rule_start = time.perf_counter()
            result = policy_client.delete_rule(attached_ingress, rule_id=rule_id)
            rule_elapsed = time.perf_counter() - rule_start
            delete_times.append(rule_elapsed)

            if not result.success:
                failed_deletes += 1

            if (i + 1) % 1000 == 0:
                elapsed = time.perf_counter() - delete_start
                rate = (i + 1) / elapsed
                logger.info(
                    f"Progress: {i + 1}/{num_rules} rules deleted "
                    f"({elapsed:.2f}s, {rate:.1f} rules/sec)"
                )

        delete_elapsed = time.perf_counter() - delete_start

        # Get memory after deletion
        memory_after_delete_kb = self._get_memory_usage_kb(nodes)
        kernel_after_delete_kb = self._get_bpf_kernel_memory_kb(nodes)
        memory_freed_kb = memory_before_delete_kb - memory_after_delete_kb
        kernel_freed_kb = kernel_before_delete_kb - kernel_after_delete_kb

        # Calculate statistics
        avg_time_ms = (sum(delete_times) / len(delete_times)) * 1000
        min_time_ms = min(delete_times) * 1000
        max_time_ms = max(delete_times) * 1000
        rules_per_sec = num_rules / delete_elapsed

        sorted_times = sorted(delete_times)
        p50_ms = sorted_times[len(sorted_times) // 2] * 1000
        p95_ms = sorted_times[int(len(sorted_times) * 0.95)] * 1000
        p99_ms = sorted_times[int(len(sorted_times) * 0.99)] * 1000

        logger.info("=" * 60)
        logger.info("Rule Deletion Performance Results")
        logger.info("=" * 60)
        logger.info(f"Total rules:        {num_rules}")
        logger.info(f"Failed deletes:     {failed_deletes}")
        logger.info(f"Total time:         {delete_elapsed:.2f} seconds")
        logger.info(f"Rules per second:   {rules_per_sec:.1f}")
        logger.info(f"Avg delete time:    {avg_time_ms:.3f} ms")
        logger.info(f"Min delete time:    {min_time_ms:.3f} ms")
        logger.info(f"Max delete time:    {max_time_ms:.3f} ms")
        logger.info(f"P50 delete time:    {p50_ms:.3f} ms")
        logger.info(f"P95 delete time:    {p95_ms:.3f} ms")
        logger.info(f"P99 delete time:    {p99_ms:.3f} ms")
        logger.info(f"Memory before del:  {memory_before_delete_kb} KB")
        logger.info(f"Memory after del:   {memory_after_delete_kb} KB")
        logger.info(
            f"Memory freed:       {memory_freed_kb} KB ({memory_freed_kb / 1024:.2f} MB)"
        )
        logger.info(f"BPF kernel memory before del (est): {kernel_before_delete_kb} KB")
        logger.info(f"BPF kernel memory after del (est):  {kernel_after_delete_kb} KB")
        logger.info(
            f"BPF kernel memory freed (est):      {kernel_freed_kb} KB ({kernel_freed_kb / 1024:.2f} MB)"
        )
        logger.info("=" * 60)

        success_rate = (num_rules - failed_deletes) / num_rules
        assert success_rate >= 0.99, (
            f"Too many failed deletes: {failed_deletes}/{num_rules}"
        )

    def test_batch_rule_installation_performance(
        self,
        nodes,
        graphql_policy_client,
        attached_ingress,
        clean_rules,
        bpftool_installed,
    ):
        """
        Test performance of batch rule installation using the addRules GraphQL mutation.

        This test uses the batch API which installs all rules in a single request,
        compared to the individual installation tests that make one request per rule.
        """
        # This test specifically requires the GraphQL client for batch support
        if not isinstance(graphql_policy_client, GraphQLPolicyClient):
            pytest.skip("Batch API requires GraphQL client")

        num_rules = self.NUM_RULES

        # Get initial memory usage
        initial_memory_kb = self._get_memory_usage_kb(nodes)
        initial_kernel_kb = self._get_bpf_kernel_memory_kb(nodes)
        logger.info(f"Initial memory usage: {initial_memory_kb} KB")
        logger.info(f"Initial BPF kernel memory (est): {initial_kernel_kb} KB")

        # Build the batch of rules
        rules = []
        for i in range(num_rules):
            prefix = self._generate_ipv4_prefix(i)
            options = AddRuleOptions(
                interface=attached_ingress,
                rule_id=600000 + i,
                src=prefix,
                dst="0.0.0.0/0",
                protocol="any",
                dport=(i % 65535) + 1,
                actions=[("pass", 0)],
            )
            rules.append(options)

        logger.info(f"Starting batch installation of {num_rules} IPv4 rules...")
        total_start = time.perf_counter()

        # Single batch call for all rules
        result = graphql_policy_client.add_rules_batch(rules)

        total_elapsed = time.perf_counter() - total_start

        # Skip if batch API is not implemented yet
        if not result.success and "Unknown field" in result.message:
            pytest.skip("Batch addRules API not implemented yet")

        # Get final memory usage
        final_memory_kb = self._get_memory_usage_kb(nodes)
        final_kernel_kb = self._get_bpf_kernel_memory_kb(nodes)
        memory_delta_kb = final_memory_kb - initial_memory_kb
        kernel_delta_kb = final_kernel_kb - initial_kernel_kb

        # Calculate statistics
        rules_per_sec = num_rules / total_elapsed
        avg_time_per_rule_ms = (total_elapsed / num_rules) * 1000

        logger.info("=" * 60)
        logger.info("Batch Rule Installation Performance Results")
        logger.info("=" * 60)
        logger.info(f"Total rules:        {num_rules}")
        logger.info(f"Succeeded:          {result.succeeded}")
        logger.info(f"Failed:             {result.failed}")
        logger.info(f"Total time:         {total_elapsed:.2f} seconds")
        logger.info(f"Rules per second:   {rules_per_sec:.1f}")
        logger.info(f"Avg time per rule:  {avg_time_per_rule_ms:.3f} ms")
        logger.info(f"Initial memory:     {initial_memory_kb} KB")
        logger.info(f"Final memory:       {final_memory_kb} KB")
        logger.info(
            f"Memory delta:       {memory_delta_kb} KB ({memory_delta_kb / 1024:.2f} MB)"
        )
        logger.info(f"Final BPF kernel memory (est): {final_kernel_kb} KB")
        logger.info(
            f"BPF kernel memory delta (est): {kernel_delta_kb} KB ({kernel_delta_kb / 1024:.2f} MB)"
        )
        logger.info(f"Memory per rule:    {memory_delta_kb / num_rules:.2f} KB")
        logger.info("=" * 60)

        assert result.success, f"Batch installation failed: {result.message}"
        assert result.succeeded == num_rules, (
            f"Failed rules: {num_rules - result.succeeded} out of {num_rules}"
        )

    def test_batch_rule_deletion(
        self,
        nodes,
        graphql_policy_client,
        attached_ingress,
        clean_rules,
        bpftool_installed,
    ):
        """
        Add a small batch of rules, then delete them using the deleteRules batch mutation.
        """
        if not isinstance(graphql_policy_client, GraphQLPolicyClient):
            pytest.skip("Batch API requires GraphQL client")

        # Use the same pattern as the batch installation performance test
        num_rules = self.NUM_RULES

        # Get initial memory (userland) and kernel BPF memory estimates
        initial_memory_kb = self._get_memory_usage_kb(nodes)
        initial_kernel_kb = self._get_bpf_kernel_memory_kb(nodes)

        # Build the batch of rules and ids using comprehensions
        rules = [
            AddRuleOptions(
                interface=attached_ingress,
                rule_id=700000 + i,
                src=self._generate_ipv4_prefix(i),
                dst="0.0.0.0/0",
                protocol="any",
                actions=[("pass", 0)],
            )
            for i in range(num_rules)
        ]
        ids = [700000 + i for i in range(num_rules)]

        logger.info(
            f"Starting batch installation of {num_rules} IPv4 rules for deletion test..."
        )
        total_start = time.perf_counter()

        add_result = graphql_policy_client.add_rules_batch(rules)

        total_elapsed = time.perf_counter() - total_start

        # If batch add isn't implemented, skip the test
        if not add_result.success and "Unknown field" in add_result.message:
            pytest.skip("Batch addRules API not implemented yet")

        # Get final memory usage and kernel estimate after add
        final_memory_kb = self._get_memory_usage_kb(nodes)
        final_kernel_kb = self._get_bpf_kernel_memory_kb(nodes)
        memory_delta_kb = final_memory_kb - initial_memory_kb
        kernel_delta_kb = final_kernel_kb - initial_kernel_kb

        logger.info(
            f"Batch add: total={num_rules} succeeded={add_result.succeeded} failed={add_result.failed} time={total_elapsed:.2f}s mem_delta={memory_delta_kb}KB kernel_delta={kernel_delta_kb}KB"
        )

        assert add_result.succeeded == num_rules

        # Confirm rules present
        existing = graphql_policy_client.list_rules()
        present_ids = {r.rule_id for r in existing}
        for rid in ids:
            assert rid in present_ids

        # Now delete them in a batch and measure
        delete_start = time.perf_counter()
        delete_result = graphql_policy_client.delete_rules_batch(attached_ingress, ids)
        delete_elapsed = time.perf_counter() - delete_start

        # If server doesn't implement deleteRules, skip
        if not delete_result.success and "Unknown field" in delete_result.message:
            pytest.skip("Batch deleteRules API not implemented yet")

        # Get memory after deletion and kernel estimate
        mem_after_delete_kb = self._get_memory_usage_kb(nodes)
        kernel_after_delete_kb = self._get_bpf_kernel_memory_kb(nodes)
        memory_freed_kb = final_memory_kb - mem_after_delete_kb
        kernel_freed_kb = final_kernel_kb - kernel_after_delete_kb

        logger.info(
            f"Batch delete: succeeded={delete_result.succeeded} failed={delete_result.failed} time={delete_elapsed:.2f}s mem_after_delete={mem_after_delete_kb}KB mem_freed={memory_freed_kb}KB kernel_freed={kernel_freed_kb}KB"
        )

        assert delete_result.succeeded == num_rules

        # Verify they are gone
        existing_after = graphql_policy_client.list_rules()
        present_after = {r.rule_id for r in existing_after}
        for rid in ids:
            assert rid not in present_after
