# Copyright (c) Peter Morrow

"""
Rootward conftest for the policy-engine integration suites.

netsim supplies the topology/VM/SSH fixtures; the options below are the ones
only policy-engine needs, so they stay out of netsim.

These must be declared here rather than in tests/scale_test/conftest.py. A
suite-level conftest only registers options when that suite is itself an
initial conftest, so under ``pytest python/tests/`` they would silently
vanish.
"""

pytest_plugins = ["netsim.testkit.plugin"]


def pytest_addoption(parser) -> None:
    """Add the options consumed by tests/scale_test/."""
    parser.addoption(
        "--scale-nodes",
        action="store",
        type=int,
        default=10,
        help="Number of policy-engine + policy-node-agent container pairs to spin up in scale tests",
    )
    parser.addoption(
        "--engine-image",
        action="store",
        default="policy-engine:0.1.0",
        help="Docker image name for policy-engine (must exist in local daemon)",
    )
    parser.addoption(
        "--agent-image",
        action="store",
        default="policy-node-agent:0.1.0",
        help="Docker image name for policy-node-agent (must exist in local daemon)",
    )
