# Copyright (c) Peter Morrow

"""
Fixtures for scale testing: many policy-engine + policy-node-agent container
pairs enrolling against a single policy-controller.

Topology: 1 controller VM + 1 docker-host VM (both on mgmt network).

The docker-host VM runs N engine+agent container pairs on an internal Docker
bridge network.  Because policy-engine only needs --network host when attaching
XDP/TC programs to real NICs, and these tests never attach BPF programs, the
engines run on a bridge network with unique IPs.  Each agent shares its engine's
network namespace via --network container:<engine>, so localhost:8080 resolves
correctly without port conflicts.

Fixture hierarchy (all package-scoped unless noted):
  running_topology → nodes → install_user_packages
    controller_service  — starts policy-controller on controller VM (systemd)
    controller_client   — ControllerClient bound to the controller VM
    docker_ready        — installs Docker on docker-host, loads engine/agent images
    scale_containers    — mints a single ZTP bundle, starts N engine+agent
                          container pairs each carrying the bundle
    enrolled_scale_nodes — waits for all N nodes to auto-enrol (Active + online)

CLI options (registered in tests/conftest.py):
  --scale-nodes     int   number of node pairs to create (default 10)
  --engine-image    str   local Docker image name for policy-engine
  --agent-image     str   local Docker image name for policy-node-agent
"""

import ipaddress
import logging
import subprocess
import time
from dataclasses import dataclass
from typing import Callable, Dict, Generator, List

import pytest

from netsim.testkit.node import Node
from netsim.testkit.parallel_utils import run_parallel_simple
from netsim.testkit.systemd_utils import ServiceStatus, restart_service, stop_service
from policy_engine_client.controller.graphql.client import (
    ControllerClient,
    mint_api_token,
)
from policy_engine_client.engine.graphql.client import GraphQLPolicyClient

logger = logging.getLogger(__name__)

_CONTROLLER_HTTP_TIMEOUT = 60
_ENROLLMENT_TIMEOUT = 300  # longer than multi_node — N agents start in parallel
_ACTIVE_TIMEOUT = 120
_POLL_INTERVAL = 2
_DOCKER_BRIDGE = "scale_net"
_DOCKER_DATA_BRIDGE = "scale_data"
_SCALE_BASE_DIR = "/tmp/scale"

# Fleet label stamped onto every node by the single ZTP enrollment token. The
# controller applies this as each node's `label` on auto-approval, so it's the
# value tests see in ControlledNode.label (not the synthetic scale-node-N name).
SCALE_FLEET_LABEL = "netsim-scale"


# ── Data types ────────────────────────────────────────────────────────────────


@dataclass
class ContainerPair:
    """Names, bridge IP, and data interface for one engine+agent pair."""

    index: int
    engine_name: str
    agent_name: str
    engine_ip: str  # IP on scale_net — for reaching the engine GraphQL API
    data_iface: str  # interface name inside the container for BPF attachment


@dataclass
class EnrollmentResult:
    """Outcome of the full enrollment sequence."""

    node_map: Dict[str, str]  # synthetic scale-node-N name → controller node ID
    seconds_to_active: float  # wall time: first container start → last Active
    seconds_to_online: float  # wall time: first container start → last online


# ── Internal helpers ──────────────────────────────────────────────────────────


def _get_mgmt_ip(node: Node, topology) -> str:
    topo_node = topology.get_node(node.name)
    mgmt_net_name = topo_node.networks[0]
    mgmt_network = topology.get_network(mgmt_net_name)
    net = ipaddress.IPv4Network(mgmt_network.subnet, strict=False)
    out = node.ssh_command(
        "ip -4 addr show | awk '/inet / {print $2}' | cut -d/ -f1",
        timeout=10,
    ).strip()
    for addr_str in out.splitlines():
        try:
            addr = ipaddress.IPv4Address(addr_str.strip())
            if addr in net:
                return str(addr)
        except ValueError:
            continue
    pytest.fail(f"Could not determine management IP for {node.name}")


def _wait_for_controller_http(
    controller: Node, timeout: int = _CONTROLLER_HTTP_TIMEOUT
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            out = controller.ssh_command(
                "curl -s -o /dev/null -w '%{http_code}' "
                "--max-time 2 http://127.0.0.1:8443/health 2>/dev/null || true",
                timeout=10,
            )
            if out.strip() == "200":
                logger.info("policy-controller HTTP API ready")
                return
        except Exception:
            pass
        time.sleep(_POLL_INTERVAL)
    pytest.fail(f"policy-controller did not become ready within {timeout}s")


def _wait_for_pending_enrollments(
    client: ControllerClient,
    expected_count: int,
    timeout: int = _ENROLLMENT_TIMEOUT,
) -> List:
    """Negative-path helper: ZTP happy path never transits Pending."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            pending = client.pending_enrollments()
            if len(pending) >= expected_count:
                logger.info(f"Found {len(pending)} pending enrollments")
                return pending
        except Exception as e:
            logger.debug(f"Polling enrollments: {e}")
        time.sleep(_POLL_INTERVAL)
    pytest.fail(
        f"Expected {expected_count} pending enrollments, timed out after {timeout}s"
    )


def _wait_for_active_nodes_by_hostname(
    client: ControllerClient,
    expected_hostnames: List[str],
    timeout: int = _ENROLLMENT_TIMEOUT,
) -> Dict[str, str]:
    """Wait until every expected hostname has an Active node entry; return hostname → node_id."""
    deadline = time.monotonic() + timeout
    needed = set(expected_hostnames)
    while time.monotonic() < deadline:
        try:
            active = client.list_nodes(status="active")
            by_host = {n.hostname: n.id for n in active if n.hostname in needed}
            if needed.issubset(by_host.keys()):
                logger.info(f"All {len(by_host)} nodes active (matched by hostname)")
                return by_host
            waiting = len(needed) - len(by_host)
            logger.debug(f"{waiting}/{len(needed)} nodes still waiting for Active")
        except Exception as e:
            logger.debug(f"Polling active nodes: {e}")
        time.sleep(_POLL_INTERVAL)
    pytest.fail(
        f"Active nodes for {len(expected_hostnames)} hostnames did not appear within {timeout}s"
    )


def _wait_for_active_nodes(
    client: ControllerClient,
    node_ids: List[str],
    timeout: int = _ACTIVE_TIMEOUT,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            active = {n.id for n in client.list_nodes(status="active")}
            if all(nid in active for nid in node_ids):
                logger.info(f"All {len(node_ids)} nodes active")
                return
            waiting = sum(1 for nid in node_ids if nid not in active)
            logger.debug(f"{waiting}/{len(node_ids)} nodes still waiting for Active")
        except Exception as e:
            logger.debug(f"Polling active nodes: {e}")
        time.sleep(_POLL_INTERVAL)
    pytest.fail(f"{len(node_ids)} nodes did not reach Active within {timeout}s")


def _wait_for_online_nodes(
    client: ControllerClient,
    node_ids: List[str],
    timeout: int = _ACTIVE_TIMEOUT,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            online = set(client.online_nodes())
            if all(nid in online for nid in node_ids):
                logger.info(f"All {len(node_ids)} nodes online")
                return
            waiting = sum(1 for nid in node_ids if nid not in online)
            logger.debug(f"{waiting}/{len(node_ids)} nodes still waiting for online")
        except Exception as e:
            logger.debug(f"Polling online nodes: {e}")
        time.sleep(_POLL_INTERVAL)
    pytest.fail(f"{len(node_ids)} nodes did not come online within {timeout}s")


def _save_and_load_image(node: Node, image_name: str) -> None:
    """Stream a Docker image from the local daemon into the VM's Docker daemon via SSH pipe."""
    logger.info(f"Streaming Docker image {image_name} to docker-host")
    # Pipe docker save directly into docker load over SSH — no temp file, no
    # ownership issues from sudo docker save writing a root-owned tarball.
    cmd = (
        f"sudo docker save {image_name} | "
        f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"-p {node.ssh_port} netsim@localhost sudo docker load"
    )
    result = subprocess.run(cmd, shell=True, capture_output=True)
    if result.returncode == 0:
        logger.info(f"Loaded {image_name} into docker-host")
        return
    pytest.fail(
        f"Could not transfer Docker image '{image_name}' to docker-host. "
        f"Verify it exists: docker images | grep {image_name.split(':')[0]}"
    )


def _install_docker(node: Node) -> None:
    """Install docker.io on the VM if not already present."""
    check = node.ssh_command(
        "command -v docker >/dev/null 2>&1 && echo PRESENT || echo MISSING",
        timeout=10,
    )
    if "PRESENT" in check:
        logger.info("Docker already installed on docker-host")
        return

    logger.info("Installing docker.io on docker-host")
    node.ssh_command(
        "sudo apt-get install -y docker.io",
        timeout=300,
    )
    node.ssh_command("sudo systemctl enable --now docker", timeout=30)
    # Verify
    node.ssh_command("sudo docker info >/dev/null", timeout=30)
    logger.info("Docker installed successfully")


def _ensure_scale_network(node: Node) -> None:
    """Create both Docker bridge networks used by scale containers."""
    existing = node.ssh_command(
        "sudo docker network ls --format '{{.Name}}'",
        timeout=10,
    )
    for bridge in (_DOCKER_BRIDGE, _DOCKER_DATA_BRIDGE):
        if bridge not in existing:
            node.ssh_command(f"sudo docker network create {bridge}", timeout=30)
            logger.info(f"Created Docker network {bridge}")


def _connect_engine_to_data_network(node: Node, idx: int) -> str:
    """Connect engine container to the data bridge; return the interface name inside it."""
    node.ssh_command(
        f"sudo docker network connect {_DOCKER_DATA_BRIDGE} pe-{idx}",
        timeout=15,
    )
    # Discover the newly added interface from the host's perspective using
    # nsenter — the engine image may not have iproute2.  Strip the @ifN
    # peer suffix that ip -br appends.
    iface = node.ssh_command(
        f"pid=$(sudo docker inspect -f '{{{{.State.Pid}}}}' pe-{idx}) && "
        f"sudo nsenter -n -t $pid ip -br link show "
        f"| awk '$1 != \"lo\" {{print $1}}' | sed 's/@.*//' | sort | tail -1",
        timeout=15,
    ).strip()
    if not iface:
        pytest.fail(f"Could not discover data interface for pe-{idx}")
    return iface


def _write_engine_config(node: Node, idx: int) -> str:
    """Write engine config.toml; return the config directory path."""
    cfg_dir = f"{_SCALE_BASE_DIR}/node-{idx}/engine"
    node.ssh_command(f"sudo mkdir -p {cfg_dir}/state", timeout=10)
    config = '[server]\nhost = "0.0.0.0"\nport = 8080\n'
    node.ssh_command(
        f"printf '%s' '{config}' | sudo tee {cfg_dir}/config.toml > /dev/null",
        timeout=10,
    )
    return cfg_dir


def _write_agent_config(node: Node, idx: int, bundle_b64: str) -> str:
    """
    Write agent config.toml and the ZTP bootstrap bundle; return the config dir.

    The bundle carries the controller URLs and pinned CA fingerprint, so
    config.toml only needs `local_server_url` (agent → local policy-engine).
    """
    cfg_dir = f"{_SCALE_BASE_DIR}/node-{idx}/agent"
    node.ssh_command(f"sudo mkdir -p {cfg_dir}", timeout=10)
    config = 'local_server_url = "http://127.0.0.1:8080/graphql"\n'
    node.ssh_command(
        f"printf '%s' '{config}' | sudo tee {cfg_dir}/config.toml > /dev/null",
        timeout=10,
    )
    node.ssh_command_with_stdin(
        f"sudo tee {cfg_dir}/bootstrap.bundle > /dev/null",
        bundle_b64,
        timeout=10,
    )
    # Containers don't use systemd DynamicUser, but the agent image likely
    # runs as non-root. Keep the bundle world-readable for the same reason as
    # the VM-based multi_node tests; it's short-lived and consumed on first use.
    node.ssh_command(f"sudo chmod 0644 {cfg_dir}/bootstrap.bundle", timeout=10)
    return cfg_dir


def _start_engine_container(
    node: Node, idx: int, engine_cfg_dir: str, controller_ip: str, image: str
) -> str:
    name = f"pe-{idx}"
    # A fresh bpffs mount per engine gives the container a real bpf filesystem
    # so BPF_OBJ_PIN succeeds, and instances don't conflict on pin paths.
    bpf_dir = f"{_SCALE_BASE_DIR}/bpf/node-{idx}"
    node.ssh_command(f"sudo mkdir -p {bpf_dir}", timeout=10)
    node.ssh_command(f"sudo mount -t bpf bpf {bpf_dir}", timeout=15)
    # bpffs root is 0700 by default; the engine needs to mkdir inside it.
    node.ssh_command(f"sudo chmod 0777 {bpf_dir}", timeout=10)

    # Remove any leftover container with the same name
    node.ssh_command(
        f"sudo docker rm -f {name} 2>/dev/null || true",
        timeout=15,
    )

    # --add-host goes on the engine container because it owns the network
    # namespace; the agent uses --network container:pe-N and inherits /etc/hosts.
    # --hostname is set to pna-N (not pe-N) because the agent shares this UTS
    # namespace and reports gethostname() to the controller during enrollment;
    # the scale fixture identifies nodes by their pna-N hostname.
    cmd = (
        f"sudo docker run -d "
        f"--name {name} "
        f"--hostname pna-{idx} "
        f"--network {_DOCKER_BRIDGE} "
        f"--add-host policy-controller:{controller_ip} "
        f"--privileged "
        f"-v {engine_cfg_dir}:/etc/policy-engine:ro "
        f"-v {engine_cfg_dir}/state:/var/lib/policy-engine "
        f"-v {bpf_dir}:/sys/fs/bpf "
        f"-e 'RUST_LOG=warn,policy_engine::server::event_stream=error,policy_engine::server::bpf_manager=error' "
        f"{image}"
    )
    node.ssh_command(cmd, timeout=30)
    return name


def _start_agent_container(node: Node, idx: int, agent_cfg_dir: str, image: str) -> str:
    name = f"pna-{idx}"
    node.ssh_command(
        f"sudo docker rm -f {name} 2>/dev/null || true",
        timeout=15,
    )
    cmd = (
        f"sudo docker run -d "
        f"--name {name} "
        f"--network container:pe-{idx} "
        f"-v {agent_cfg_dir}:/etc/policy-node-agent "
        f"-e RUST_LOG=warn "
        f"{image}"
    )
    node.ssh_command(cmd, timeout=30)
    return name


def _get_container_bridge_ip(node: Node, container_name: str) -> str:
    ip = node.ssh_command(
        f"sudo docker inspect "
        f"-f '{{{{.NetworkSettings.Networks.{_DOCKER_BRIDGE}.IPAddress}}}}' "
        f"{container_name}",
        timeout=10,
    ).strip()
    if not ip:
        pytest.fail(f"Could not get bridge IP for container {container_name}")
    return ip


def _stop_and_remove_containers(node: Node, pairs: List[ContainerPair]) -> None:
    names = [f"pe-{p.index}" for p in pairs] + [f"pna-{p.index}" for p in pairs]
    if not names:
        return
    name_list = " ".join(names)
    try:
        node.ssh_command(
            f"sudo docker rm -f {name_list} 2>/dev/null || true", timeout=60
        )
    except Exception as e:
        logger.warning(f"Error removing scale containers: {e}")


def _start_one_pair(
    node: Node,
    idx: int,
    controller_ip: str,
    bundle_b64: str,
    engine_image: str,
    agent_image: str,
) -> ContainerPair:
    """Start engine then agent for one node index. Runs in a thread."""
    engine_cfg = _write_engine_config(node, idx)
    agent_cfg = _write_agent_config(node, idx, bundle_b64)
    _start_engine_container(node, idx, engine_cfg, controller_ip, engine_image)
    _start_agent_container(node, idx, agent_cfg, agent_image)
    data_iface = _connect_engine_to_data_network(node, idx)
    engine_ip = _get_container_bridge_ip(node, f"pe-{idx}")
    return ContainerPair(
        index=idx,
        engine_name=f"pe-{idx}",
        agent_name=f"pna-{idx}",
        engine_ip=engine_ip,
        data_iface=data_iface,
    )


# ── Package-scoped fixtures ───────────────────────────────────────────────────


@pytest.fixture(scope="package")
def scale_node_count(request) -> int:
    return request.config.getoption("--scale-nodes")


@pytest.fixture(scope="package")
def engine_image(request) -> str:
    return request.config.getoption("--engine-image")


@pytest.fixture(scope="package")
def agent_image(request) -> str:
    return request.config.getoption("--agent-image")


@pytest.fixture(scope="package")
def controller_service(
    nodes, install_user_packages
) -> Generator[ServiceStatus, None, None]:
    """Start policy-controller on the controller VM."""
    controller = nodes["controller"]
    check = controller.ssh_command(
        "systemctl cat policy-controller.service >/dev/null 2>&1 && echo EXISTS || echo MISSING"
    )
    if "MISSING" in check:
        pytest.skip(
            "policy-controller.service not installed (check 'packages' in the topology yaml)"
        )

    status = restart_service(controller, "policy-controller")
    if not status.is_healthy:
        pytest.fail(f"Failed to start policy-controller: {status.status_text}")

    logger.info(f"policy-controller running PID={status.main_pid}")
    _wait_for_controller_http(controller)

    yield status

    try:
        stop_service(controller, "policy-controller")
    except Exception as e:
        logger.warning(f"Failed to stop policy-controller: {e}")


@pytest.fixture(scope="package")
def controller_api_token(nodes, controller_service) -> str:
    """Mint a bearer token for this test package via SSH."""
    import time

    return mint_api_token(nodes["controller"], f"netsim-scale-{int(time.time())}")


@pytest.fixture(scope="package")
def controller_client(
    nodes, controller_service, controller_api_token
) -> ControllerClient:
    return ControllerClient(nodes["controller"], api_token=controller_api_token)


@pytest.fixture(scope="package")
def docker_ready(
    nodes, apt_updated, engine_image, agent_image
) -> Generator[None, None, None]:
    """
    Ensure Docker is installed on docker-host and both images are loaded.

    Images are saved from the local Docker daemon on the netsim host (trying
    plain docker then sudo docker), copied to the docker-host VM via SCP, and
    loaded there.  Fails with a clear message if either image cannot be saved.
    """
    docker_host = nodes["docker-host"]
    _install_docker(docker_host)

    for img in (engine_image, agent_image):
        _save_and_load_image(docker_host, img)

    logger.info("docker_ready: images loaded into docker-host")
    yield


@pytest.fixture(scope="package")
def scale_containers(
    nodes,
    topology,
    controller_client,
    docker_ready,
    configure_node_interfaces,
    scale_node_count,
    engine_image,
    agent_image,
) -> Generator[List[ContainerPair], None, None]:
    """
    Spin up scale_node_count engine+agent container pairs on docker-host.

    All pairs are started in parallel.  The fixture yields the list of
    ContainerPair objects and tears down all containers on exit.
    """
    docker_host = nodes["docker-host"]
    controller_ip = _get_mgmt_ip(nodes["controller"], topology)

    # Mint a single ZTP bundle for all N agents. The bundle is shown once and
    # gets baked into each agent's config dir at /etc/policy-node-agent/bootstrap.bundle.
    issued = controller_client.create_enrollment_token(
        enrollment_url="https://policy-controller:7776",
        controller_url="https://policy-controller:7777",
        ttl_seconds=3600,
        max_uses=scale_node_count,
        fleet_label=SCALE_FLEET_LABEL,
    )
    logger.info(
        f"Minted ZTP bundle (token_id={issued.token_id}, max_uses={scale_node_count})"
    )

    _ensure_scale_network(docker_host)

    # Clear any leftover state from a previous run
    docker_host.ssh_command(
        f"sudo rm -rf {_SCALE_BASE_DIR} && sudo mkdir -p {_SCALE_BASE_DIR}",
        timeout=15,
    )

    # Limit concurrency: each pair makes several SSH calls on the same
    # docker-host connection; too many concurrent channels destabilises the
    # paramiko transport.  4 workers keeps throughput reasonable while staying
    # well below paramiko's default channel limit.
    _CONTAINER_WORKERS = 4
    logger.info(
        f"Starting {scale_node_count} engine+agent pairs "
        f"({_CONTAINER_WORKERS} at a time)"
    )
    args = [
        (docker_host, idx, controller_ip, issued.bundle, engine_image, agent_image)
        for idx in range(scale_node_count)
    ]
    pairs: List[ContainerPair] = run_parallel_simple(
        _start_one_pair, args, max_workers=_CONTAINER_WORKERS
    )
    logger.info(f"All {scale_node_count} container pairs started")

    yield pairs

    logger.info("Tearing down scale containers")
    _stop_and_remove_containers(docker_host, pairs)
    # Unmount per-engine bpffs mounts before removing directories
    for pair in pairs:
        docker_host.ssh_command(
            f"sudo umount {_SCALE_BASE_DIR}/bpf/node-{pair.index} 2>/dev/null || true",
            timeout=10,
        )
    docker_host.ssh_command(
        f"sudo docker network rm {_DOCKER_BRIDGE} {_DOCKER_DATA_BRIDGE} 2>/dev/null || true",
        timeout=15,
    )
    docker_host.ssh_command(f"sudo rm -rf {_SCALE_BASE_DIR}", timeout=15)


@pytest.fixture(scope="package")
def enrolled_scale_nodes(
    scale_containers, controller_client, scale_node_count
) -> EnrollmentResult:
    """
    Wait for all container pairs to ZTP-auto-enrol, then wait for Active + online.

    Each agent container is started with `--hostname pna-N` so the agent
    reports that hostname during enrollment. We map it back to "scale-node-N"
    labels for test consumption.

    Returns an EnrollmentResult with the label→node_id map and timing metrics.
    """
    t_start = time.monotonic()

    expected_hostnames = [f"pna-{p.index}" for p in scale_containers]
    by_host = _wait_for_active_nodes_by_hostname(controller_client, expected_hostnames)
    t_active = time.monotonic()

    node_map: Dict[str, str] = {
        f"scale-node-{p.index}": by_host[f"pna-{p.index}"] for p in scale_containers
    }

    logger.info("All nodes Active, waiting for online (management gRPC)")
    _wait_for_online_nodes(controller_client, list(node_map.values()))
    t_online = time.monotonic()

    result = EnrollmentResult(
        node_map=node_map,
        seconds_to_active=t_active - t_start,
        seconds_to_online=t_online - t_start,
    )
    logger.info(
        f"Enrollment complete: {len(node_map)} nodes, "
        f"active in {result.seconds_to_active:.1f}s, "
        f"online in {result.seconds_to_online:.1f}s"
    )
    return result


@pytest.fixture(scope="package")
def engine_client_for(
    nodes, scale_containers
) -> "Callable[[int], GraphQLPolicyClient]":
    """
    Return a factory that gives a GraphQLPolicyClient aimed at container index N.

    Queries are run as curl from the docker-host VM targeting the engine's
    bridge IP, so no port-mapping is required.
    """
    docker_host = nodes["docker-host"]
    pair_by_idx = {p.index: p for p in scale_containers}

    def _factory(idx: int) -> GraphQLPolicyClient:
        pair = pair_by_idx[idx]
        url = f"http://{pair.engine_ip}:8080/graphql"
        return GraphQLPolicyClient(docker_host, server_url=url)

    return _factory
