# Policy Engine — Container Deployment

This document covers building and running all three components as containers using the
pre-built Debian packages. Configuration files, certificates, and persistent state are
always provided via bind mounts — nothing environment-specific is baked into the images.

---

## Overview

| Container | Image | Network mode | Linux capabilities |
|---|---|---|---|
| `policy-engine` | `policy-engine:x.y.z` | `host` (mandatory) | `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN` |
| `policy-node-agent` | `policy-node-agent:x.y.z` | `host` | _(none)_ |
| `policy-controller` | `policy-controller:x.y.z` | bridge (standard) | _(none)_ |

`policy-engine` **must** run in the host network namespace. XDP and TC programs attach
to specific host NICs; a container-private network namespace would not see real traffic.
`policy-node-agent` also uses `host` networking so it can reach `policy-engine` on
`localhost:8080`.

`policy-engine-client` and `policy-controller-client` are intended to be installed
directly on the host via their respective `.deb` packages. They do not have container
images.

---

## Prerequisites

### Host requirements

- Linux kernel ≥ 5.8 (provides `CAP_BPF` separately from `CAP_SYS_ADMIN`)
- `bpffs` mounted at `/sys/fs/bpf` (standard on any modern distribution; verify with
  `mount | grep bpf`)
- Docker Engine ≥ 20.10 or Podman ≥ 3.0

### Build requirements

The Debian packages must be built before building the container images. Building the
packages requires:

| Tool | Version | Purpose |
|---|---|---|
| `cargo` / `rustc` | stable | Rust workspace compilation |
| `clang` / `llvm` | ≥ 19 | BPF program compilation |
| `libbpf-dev` | — | BPF header files |
| `linux-headers` | matching host kernel | BPF vmlinux BTF |
| `protobuf-compiler` | — | gRPC code generation |
| `nodejs` / `npm` | — | Web UI assets |
| `dpkg-dev` / `debhelper` | ≥ 13 | Debian package build |

Build the packages (from the `policy-engine/` workspace root):

```bash
# Base engine
dpkg-buildpackage -us -uc -b

# With Suricata IPS/IDS
DEB_BUILD_PROFILES=pkg.policy-engine.suricata dpkg-buildpackage -us -uc -b

# With IPFIX flow export
DEB_BUILD_PROFILES=pkg.policy-engine.ipfix dpkg-buildpackage -us -uc -b

# With both
DEB_BUILD_PROFILES="pkg.policy-engine.suricata pkg.policy-engine.ipfix" dpkg-buildpackage -us -uc -b
```

The resulting `.deb` files are written to the repository root (parent of `policy-engine/`).

---

## Building the container images

All Dockerfiles live under `docker/` inside the `policy-engine/` repository. The build
context must be the parent directory (where `dpkg-buildpackage` writes the `.deb` files),
so all commands below are run from within `policy-engine/`.

### policy-engine

```bash
# Base variant
docker build \
  --build-arg DEB=policy-engine_0.1.0_amd64.deb \
  -f docker/policy-engine/Dockerfile \
  -t policy-engine:0.1.0 ..

# Suricata (IPS/IDS) variant
docker build \
  --build-arg DEB=policy-engine-ips_0.1.0_amd64.deb \
  -f docker/policy-engine/Dockerfile \
  -t policy-engine:0.1.0-ips ..

# IPFIX variant
docker build \
  --build-arg DEB=policy-engine-ipfix_0.1.0_amd64.deb \
  -f docker/policy-engine/Dockerfile \
  -t policy-engine:0.1.0-ipfix ..
```

### policy-node-agent

```bash
docker build \
  --build-arg DEB=policy-node-agent_0.1.0_amd64.deb \
  -f docker/policy-node-agent/Dockerfile \
  -t policy-node-agent:0.1.0 ..
```

### policy-controller

```bash
docker build \
  --build-arg DEB=policy-controller_0.1.0_amd64.deb \
  -f docker/policy-controller/Dockerfile \
  -t policy-controller:0.1.0 ..
```

---

## Configuration

No configuration is bundled in any image. The expected host paths for bind mounts are
the same paths used by the Debian package installations.

### policy-engine — `/etc/policy-engine/config.toml`

```toml
[server]
host = "0.0.0.0"
port = 8080
```

See the main README and `docs/tls.md` for TLS and auth options. The API token can also
be injected via the `POLICY_ENGINE_API_TOKEN` environment variable instead of the config
file, which is preferable in container deployments.

### policy-node-agent — `/etc/policy-node-agent/config.toml`

```toml
engine_url       = "http://127.0.0.1:8080/graphql"
enrollment_url   = "https://controller.example.com:7776"
controller_url   = "https://controller.example.com:7777"
```

The identity key and mTLS certificates are generated automatically on first enrollment
and written back to `/etc/policy-node-agent/`. Mount this directory read-write during
initial enrollment, then switch to read-only once certificates are issued.

### policy-controller — `/etc/policy-controller/config.toml`

```toml
[server]
http_bind = "0.0.0.0:8443"

[grpc]
enrollment_bind = "0.0.0.0:7776"
management_bind = "0.0.0.0:7777"
```

The CA key and certificate are generated automatically on first run and written to
`/etc/policy-controller/`. Mount this directory read-write so the CA files persist.

---

## Running with Docker Compose

Two Compose files are provided under `docker/`. All commands are run from within
`policy-engine/`.

### Node-side (policy-engine + policy-node-agent)

Run on every host that enforces network policy:

```bash
docker compose -f docker/docker-compose.node.yml up -d
```

To pass an API token without putting it in a config file:

```bash
POLICY_ENGINE_API_TOKEN=<token> docker compose -f docker/docker-compose.node.yml up -d
```

### Controller

Run once on the central management host:

```bash
docker compose -f docker/docker-compose.controller.yml up -d
```

---

## Running with plain Docker

### policy-engine

```bash
docker run -d \
  --name policy-engine \
  --network host \
  --cap-add CAP_BPF \
  --cap-add CAP_NET_ADMIN \
  --cap-add CAP_SYS_ADMIN \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /etc/policy-engine:/etc/policy-engine:ro \
  -v /var/lib/policy-engine:/var/lib/policy-engine \
  -v /var/log/policy-engine:/var/log/policy-engine \
  -e RUST_LOG=info \
  --restart unless-stopped \
  policy-engine:0.1.0
```

### policy-node-agent

```bash
docker run -d \
  --name policy-node-agent \
  --network host \
  -v /etc/policy-node-agent:/etc/policy-node-agent:ro \
  -e RUST_LOG=info \
  --restart unless-stopped \
  policy-node-agent:0.1.0
```

### policy-controller

```bash
docker run -d \
  --name policy-controller \
  -p 8443:8443 \
  -p 7776:7776 \
  -p 7777:7777 \
  -v /etc/policy-controller:/etc/policy-controller \
  -v /var/lib/policy-controller:/var/lib/policy-controller \
  -e RUST_LOG=info \
  --restart unless-stopped \
  policy-controller:0.1.0
```

---

## Client tools on the host

The CLI clients are thin binaries with no BPF dependencies. Install them directly on
any host — no container required.

```bash
# Query a policy-engine running in a container on the same host
dpkg -i policy-engine-client_0.1.0_amd64.deb
policy-client status

# Query a remote policy-engine
policy-client --server http://10.0.0.5:8080/graphql status

# Manage the fleet controller
dpkg -i policy-controller-client_0.1.0_amd64.deb
policy-controller-client nodes list
```

---

## BPF map persistence across container restarts

BPF maps are pinned to `/sys/fs/bpf/policy_engine/` on the host. Because this path is
bind-mounted into the container, maps persist across container restarts and survive
image upgrades. When `policy-engine` starts it detects existing pinned maps and reuses
them, which means the BPF dataplane continues enforcing policy with zero gap during a
container replacement.

On clean node decommission, detach the BPF programs before stopping the container:

```bash
policy-client detach ingress --interface eth0
policy-client detach egress  --interface eth0
docker stop policy-engine
```

---

## Troubleshooting

**`dpkg: error: requested operation requires superuser privilege`**
The container needs `CAP_SYS_ADMIN` in addition to `CAP_BPF` on kernels older than 5.8.
Both are included in the compose file and the `docker run` examples above.

**`libbpf: failed to pin map`**
`/sys/fs/bpf` is not mounted on the host. Check with `mount | grep bpf`. On systemd
hosts run `systemctl start sys-fs-bpf.mount`.

**`policy-node-agent: connection refused on localhost:8080`**
The agent container started before the engine was ready. The compose file has
`depends_on: policy-engine` but that only waits for the container to start, not for
the HTTP server to be up. Restart the agent container after the engine is fully
initialised, or add a healthcheck to `docker-compose.node.yml`.
