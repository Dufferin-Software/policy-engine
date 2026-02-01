# Node Identity

This document describes what a "node identity" is in the fleet, how it is established and persisted on traditional VM / bare-metal hosts, and how the same model applies — with a few extra wrinkles — to containerised deployments.

For the wire-level enrollment and mTLS flow see [enrollment-crypto.md](enrollment-crypto.md). For TPM specifics see [tpm.md](tpm.md). For container packaging and bind mounts see [containers.md](containers.md).

---

## What Is a Node Identity?

Each `policy-node-agent` instance has a **stable cryptographic identity** consisting of:

| Element | Definition |
|---|---|
| Identity keypair | ECDSA P-256, generated on first start |
| Public key DER | `SubjectPublicKeyInfo` encoding of the identity public key |
| **Node ID** | `hex(SHA-256(public_key_der))` |

The Node ID is the **primary identifier** used everywhere in the system: it is the database primary key in the controller's node registry, the `CommonName` on the issued mTLS client certificate, the subject of every audit record, and the value the agent sends in its `AgentHello` on each management connection.

Two properties are deliberate:

1. **Derived from the key, not the host.** Hostname, IP address, MAC address, and DMI UUID are never used as identity. They are recorded as informational metadata only. A node can be renamed, re-IP'd, or moved between racks without changing its identity.
2. **Stable for the life of the key.** As long as the identity private key survives, the Node ID survives — across reboots, agent restarts, and package upgrades. Conversely, losing the key (or generating a new one) creates a *new* node from the controller's point of view; the old node must be re-approved or decommissioned.

The identity key is used **only** to prove possession during enrollment. The credential used on the management mTLS channel is a separate, controller-issued key (see [enrollment-crypto.md](enrollment-crypto.md) Phase 5). This two-key split means the high-value identity key can be hardware-bound while the mTLS key is rotated cheaply on cert expiry.

**Source:** `fleet/agent/src/identity/mod.rs:16-86`

---

## Identity on VM and Bare-Metal Hosts

On a host where `policy-node-agent` is installed from the `.deb` package, identity selection happens once at first start and is then persistent.

### Backend selection (runtime, not build-time)

The agent picks a backend in this order:

1. **TPM 2.0** — if `/dev/tpmrm0` or `/dev/tpm0` exists and the agent can talk to it, the identity key is generated *inside* the TPM and persisted at owner-hierarchy handle `0x81000001`. The private key never leaves hardware. See [tpm.md](tpm.md).
2. **File** — otherwise the agent generates an ECDSA P-256 key with `OsRng` and writes it to `/var/lib/policy-node-agent/identity.key` as PKCS#8 PEM, mode `0600`.

There is no build flag or config knob — a host that has a usable TPM transparently upgrades to hardware-backed identity, and one that doesn't keeps a software key on disk. Which backend is in use on any given node is visible via the `tpm_backed` label on the `fleet_node_info` Prometheus metric.

### Lifecycle

| Event | Effect on identity |
|---|---|
| First boot | Key generated, Node ID derived, agent enters enrollment |
| Reboot | Same key loaded, same Node ID, no re-enrollment needed |
| Agent package upgrade | Key files preserved (`/var/lib/policy-node-agent/` is not removed) |
| Package purge (`dpkg --purge`) | File-backed key is deleted; TPM-resident key survives in NV |
| Disk reimage | File-backed key lost → new identity; TPM-resident key survives if the same TPM is reused |
| VM clone from a snapshot | **Both backends produce a collision risk** — see below |
| Hardware replacement | Identity is lost (new TPM or empty disk) → must re-enrol |

### The VM cloning hazard

Cloning a VM image after enrolment is the one operation that breaks the identity model:

- **File backend:** the cloned image carries `/var/lib/policy-node-agent/identity.key`, so both VMs come up claiming the same Node ID. The controller will reject the second connection at the application layer (one node, one active mTLS cert), but operationally this is a footgun.
- **TPM backend:** a hypervisor-virtualised TPM (e.g. `swtpm`) is part of the VM image and clones with it, producing the same Node ID. A physically distinct TPM cannot reproduce the key, so cloning baremetal-attested identities is safe by construction.

Recommended practice: build VM images *without* an enrolled identity, and let enrolment happen on first boot of each instance. To force re-enrolment on a cloned image, delete `/var/lib/policy-node-agent/identity.key` (file backend) or `tpm2_evictcontrol -c 0x81000001` (TPM backend) before sealing the image.

### Files on a VM/bare-metal node

| Path | Mode | Backend | Purpose |
|---|---|---|---|
| `/var/lib/policy-node-agent/identity.key` | 0600 | File only | Long-term identity private key |
| TPM NV handle `0x81000001` | — | TPM only | Long-term identity private key |
| `/etc/policy-node-agent/controller-ca.crt` | 0644 | both | Pre-distributed CA trust anchor |
| `/var/lib/policy-node-agent/controller-client.key` | 0600 | both | mTLS client private key (issued by controller) |
| `/var/lib/policy-node-agent/controller-client.crt` | 0644 | both | mTLS client certificate (90-day TTL) |

---

## Identity in Containers

The container build does not change the identity model — the same agent binary uses the same backend-selection logic. What changes is the *substrate* the identity is anchored to, and that substrate is now a bind-mounted host directory rather than the container's own filesystem.

### Default: file-backed, persisted via bind mount

The reference `docker-compose.node.yml` and the `docker run` examples in [containers.md](containers.md) bind-mount the host directory `/etc/policy-node-agent/` into the container. The identity file lives under `/var/lib/policy-node-agent/` in the standard package layout; container deployments should mount that path through as well (read-write at least until enrolment completes, read-only afterwards).

Implications:

- Identity is bound to the **host directory**, not to the container image or container instance.
- Restarting, replacing, or upgrading the container does **not** change the Node ID, because the identity key persists on the host.
- Two containers on the same host pointed at the same mount **share an identity** — this is correct for replace-in-place upgrades and wrong for "run two agents side by side", which is not supported regardless.
- Moving the container to a different host without copying `/var/lib/policy-node-agent/` produces a new identity (and requires re-enrolment), exactly as it would for a `.deb` install.

### TPM-backed identity in containers

A TPM is a host-level device. To use TPM-backed identity from inside a container you must:

1. Bind-mount the device node: `--device /dev/tpmrm0` (or `/dev/tpm0`).
2. Ensure the in-container user can open it. On Debian/Ubuntu hosts `/dev/tpmrm0` is typically owned by group `tss` (GID varies). Either run the container as that GID (`--group-add`) or adjust udev permissions.

If the device is not passed through, the agent silently falls through to the file backend on first start — which is fine, but means the identity is no longer hardware-bound.

The TPM NV handle `0x81000001` is owned by the host's TPM and is shared by **every** container that mounts the device on that host. Running two agent containers against the same TPM on the same host is not supported and will produce conflicting Node IDs.

### Ephemeral-filesystem deployments (Kubernetes, etc.)

If the container's `/var/lib/policy-node-agent/` is *not* persisted (e.g. a stateless pod with no PVC) then:

- Without a TPM: every restart generates a fresh identity key, which produces a fresh Node ID, which requires a fresh enrolment + operator approval. This is rarely what you want.
- With a TPM passed through (DaemonSet pinned to a node): the TPM provides stability, and the on-disk state is effectively a cache. Restarts re-derive the same Node ID from the persistent TPM handle.

The pragmatic deployment shapes are therefore:

| Shape | Identity stability | Notes |
|---|---|---|
| `docker run` + host bind mount of `/var/lib/policy-node-agent` | Stable | Same as a `.deb` install |
| K8s DaemonSet + `hostPath` volume for `/var/lib/policy-node-agent` | Stable | One agent per host, persistent identity |
| K8s DaemonSet + TPM device + ephemeral volume | Stable | TPM is the source of truth, disk is a cache |
| Ephemeral container with no persistence and no TPM | **Unstable — avoid** | Every restart is a new node |

### What the threat model gains and loses inside a container

A container's filesystem isolation is not a security boundary for the identity key — the key file is bind-mounted from the host and is readable by anyone with host root. This matches the baremetal case. What containers add is:

- **A confused-deputy risk if the mount is shared too widely.** Bind-mounting `/var/lib/policy-node-agent` into an unrelated container effectively hands that container the node's identity. Treat the path as a credential.
- **No new defence against image theft.** Pulling the `policy-node-agent` image does not give an attacker any identity material — the image is generic; identity lives on the host.

TPM-backed identity in a container retains its security property: even with full root inside the container, the private key cannot be exfiltrated, because it never exists outside the TPM.

---

## Operational Quick Reference

| Goal | Action |
|---|---|
| Read a node's current Node ID | `journalctl -u policy-node-agent | grep 'node_id'`, or `policy-controller-client nodes list` from the controller |
| Force a node to re-enrol with a new identity | Stop agent → delete `/var/lib/policy-node-agent/identity.key` *and* (if TPM) `tpm2_evictcontrol -c 0x81000001` → start agent |
| Preserve identity across a host reinstall | Back up `/var/lib/policy-node-agent/` before wiping. TPM-resident identity also requires the same physical TPM. |
| Check whether the identity is hardware-backed | `fleet_node_info{tpm_backed="true"}` in Prometheus, or look for `Using TPM-backed node identity` in the agent log |
| Build a golden VM/container image safely | Do **not** start the agent during image build. Let enrolment run on first boot of each instance. |

---

## Source Map

| Concern | File |
|---|---|
| Backend selection logic | `fleet/agent/src/identity/mod.rs` (`select_identity`) |
| Node ID derivation | `fleet/agent/src/identity/mod.rs` (`derive_node_id`) |
| File backend | `fleet/agent/src/identity/file.rs` |
| TPM backend | `fleet/agent/src/identity/tpm.rs` |
| Enrollment use of identity | `fleet/agent/src/enrollment/mod.rs` |
| Controller-side validation | `fleet/controller/src/node_registry/mod.rs`, `fleet/controller/src/grpc/management.rs` |
