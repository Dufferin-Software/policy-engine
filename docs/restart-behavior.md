# Policy Engine — Restart & Stop Behavior

This document describes what happens to the policy-engine server process and the BPF data plane
when the daemon is stopped, crashes, or restarts, and how the stop behavior setting controls
cleanup on shutdown.

---

## Key principle: enforcement is decoupled from the daemon

The XDP and TC eBPF programs live in the kernel, not in the userspace daemon. Once a program is
attached to an interface it continues executing — matching and enforcing rules — regardless of
whether the policy-engine daemon process is running.

What happens to enforcement when the daemon stops depends on the configured stop behavior:

- **`clear-state` (default):** the daemon detaches all programs and removes pinned maps on a clean
  shutdown. Enforcement stops until the daemon restarts and restores state from `state.json`.
- **`preserve-state`:** no cleanup runs on shutdown. Programs remain attached and enforcement
  continues uninterrupted while the daemon is not running.
- **Crash (`kill -9`):** the graceful shutdown path never runs, so programs always remain attached
  regardless of the configured mode.

---

## Stop behavior modes

The daemon supports two configurable stop behavior modes, controlled via the GraphQL API and
persisted in `state.json`:

| Mode | On shutdown | Use case |
|------|-------------|----------|
| `clear-state` **(default)** | Detaches all XDP/TC programs and removes all pinned maps | Clean slate; next start always restores from `state.json` |
| `preserve-state` | Leaves programs attached and maps in the kernel | Zero-gap enforcement across daemon restarts |

The mode is set via the local GraphQL mutation (on the engine directly) or pushed from the
controller and can be changed at runtime without restarting:

```graphql
mutation {
  configureStopBehavior(input: { stopBehavior: "preserve-state" }) {
    success
  }
}
```

The controller also exposes this per-node via the `setNodeStopBehavior` GraphQL mutation and the
node detail page in the controller web UI. When the controller sets the behavior it is
immediately pushed to the agent (if connected) via a `DeltaConfigPush` and persisted in the
controller database. The agent applies it to the local engine; it is also included in full-restore
pushes sent when a node reconnects.

### `clear-state` (default)

After the actix-web HTTP server has fully shut down, `perform_stop_cleanup()` is called, which
invokes `BpfManager::cleanup_pinned_state()`:

1. Detaches XDP programs from every interface listed in the metadata files.
2. Destroys TC clsact qdiscs on every interface listed in the metadata files.
3. Removes all pin files under `/sys/fs/bpf/policy_engine/`.
4. Removes runtime metadata files under `/var/run/policy_engine/`.

`state.json` is **not** removed. On next start the daemon calls `restore_from_store()` to
re-attach interfaces and re-apply rules from disk, exactly as it does after a reboot or a BPF
version change.

### `preserve-state`

No BPF teardown occurs on shutdown. Programs remain attached and maps remain in the kernel. Use
this when you want zero enforcement gap across daemon restarts (e.g. a daemon upgrade with no BPF
binary change).

---

## What happens when the daemon stops

### BPF programs (XDP / TC)

With `preserve-state`, programs are **not detached** on shutdown. The `BpfManager::Drop`
implementation only emits a debug log line:

```rust
// src/server/bpf_manager.rs
impl Drop for BpfManager {
    fn drop(&mut self) {
        if self.xdp_skel.is_some() || self.tc_skel.is_some() {
            debug!("BpfManager dropped, pinned BPF programs remain attached");
        }
    }
}
```

With `clear-state`, cleanup runs before `Drop` is reached (initiated by `http.rs` after the
server finishes), so by the time `Drop` fires all programs are already detached.

Signal handling (`SIGTERM` / `SIGINT`) triggers a graceful actix-web shutdown which then runs the
stop cleanup path before the process exits.

### BPF maps

With `preserve-state`: all maps remain pinned to `/sys/fs/bpf/policy_engine/` and survive the
daemon exiting. Rule data, default actions, and flow verdict caches stay in the kernel unchanged.

With `clear-state`: all pin files are removed as part of `cleanup_pinned_state()`.

### Net effect

| What happened | Stop behavior | XDP program | TC program | Rule data | Traffic enforced? |
|---|---|---|---|---|---|
| `systemctl stop` | `preserve-state` | Still attached | Still attached | Still in kernel | **Yes** |
| `systemctl stop` | `clear-state` | **Detached** | **Detached** | **Removed** | No |
| `kill -9` (crash) | either | Still attached | Still attached | Still in kernel | **Yes** |

Note: a crash (`kill -9`) bypasses the graceful shutdown path entirely, so cleanup never runs
regardless of the configured mode.

---

## What happens on daemon restart

On startup `BpfManager::new()` calls `check_version_and_cleanup_if_changed()` which:

1. Computes a FNV-1a hash of the embedded XDP + TC skeleton ELF bytes.
2. Reads the stored hash from `/var/run/policy_engine/.bpf_version`.
3. Decides whether to reuse or rebuild:

### Case 1 — same BPF binary, `preserve-state` (normal restart, no gap)

Hash matches → `pins_were_reused() == true`.

- Existing pinned maps are reused as-is. The kernel already holds the correct rule state.
- In-memory attachment metadata is restored by scanning `/var/run/policy_engine/xdp_mode_*` and
  `tc_egress_*` files.
- `restore_from_store()` is **not** called; disk state is not touched.
- Enforcement continues without interruption; no rules need to be re-applied.

### Case 2 — same BPF binary, `clear-state` (or post-crash after `clear-state` stop)

After a clean `clear-state` stop, no pins exist on disk. The daemon loads fresh programs, pins
them, and calls `restore_from_store()` to replay attachments and rules from `state.json`. There
is a brief gap between process exit and when `restore_from_store()` completes on the next start.

### Case 3 — different BPF binary (BPF struct layout / program change)

Hash differs → `cleanup_pinned_state()` is called regardless of stop behavior setting, which:

1. Detaches XDP programs from every interface listed in the metadata files.
2. Destroys TC clsact qdiscs on every interface listed in the metadata files.
3. Removes all pin files under `/sys/fs/bpf/policy_engine/`.
4. Removes runtime metadata files under `/var/run/policy_engine/`.

After cleanup the daemon loads the new BPF programs, pins fresh maps, and calls
`restore_from_store()` to replay attachments and rules from `state.json`.

There is a brief window between cleanup and restore completion where no programs are attached and
no rules are enforced. This is unavoidable when the BPF ABI changes.

### Case 4 — reboot

The BPF filesystem (`/sys/fs/bpf/`) is a `tmpfs` mount. It is empty after a reboot. With no
pins present `check_version_and_cleanup_if_changed()` returns `false` immediately (no cleanup
needed). The daemon loads fresh programs, pins them, and calls `restore_from_store()` to
re-attach interfaces and re-apply all rules from `state.json`.

---

## Startup decision flowchart

```
daemon starts
    │
    ▼
/sys/fs/bpf/policy_engine/ exists?
    │ No  → load fresh BPF, pin, restore_from_store()
    ▼ Yes
hash(embedded ELF) == stored .bpf_version?
    │ No  → cleanup_pinned_state()
    │         (detach programs, remove pins, remove metadata)
    │       load fresh BPF, pin, restore_from_store()
    ▼ Yes
reuse pinned maps + restore in-memory attachment metadata
(no restore_from_store — kernel already has the rules)
```

---

## Explicit detach (stopping enforcement)

Programs can also be detached explicitly while the daemon is running:

```
policy-client detach ingress --interface eth0   # removes XDP program
policy-client detach egress  --interface eth0   # removes TC clsact qdisc
```

These call `bpf_xdp_detach()` and `bpf_tc_hook_destroy()` respectively and remove the
corresponding metadata files.

---

## Controller integration

The controller stores the desired stop behavior per node in the `nodes.stop_behavior` column
(SQLite). When a node connects the behavior is included in the full-restore `DeltaConfigPush`. It
can also be changed at runtime via the `setNodeStopBehavior` mutation which drives the
`SetStopBehavior` pending op — this pushes a minimal `DeltaConfigPush` (containing only the
`stop_behavior` field) to the connected agent immediately, and commits the value to the database
once the agent confirms. The controller web UI exposes this as a two-button toggle on the node
detail page.

The agent reads the `stop_behavior` field from each incoming `DeltaConfigPush` and, if non-empty,
calls `configure_stop_behavior` on the local engine's GraphQL API. The current value is also
included in `StateSnapshot` messages sent from agent to controller so the controller can
display it.

---

## Filesystem paths summary

| Path | Contents | Survives reboot? |
|------|----------|:---:|
| `/sys/fs/bpf/policy_engine/` | Pinned programs, maps, link objects | No (tmpfs) |
| `/sys/fs/bpf/policy_engine/groups_v{4,6}_{in,eg}/` | Inner destination LPM tries | No (tmpfs) |
| `/var/run/policy_engine/` | Attachment metadata, `.bpf_version` | No (tmpfs) |
| `/var/run/policy_engine/xdp_mode_<ifname>` | XDP mode for interface | No |
| `/var/run/policy_engine/tc_egress_<ifname>` | TC attachment record | No |
| `/var/lib/policy-engine/state.json` | Persisted rule + attachment state (incl. stop behavior) | **Yes** |

---

## Scenario reference

| Scenario | Stop behavior | Programs after event | Maps after event | Rules enforced? | Restore needed? |
|---|---|---|---|:---:|:---:|
| Daemon running | — | Attached | In kernel | Yes | — |
| `systemctl stop` | `clear-state` | **Detached** | **Removed** | No | Yes (on next start) |
| `systemctl stop` | `preserve-state` | Still attached | Still in kernel | **Yes** | No |
| `kill -9` crash | either | Still attached | Still in kernel | **Yes** | No |
| Restart, same BPF, `preserve-state` | preserve-state | Reattached (metadata restored) | Reused from pins | Yes | No |
| Restart, same BPF, `clear-state` | clear-state | Fresh attach | Fresh (restored from disk) | Yes (after restore) | Yes |
| Restart, new BPF | either | Detached then reattached fresh | Fresh (restored from disk) | Yes (after restore) | Yes |
| System reboot | either | Detached (tmpfs cleared) | Gone (tmpfs cleared) | No (until started) | Yes |
| `detach` command | — | Explicitly detached | Still pinned | No | N/A |
