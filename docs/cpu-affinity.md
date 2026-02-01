# CPU Affinity & Performance Tuning

policy-engine steers its control-plane threads, ring-buffer poller, and NIC
IRQs/RPS onto dedicated CPU cores so that XDP and TC dataplane processing is
not competing with API traffic.

## Why this matters

XDP and TC BPF programs run in the context of the CPUs that receive NIC
interrupts (one execution per received packet, per core).  If the GraphQL
server, ring-buffer poller, and Suricata EVE consumer are all free to run on
those same cores they will introduce cache noise and scheduling jitter.
Pinning the control plane to a small number of dedicated cores — and steering
NIC IRQs to the remaining ones — gives the dataplane the lowest possible
latency budget.

## Thread roles

| Thread pool | Default CPUs | Description |
|---|---|---|
| **control** | CPU 0 | Tokio worker threads + actix-web request handlers (GraphQL API, HTTP) |
| **event** | CPU 1 | `std::thread` that polls the XDP/TC BPF ring buffers and dispatches events to WebSocket clients |
| **dataplane** | CPU 2 … N-1 | No server threads run here.  NIC IRQs and RPS are steered to these cores. |

## Auto-default layout

The layout is computed automatically from the number of logical CPUs available
at startup:

| Total CPUs | control | event | dataplane |
|---|---|---|---|
| 1 | [0] | [0] | [0] |
| 2 | [0] | [0] | [1] |
| 3 | [0] | [1] | [2] |
| ≥ 4 | [0] | [1] | [2 … N-1] |

The assignment is logged at `INFO` level on startup:

```
[INFO] CPU affinity: control=[0] event=[1] dataplane=[2, 3, 4, 5, 6, 7] actix_workers=1 disabled=false
```

## Configuration file

Overrides are read from `/etc/policy-engine/config.toml` (optional; missing
file → use defaults).

```toml
[affinity]
# CPU list for Tokio workers and actix-web threads.
# control_cpus = [0]

# CPU for the BPF ring-buffer polling thread.
# event_cpus = [1]

# CPUs that NIC IRQs and software RPS are steered to after attach.
# dataplane_cpus = [2, 3, 4, 5, 6, 7]

# Number of actix-web worker threads (defaults to control_cpus.len()).
# actix_workers = 1

# Set true in containers / VMs where sched_setaffinity is not permitted.
# disabled = false
```

All fields are optional.  Fields that are absent are auto-computed from the
table above.

### Disabling affinity

Set `disabled = true` to skip all CPU pinning.  This is the right choice when
running inside a container with a limited cpuset or on a single-core VM.  The
server starts with one actix worker and does not call `sched_setaffinity` or
write to `/proc/irq`.

## NIC IRQ and RPS steering

When an interface is attached (`attachIngress` or `attachTc` GraphQL
mutation), policy-engine writes the **dataplane CPU list** to two places:

1. **Hardware IRQ affinity** — `/proc/irq/{N}/smp_affinity_list` for every
   IRQ whose description in `/proc/interrupts` contains the interface name.
   This steers hardware interrupt delivery to the dataplane cores.

2. **Software RPS** — `/sys/class/net/{iface}/queues/rx-*/rps_cpus` (hex
   bitmask).  Software Receive Packet Steering redistributes packets across
   CPUs when the NIC does not support hardware RSS.  Writing the dataplane mask
   here ensures soft-IRQ processing also stays on dataplane cores.

Both writes are best-effort: failures are logged but never fatal.  On kernels
or environments where writing to `/proc/irq` requires additional privileges the
server continues normally.

### Restore on detach

Before applying the new affinity values on attach, policy-engine **captures
the current settings** from `/proc/irq/{N}/smp_affinity_list` and
`rps_cpus`.  The original values are held in memory for the lifetime of the
attachment.

When the interface is detached (`detachIngress`, `detachTc`, or `detachAll`),
the saved values are written back, restoring the IRQ and RPS configuration
that existed before policy-engine touched it.

#### Reference counting

Both `attachIngress` and `attachTc` can be used on the same physical
interface.  The snapshot is captured only on the **first** attach and reference
counted:

```
attachIngress(eth0)  →  snapshot captured, ref = 1, affinity applied
attachTc(eth0)       →  ref = 2, affinity re-applied (same values)
detachIngress(eth0)  →  ref = 1, nothing restored yet
detachTc(eth0)       →  ref = 0, original settings restored
```

`detachAll` unconditionally restores every interface in a single call.

## Verification

```bash
# After startup — check logged affinity plan:
journalctl -u policy-engine | grep "CPU affinity"

# After attaching eth0 — confirm IRQ steering:
cat /proc/irq/*/smp_affinity_list   # dataplane CPUs

# After detaching eth0 — confirm restore:
cat /proc/irq/*/smp_affinity_list   # original values

# Confirm reduced thread count vs. num_cpus default:
ps -eLf | grep policy-engine        # ~3–4 threads total

# Confirm actix worker count:
ss -tlnp | grep 8080                # sanity-check server is up
```
