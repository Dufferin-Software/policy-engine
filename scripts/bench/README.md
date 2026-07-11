# Datapath benchmarking

`xdp-bench.py` measures the XDP policy engine's **per-packet cost** on real
hardware, and diffs two builds.

Run it from your dev box. It logs in to the traffic generator (TX) and the
device under test (RX) over SSH:

```
dev box  ──ssh──>  TX node   (pktgen)
   │                  │ packets
   └─────ssh──────>  RX node  (policy-engine + perf)
```

| node | needs |
|---|---|
| dev box | `python3`, `ssh` |
| TX | passwordless sudo, `pktgen` module |
| RX | passwordless sudo, `perf`, `ethtool` |

## Measure

```bash
./xdp-bench.py --tx fw4b --tx-iface enp2s0 \
               --rx fws-2277 --rx-iface enp2s0 \
               --profile hit --label "baseline" -o old.json
```

Rebuild and redeploy the engine on RX, then run again to `new.json` and:

```bash
./xdp-bench.py --compare old.json new.json
```

## The two profiles measure different code

Pick the one that matches the change you made. Measuring the wrong profile is
the easiest way to conclude nothing happened.

**`--profile hit`** — a bounded set of 5-tuples (`--flows`, default 64512), sent
repeatedly. After warm-up nearly every packet hits the flow verdict cache, so
this is the **fast path**: parse, per-CPU stats, one hash lookup. This is what
steady-state production traffic looks like, and it is the profile to use for
anything touching `flow_verdict_cache`, `global_stats`, or packet parsing.

**`--profile miss`** — every packet is a fresh 5-tuple (randomised source address
*and* port), so nothing ever hits the verdict cache and every packet walks the
two-level LPM trie. This is the **slow path**, and it is the only profile that
exercises the rule-matching structures — `dst_lpm_value`, `l4_rule`, the
src/dst LPM tries.

Under `hit`, roughly 1% of packets take the miss path, so an LPM change will
look like it did nothing. Under `miss`, the verdict cache is never read, so a
cache-layout change will look like it did nothing. Both would be wrong.

## Reading the output

Everything is **per packet**, divided by the RX NIC's hardware receive counter.
Raw perf counters are meaningless on their own — a run that received 7% fewer
packets shows 7% fewer cycles and looks like a win.

Each measurement is repeated (`--repeats`, default 5) and reported as a median
with spread. `--compare` marks a delta as **`noise`** when it is within the
combined run-to-run spread of the two runs: the effects worth chasing here are
often only a few percent, and a single run cannot tell those apart from jitter.

`pps` is reported as **`load`**, not a verdict. It is the *offered* load, and
only says something about the DUT if the DUT is the bottleneck. `clone_skb 0` —
which is required, or pktgen reuses one skb and every packet carries the same
5-tuple, silently collapsing either profile to a single flow — makes the
generator allocate an skb per packet, so TX is often the limit. Compare rx `pps`
against `tx_pps` in the JSON: if they match, the generator was the ceiling and
the per-packet columns are the real answer.

## Portability

Nothing is tuned to a particular CPU. Perf event names vary by architecture
(`LLC-load-misses` does not exist everywhere), so the usable set is probed on RX
and unsupported events are dropped rather than failing the run.

The RX platform's facts — CPU, cache sizes (**including whether an L3 exists at
all**), NIC driver, kernel, BPF JIT and clocksource settings — are recorded into
the JSON and printed. That matters: a box with no L3 has a last-level cache of a
couple of MB, so a map that fits comfortably on a Xeon may not fit at all, and a
result from one machine cannot be read as a result from another without knowing
that. `--compare` warns if the two runs came from different CPUs.

## Before trusting any run

- `bpf_jit_enable` must be `1` and **`bpf_jit_harden` must be `0`** — constant
  blinding makes the JIT'd program several times slower. Both are printed.
- `clocksource` should be `tsc`. The datapath takes two `bpf_ktime_get_ns()`
  readings per packet; on `hpet` those dominate everything else.
- Install a **drop rule** for the test traffic on RX, so packets terminate in
  XDP instead of going up the stack into a socket. Otherwise you are largely
  measuring the network stack. The tell: `perf report` on RX should show no
  `udp_recvmsg` / `rep_movs_alternative`.
