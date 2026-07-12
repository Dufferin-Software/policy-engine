# Datapath benchmarking

There are two tools, and they answer different questions. Pick deliberately.

| | `policy-progbench` | `xdp-bench.py` |
|---|---|---|
| **question** | did this patch make the *program* cheaper? | what does the *appliance* do? |
| **method** | `BPF_PROG_TEST_RUN` — the kernel replays one synthetic packet through `xdp_policy_main` in a tight loop | pktgen over a real wire into a real NIC |
| **needs** | root on one box. No NIC, no generator, no wire. | a TX box, a DUT, and a link fast enough to saturate the DUT |
| **metric** | cycles/packet | cycles/packet, pps, cache misses |
| **resolves** | ~1% changes | whatever the rig's noise floor allows |
| **blind to** | cache/LRU pressure across many flows | small changes — the program is a minority of measured cycles |

**Start with `policy-progbench`.** It is the one that can actually see a few
percent, it needs no hardware, and every optimisation to the datapath's
*instructions* shows up in it. Reach for the packet rig when you need to know
what the box in the field does, or when the change is about cache behaviour
under many flows — which `progbench` cannot see (it replays one packet, so every
map stays hot in L1).

Note the rig has its own ceiling: `protectli ↔ fws-2277` is 1GbE, whose 64-byte
line rate is 1.488 Mpps. No DUT will plateau below that, so `xdp-bench.py`
cannot currently prove saturation on that link and will say so rather than
pretend.

---

# `policy-progbench` — per-packet program cost

```bash
sudo policy-progbench --profile policy -o old.json --label "baseline"
# ... make the change, cargo build ...
sudo policy-progbench --profile policy -o new.json --label "SoA dst_lpm_value"
policy-progbench --compare old.json new.json
```

## Read cycles/pkt, never ns/pkt

The tool reports both; only cycles means anything across two runs. The core
clock moves with thermal and power state — this dev laptop ranges 0.8–4.5 GHz —
and `cargo build` sits between your A run and your B run, heating the CPU. So
**ns is biased against whichever build you measured second.**

Measured on the same unchanged program, cold vs. after a 45s CPU load:

```
                  cold (A)      hot (B)      delta
  cycles/pkt         619.7        623.0      +0.5%   noise
  ns/pkt             139.0        144.0      +3.6%   <-- pure thermal artifact
```

A 3.6% "regression" that is nothing but a warm CPU is bigger than most of the
wins we are chasing. `instructions/pkt` is steadier still (2137.3 vs 2137.4 for
the same program) and is the sharpest signal for a pure instruction-count change.

## Contention: `--threads` and `--flows`

**A single thread cannot see the things most worth fixing on the fast path.** A
shared LRU-list lock, or a cache line bouncing between cores, costs nothing at
all until two CPUs want it at once. Run `--threads 1` and `--threads N` and
compare: a contention fix leaves the 1-thread number alone and drops the
N-thread one.

The two flow modes stress different structures, and measuring the wrong one will
make a real fix look like nothing:

| | what contends | the fix it can see |
|---|---|---|
| `--flows shared` | every thread drives the **same** 5-tuple, so all CPUs hit one verdict-cache entry and its counters | the atomics on the verdict entry (cache-line ping-pong, elephant flows) |
| `--flows distinct` | every thread drives **its own** 5-tuple, so the CPUs contend on the map's LRU list rather than one entry | `BPF_F_NO_COMMON_LRU` |

`--compare` refuses to diff two runs with different `--threads`/`--flows`:
contention *is* the thing being measured, so a delta across settings says
nothing about the code.

**One thread per physical core.** The tool refuses a CPU range that puts two
threads on SMT siblings — they share execution units, so cycles/pkt roughly
doubles for reasons that have nothing to do with our maps, and it looks exactly
like the contention you are hunting. On this dev box CPU 0's sibling is CPU 8,
so `--threads 8` is fine and `--threads 9` is not.

## The two profiles

The datapath **caches its own verdicts**: the first packet of a flow walks the
LPM trie, then `xdp_policy_write_verdict` seeds `flow_verdict_cache` so every
later packet on that 5-tuple short-circuits. The profiles are the two sides of
that.

**`--profile verdict`** — steady state, and the overwhelming majority of packets
in the field: parse, stats, one LRU hash lookup. Use for anything touching
`flow_verdict_cache`, `global_stats`, or parsing.

**`--profile policy`** — the two-level LPM walk (src group → dst prefix → L4
rule), which in production happens once per flow. The only profile that
exercises `dst_lpm_value` and `l4_rule`. There is no runtime switch to disable
the verdict cache, so the bench forces the walk to repeat by giving the matching
rule a rate-limited `LOG` action — the datapath marks `LOG` flows non-cacheable.
Absolute numbers from this profile are therefore "LPM walk + LOG bookkeeping";
the LOG cost is identical in both halves of an A/B, so it cannot manufacture or
hide a delta.

## Sampling

`--reloads` is the unit of repetition that matters, not `--rounds`. Rounds
within one load of the BPF object share its maps and JIT placement, so they
agree to well under 1% and *flatter* the real uncertainty. The reported
min/max/spread are across reloads.

## It checks it measured what it claims

Every run reads back the datapath's own stats counters and refuses to let you
believe a number that came from the wrong code path — a rule that silently
failed to match, or a stale cached verdict short-circuiting the LPM walk, would
otherwise look like a spectacular improvement. It also records the program's
tag, so comparing a build against itself (forgot to rebuild) is caught rather
than reported as noise.

`--profile policy` refuses to run if `policy-engine` has XDP attached: the bench
installs its own rules into the shared pinned maps and would corrupt a live
policy.

---

# `xdp-bench.py` — the packet rig

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
