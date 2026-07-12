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

## Running it

It is a dev tool, not part of the shipped packages, so build it from the repo:

```bash
cargo build --release --bin policy-progbench
```

Needs **root** (it loads BPF and opens perf counters) and a kernel with
`BPF_PROG_TEST_RUN` — anything current. It creates *nothing* on the system: the
kernel insists `ctx->ingress_ifindex` names a real netdev, so it uses `lo`, and
no packet ever leaves the box.

```bash
# the fast path — what a steady-state packet costs
sudo ./target/release/policy-progbench --profile verdict
```

```
  cpu       11th Gen Intel(R) Core(TM) i7-11850H (pinned to CPU 0)
  datapath  xdp_policy_main tag=2842fc913203f590
  threads   1 (CPUs 0..0), shared flow(s)
  sampling  5 reloads x 5 rounds x 2000000 invocations/thread
  verdict   XDP_PASS

  metric                   median        min        max   spread
  -------------------- ---------- ---------- ---------- --------
  cycles/pkt                328.3      322.5      340.5     2.8%
  instructions/pkt        1287.3
  ipc                        3.92
  ns/pkt                     71.0                           1.4%

  path      confirmed: 5100001 rx, 5100001 policy match(es), 5100000 verdict-cache hit(s)
```

That `path confirmed` line is not decoration. The tool reads back the datapath's
own stats counters and tells you whether the packets really took the path the
profile claims — see [It checks it measured what it claims](#it-checks-it-measured-what-it-claims).

**Stop `policy-engine` first.** The bench installs its own rules into the shared
pinned maps, so it refuses to run while the service has XDP attached to an
interface rather than corrupt a live policy:

```bash
sudo systemctl stop policy-engine
```

## Comparing two builds

This is the whole point. Save a result, change the code, save another, diff:

```bash
sudo ./target/release/policy-progbench --profile verdict -o old.json --label baseline

# ... make the datapath change, then:
cargo build --release --bin policy-progbench

sudo ./target/release/policy-progbench --profile verdict -o new.json --label "coarse clock"

./target/release/policy-progbench --compare old.json new.json   # no root needed
```

The real diff that produced commit `a16e7e2` (taking the RDTSC off the fast path):

```
  metric                        A          B      delta   verdict
  -------------------- ---------- ---------- ----------   --------
  cycles/pkt                372.7      328.3     -11.9%   better
  instructions/pkt        1280.3     1287.3      +0.5%
  ipc                        3.44       3.92
  ns/pkt                     80.0       71.0     -11.2%   informational
```

Instructions *up*, cycles *down*, IPC up — the signature of removing a
serialising instruction rather than removing work.

`--compare` refuses to diff runs with different `--profile`, `--threads` or
`--flows` (they are different experiments), warns if the two runs loaded the same
program tag (you forgot to rebuild), and marks anything inside the combined
run-to-run spread as **`noise`** rather than letting you read a story into it.

## The knobs

| flag | default | what it is for |
|---|---|---|
| `--profile verdict\|policy` | `verdict` | which code path — see [The two profiles](#the-two-profiles) |
| `--threads N` | `1` | CPUs hammering the same maps; the only way to see contention |
| `--flows shared\|distinct` | `shared` | whether those CPUs collide on one cache entry or on the LRU list |
| `--repeat N` | `2000000` | program invocations per round |
| `--rounds N` | `5` | rounds per load (medians away scheduler noise) |
| `--reloads N` | `5` | full teardown+reload cycles — **this** is the error bar |
| `--rules N` | `64` | decoy dst prefixes, so the LPM trie isn't a single leaf |
| `--pkt-size N` | `64` | frame size on the wire |
| `--cpu N` | `0` | first CPU to pin to |
| `-o FILE`, `--label` | — | save a result for `--compare` |

A full run takes about 30 seconds. `--reloads 1 --rounds 3 --repeat 400000` is a
quick look, at the cost of a wider error bar.

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

It refuses to run if `policy-engine` has XDP attached: the bench installs its own
rules into the shared pinned maps and would corrupt a live policy.

One thing it cannot subtract: **about 3% of the absolute cycles/pkt is the
`BPF_PROG_TEST_RUN` harness itself** (`bpf_test_run`, `bpf_test_timer_continue`),
not your datapath. It is constant across builds, so it cannot distort an A/B —
but the absolute figure is very slightly flattering to reality.

## Going deeper: which *part* of the program?

`progbench` tells you the program got cheaper. To find out *where* the cycles
are, profile the run — the JIT'd subprograms and the kernel helpers they call
show up as ordinary symbols:

```bash
sudo perf record -F 9999 -e cycles -C 0 -o perf.data -- \
  ./target/release/policy-progbench --profile verdict \
  --reloads 1 --rounds 40 --repeat 2000000

sudo perf report -i perf.data --stdio --sort symbol --percent-limit 1
```

Pin `perf` to the same CPU the bench pins itself to (`-C 0` matches the default
`--cpu 0`), and give it enough rounds that the measured loop dominates the BPF
load at the start.

This is how the fast path's costs were found. As of `a16e7e2` the verdict-cache
hit path breaks down roughly as:

| share | what |
|---|---|
| ~31% | JIT'd `xdp_policy_main` body (stats bumps, inlined logic) |
| ~14% | `htab_map_hash` — jhash over the 20-byte verdict-cache key |
| ~12% | `parse_l3l4` + `parse_packet` (`__noinline` subprograms) |
| ~2% | `bpf_ktime_get_coarse_ns` — was 11.6% before `a16e7e2` |
| ~3% | the harness (see above) |

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
