#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

"""Datapath microbenchmark for the XDP policy engine.

Run this from a *third* box (your dev machine).  It logs in to the traffic
generator (TX) and to the device under test (RX), drives a pktgen load from TX,
measures RX with perf, and normalises everything **per packet** so results are
comparable across machines, packet rates and builds.

    dev box  ──ssh──>  TX node   (pktgen)
       │                  │ packets
       └─────ssh──────>  RX node  (XDP policy engine + perf)

Nothing needs to be installed on the dev box except python3 and ssh.

Why per-packet, and why repeats
-------------------------------
Raw perf counters are meaningless on their own: a run that received 7% fewer
packets shows 7% fewer cycles and looks like a win.  Everything here is divided
by the RX NIC's own hardware receive counter.  Each measurement is repeated and
reported as a median with spread, because the effects we chase are often only a
few percent, and one run cannot tell a few percent apart from noise.

Traffic profiles
----------------
hit   A bounded set of 5-tuples (--flows), sent repeatedly.  After warm-up
      almost every packet hits the flow verdict cache, so this measures the
      *fast path*: parse, stats, one hash lookup.  This is what steady-state
      production traffic looks like.

miss  Every packet is a fresh 5-tuple (randomised source address as well as
      port), so nothing hits the verdict cache and every packet walks the
      two-level LPM trie.  This measures the *slow path*, and is the only
      profile that exercises the rule-matching structures (dst_lpm_value,
      l4_rule).

A change usually moves only one of the two.  Measuring the wrong profile is the
easiest way to conclude that nothing happened.

Portability
-----------
Nothing here is tuned to a particular CPU.  Perf event names vary by
architecture (LLC-load-misses does not exist everywhere), so the usable set is
probed on the RX node at startup and unsupported events are dropped rather than
failing the run.  The RX platform's own facts -- CPU, cache sizes (including
whether an L3 exists at all), NIC driver, kernel, JIT and clocksource settings
-- are recorded into the result, so a number from one box can be compared
honestly against a number from another.

Usage
-----
    # measure the current build
    ./xdp-bench.py --tx fw4b --tx-iface enp2s0 \
                   --rx fws-2277 --rx-iface enp2s0 \
                   --profile hit -o new.json

    # ... rebuild/redeploy the other version on RX, then:
    ./xdp-bench.py --tx fw4b --tx-iface enp2s0 \
                   --rx fws-2277 --rx-iface enp2s0 \
                   --profile hit -o old.json

    # compare (runs anywhere, no ssh needed)
    ./xdp-bench.py --compare old.json new.json

Requirements
------------
    dev box   python3, ssh
    TX node   passwordless sudo, pktgen module
    RX node   passwordless sudo, perf, ethtool
"""

import argparse
import json
import re
import shlex
import statistics
import subprocess
import sys
import time

PKTGEN = "/proc/net/pktgen"

# Load-sweep tuning.  PLATEAU_TOL is how flat "flat" has to be: rx pps within
# 2% of the best seen.  PLATEAU_MIN_SPAN stops a plateau being declared off a
# short lever arm -- the offered load has to rise at least 15% across the flat
# region before "more load buys nothing" means anything.
SWEEP_SETTLE = 2
PLATEAU_TOL = 0.02
PLATEAU_MIN_SPAN = 0.15

# Counters we would like.  Probed on the RX node at startup; whatever that CPU
# does not implement is dropped.  cycles/instructions are the only ones we
# genuinely require -- the rest are diagnostic.
CANDIDATE_EVENTS = [
    "cycles",
    "instructions",
    "cache-misses",
    "cache-references",
    "LLC-load-misses",
    "LLC-store-misses",
    "branch-misses",
    "dTLB-load-misses",
]
REQUIRED_EVENTS = ["cycles", "instructions"]


def die(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


# --------------------------------------------------------------------------
# remote node
# --------------------------------------------------------------------------


class Node:
    """A box we drive over SSH.  Both TX and RX are one of these."""

    def __init__(self, host, user=None, ssh_opts="", role=""):
        self.host = host
        self.role = role
        self.target = f"{user}@{host}" if user else host
        self.ssh_opts = shlex.split(ssh_opts)

    def sh(self, cmd, check=True):
        """Run `cmd` in the remote login shell."""
        r = subprocess.run(
            ["ssh", *self.ssh_opts, self.target, cmd],
            text=True,
            capture_output=True,
        )
        if check and r.returncode != 0:
            die(f"[{self.role} {self.host}] command failed: {cmd}\n"
                f"        {r.stderr.strip()}")
        return r

    def sudo(self, cmd, check=True):
        return self.sh(f"sudo sh -c {shlex.quote(cmd)}", check=check)

    def read(self, path, default=None):
        r = self.sh(f"cat {shlex.quote(path)} 2>/dev/null", check=False)
        out = r.stdout.strip()
        return out if r.returncode == 0 and out else default

    def exists(self, path):
        """Presence of `path`, via sudo: /proc/net/pktgen/* are 0600 root, so an
        unprivileged stat cannot tell "absent" from "not allowed to look"."""
        return self.sudo(f"test -e {shlex.quote(path)}", check=False).returncode == 0

    def have(self, tool):
        """True if `tool` is on the login user's PATH or on root's.

        Tools like ethtool live in /sbin, which a non-interactive login shell
        usually leaves off PATH; we always invoke them through sudo anyway.
        """
        probe = f"command -v {tool} >/dev/null 2>&1"
        if self.sh(probe, check=False).returncode == 0:
            return True
        return self.sudo(probe, check=False).returncode == 0

    def preflight(self, tools, need_sudo=True):
        if self.sh("true", check=False).returncode != 0:
            die(f"cannot ssh to {self.target} (role: {self.role}). "
                f"Check the host and that key auth works non-interactively.")
        if need_sudo and self.sh("sudo -n true", check=False).returncode != 0:
            die(f"[{self.role} {self.host}] passwordless sudo is required")
        for t in tools:
            if not self.have(t):
                die(f"[{self.role} {self.host}] '{t}' is not installed")


# --------------------------------------------------------------------------
# RX platform description -- recorded, never assumed
# --------------------------------------------------------------------------


def describe_platform(rx, iface):
    """Everything about the RX box that could change the numbers."""
    info = {
        "host": rx.host,
        "kernel": rx.sh("uname -r").stdout.strip(),
        "cpu": None,
        "cores": None,
        "caches": {},
        "clocksource": rx.read(
            "/sys/devices/system/clocksource/clocksource0/current_clocksource"
        ),
        "bpf_jit_enable": rx.read("/proc/sys/net/core/bpf_jit_enable"),
        "bpf_jit_harden": rx.read("/proc/sys/net/core/bpf_jit_harden"),
        "nic": {"iface": iface},
    }

    for line in rx.sh("lscpu", check=False).stdout.splitlines():
        if line.startswith("Model name:"):
            info["cpu"] = line.split(":", 1)[1].strip()
        elif re.match(r"^CPU\(s\):", line):
            try:
                info["cores"] = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass

    # Cache topology from sysfs.  Never assume an L3 exists -- plenty of
    # embedded/Atom parts have none, which completely changes how a large map
    # behaves, and a reader of these numbers needs to know that.
    for idx in range(5):
        base = f"/sys/devices/system/cpu/cpu0/cache/index{idx}"
        level = rx.read(f"{base}/level")
        ctype = rx.read(f"{base}/type")
        size = rx.read(f"{base}/size")
        if level and size:
            suffix = {"Instruction": "i", "Data": "d"}.get(ctype, "")
            info["caches"][f"L{level}{suffix}"] = size

    uevent = rx.read(f"/sys/class/net/{iface}/device/uevent", "") or ""
    m = re.search(r"DRIVER=(\S+)", uevent)
    if m:
        info["nic"]["driver"] = m.group(1)
    info["nic"]["mac"] = rx.read(f"/sys/class/net/{iface}/address")
    info["bpf"] = bpf_fingerprint(rx)

    return info


def bpf_fingerprint(rx):
    """Identify the loaded datapath, so a result file says which build made it.

    Two runs of two different builds is the entire point of this tool, and
    nothing else in the result distinguishes them -- forget to redeploy and you
    get a beautifully precise comparison of a binary against itself.  The
    program tag is a hash of the instructions, so it changes iff the datapath
    changed; the map value sizes catch a struct-layout change even if the code
    is identical.
    """
    fp = {"prog_tags": {}, "map_value_sizes": {}}

    r = rx.sudo("bpftool prog show -j", check=False)
    if r.returncode == 0:
        try:
            for p in json.loads(r.stdout):
                name = p.get("name", "")
                if name.startswith(("xdp_policy", "tc_policy")) and p.get("tag"):
                    fp["prog_tags"][name] = p["tag"]
        except (ValueError, TypeError):
            pass

    r = rx.sudo("bpftool map show -j", check=False)
    if r.returncode == 0:
        try:
            for m in json.loads(r.stdout):
                name = m.get("name", "")
                if name in ("global_stats", "tc_global_stats", "pkt_scratch",
                            "tc_pkt_scratch") and "bytes_value" in m:
                    fp["map_value_sizes"][name] = m["bytes_value"]
        except (ValueError, TypeError):
            pass

    if not fp["prog_tags"] and not fp["map_value_sizes"]:
        return None
    return fp


# --------------------------------------------------------------------------
# Ethernet flow control
# --------------------------------------------------------------------------
#
# PAUSE frames turn the rig into a closed loop: a saturated DUT tells the
# generator to back off, so the offered load becomes a function of DUT capacity
# instead of an independent variable.  A build that speeds the datapath up then
# gets offered MORE traffic, and pps, delivered% and the cache counters all move
# for reasons that have nothing to do with per-packet cost.  Open-loop is the
# only regime in which "how many packets can the DUT absorb" has an answer, so
# the harness turns flow control off for the duration and puts it back after.


def pause_get(node, iface):
    """Current pause settings, or None if the driver has no ethtool -a."""
    r = node.sudo(f"ethtool -a {shlex.quote(iface)}", check=False)
    if r.returncode != 0:
        return None
    out = {}
    for key, field in (("Autonegotiate", "autoneg"), ("RX", "rx"), ("TX", "tx")):
        m = re.search(rf"^{key}:\s*(on|off)\s*$", r.stdout, re.M)
        if m:
            out[field] = m.group(1)
    return out or None


def pause_set(node, iface, settings):
    """Apply pause settings; returns True on success."""
    args = " ".join(f"{k} {v}" for k, v in settings.items())
    r = node.sudo(f"ethtool -A {shlex.quote(iface)} {args}", check=False)
    return r.returncode == 0


def pause_counters(node, iface):
    """XON/XOFF frame counters, to prove whether back-pressure actually fired."""
    r = node.sudo(f"ethtool -S {shlex.quote(iface)}", check=False)
    if r.returncode != 0:
        return {}
    out = {}
    for line in r.stdout.splitlines():
        m = re.match(r"\s*((?:rx|tx)_flow_control_x(?:on|off)):\s*(\d+)", line)
        if m:
            out[m.group(1)] = int(m.group(2))
    return out


def flow_control_disable(nodes_ifaces):
    """Turn pause off on every endpoint; return what to restore."""
    saved = []
    for node, iface in nodes_ifaces:
        before = pause_get(node, iface)
        if before is None:
            print(f"  note: [{node.role} {node.host}] {iface} has no ethtool -a; "
                  f"cannot check flow control")
            continue
        saved.append((node, iface, before))
        if before.get("rx") == "off" and before.get("tx") == "off":
            continue
        # autoneg must go off too, or the link renegotiates pause straight back on.
        if not pause_set(node, iface, {"autoneg": "off", "rx": "off", "tx": "off"}):
            print(f"  WARNING: [{node.role} {node.host}] could not disable flow "
                  f"control on {iface}. PAUSE frames will couple the offered load "
                  f"to DUT capacity and the results will not be trustworthy.")
        else:
            print(f"  flow control: disabled on {node.host}/{iface} "
                  f"(was rx={before.get('rx')} tx={before.get('tx')})")
    return saved


def flow_control_restore(saved):
    """Put pause back exactly as it was.  Runs even if the benchmark blew up."""
    for node, iface, before in saved:
        if pause_set(node, iface, before):
            print(f"  flow control: restored on {node.host}/{iface} "
                  f"(rx={before.get('rx')} tx={before.get('tx')} "
                  f"autoneg={before.get('autoneg')})")
        else:
            print(f"  WARNING: [{node.role} {node.host}] FAILED to restore flow "
                  f"control on {iface}. Original settings were "
                  f"{before}. Restore by hand:")
            args = " ".join(f"{k} {v}" for k, v in before.items())
            print(f"           ssh {node.host} sudo ethtool -A {iface} {args}")


def rx_ipv4(rx, iface):
    """The RX interface's address, so --rx-ip is optional."""
    out = rx.sh(f"ip -4 -o addr show dev {shlex.quote(iface)}", check=False).stdout
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


def probe_events(rx):
    """Keep only the perf events the RX CPU actually implements."""
    usable = []
    for ev in CANDIDATE_EVENTS:
        r = rx.sudo(f"perf stat -e {ev} -x, true", check=False)
        if r.returncode == 0 and "not supported" not in r.stderr:
            usable.append(ev)
    missing = [e for e in REQUIRED_EVENTS if e not in usable]
    if missing:
        die(f"[rx {rx.host}] perf cannot count {', '.join(missing)}. "
            f"Try: sudo sysctl -w kernel.perf_event_paranoid=-1")
    return usable


# --------------------------------------------------------------------------
# packet counting
# --------------------------------------------------------------------------


def rx_packets(rx, iface):
    """RX NIC hardware receive count.

    Deliberately ethtool and not /sys/class/net/*/statistics/rx_packets: whether
    an XDP_DROP'd packet appears in the netdev stats varies by driver, and a
    benchmark that drops every packet would then be dividing by garbage.  The
    hardware counter is always right.  Falls back to sysfs if the driver exposes
    no rx_packets in ethtool -S.
    """
    n, _ = rx_packets_at(rx, iface)
    return n


def rx_packets_at(rx, iface):
    """(count, remote timestamp) -- read in ONE ssh, with the DUT's own clock.

    The timestamp is the whole point.  Sampling a counter before and after a
    sleep and dividing by the sleep length assumes the two reads are free; they
    are not, they are ssh round trips, and on a slow link the real window is
    seconds longer than the nominal one.  That inflates every rate -- this tool
    once reported 1.89 Mpps on a 1 GbE link, whose 64-byte line rate is 1.49
    Mpps.  Divide by the elapsed time you actually measured, never by the one
    you asked for.
    """
    script = (
        f"ethtool -S {shlex.quote(iface)} 2>/dev/null "
        f"| awk '/^[[:space:]]*rx_packets:/ {{print $2; found=1}} "
        f"END {{if (!found) exit 1}}' "
        f"|| cat /sys/class/net/{shlex.quote(iface)}/statistics/rx_packets; "
        f"date +%s.%N"
    )
    r = rx.sudo(script, check=False)
    nums = re.findall(r"^\s*([\d.]+)\s*$", r.stdout, re.M)
    if len(nums) < 2:
        die(f"[rx {rx.host}] cannot read a receive counter for {iface}")
    return int(float(nums[0])), float(nums[1])


# --------------------------------------------------------------------------
# pktgen, on the TX node
# --------------------------------------------------------------------------


def pktgen_devices(args):
    """The /proc/net/pktgen entry names for this run.

    pktgen runs one kernel thread per CPU (kpktgend_N) and a thread drives a
    device named `iface@N`.  A single generating thread caps out well below
    line rate at small frame sizes -- with clone_skb 0 every packet is a fresh
    skb -- so a fast DUT is never saturated and pps measures the generator
    rather than the device under test.  Spreading the same device across N
    threads (and N hardware TX queues) is what lifts that ceiling.

    One thread keeps the bare `iface` name, matching what earlier runs of this
    script produced, so old result files stay comparable.
    """
    if args.tx_threads > 1:
        return [f"{args.tx_iface}@{i}" for i in range(args.tx_threads)]
    return [args.tx_iface]


def pktgen_threads(tx):
    """Every kpktgend_N thread the running kernel exposes (one per CPU)."""
    out = tx.sudo(f"ls {PKTGEN}", check=False).stdout or ""
    return sorted(re.findall(r"kpktgend_(\d+)", out), key=int)


def nic_tx_queues(tx, iface):
    """Hardware TX queue count, or None if ethtool can't say."""
    r = tx.sudo(f"ethtool -l {iface}", check=False)
    if r.returncode != 0:
        return None
    # Two blocks: "maximums" then "Current hardware settings"; we want current.
    cur = r.stdout.split("Current hardware settings:")
    if len(cur) < 2:
        return None
    counts = [int(m) for m in re.findall(r"^(?:TX|Combined):\s*(\d+)",
                                         cur[1], re.M)]
    return max(counts) if counts else None


def pktgen_configure(tx, args, rx_mac, dst_ip):
    tx.sudo("modprobe pktgen")

    if not tx.exists(f"{PKTGEN}/kpktgend_0"):
        die(f"[tx {tx.host}] {PKTGEN}/kpktgend_0 not present after modprobe pktgen")

    avail = pktgen_threads(tx)
    if args.tx_threads > len(avail):
        die(f"[tx {tx.host}] --tx-threads {args.tx_threads} but only "
            f"{len(avail)} pktgen thread(s) exist. pktgen creates one thread "
            f"per CPU, so this host cannot generate from more than "
            f"{len(avail)} thread(s).")

    devs = pktgen_devices(args)

    # Clear every thread, not just the ones about to be used: a previous run
    # with a higher --tx-threads leaves devices bound to the upper threads,
    # and pgctrl start would set them transmitting too, silently adding load
    # this run never configured.
    cmds = [(f"{PKTGEN}/kpktgend_{t}", "rem_device_all") for t in avail]

    ntxq = nic_tx_queues(tx, args.tx_iface)
    if args.tx_threads > 1 and ntxq is not None and ntxq < args.tx_threads:
        print(f"  note: {args.tx_iface} has {ntxq} TX queue(s) but "
              f"--tx-threads {args.tx_threads}; threads will contend on a "
              f"shared queue and may not scale")

    for i, dev in enumerate(devs):
        d = f"{PKTGEN}/{dev}"
        cmds += [
            (f"{PKTGEN}/kpktgend_{i}", f"add_device {dev}"),
            (d, "count 0"),
            # A fresh skb per packet.  With clone_skb > 0 pktgen reuses one skb,
            # so the randomisation flags below would be applied once and every
            # packet would carry the same 5-tuple -- silently turning either
            # profile into a single-flow test.
            (d, "clone_skb 0"),
            (d, f"pkt_size {args.pkt_size}"),
            (d, "delay 0"),
            (d, f"dst {dst_ip}"),
            (d, f"dst_mac {rx_mac}"),
            (d, f"udp_dst_min {args.dst_port}"),
            (d, f"udp_dst_max {args.dst_port}"),
        ]

        # Pin each thread to its own hardware TX queue.  Without this every
        # thread enqueues on the queue selected for the skb, re-serialising the
        # threads on one queue lock and wasting the extra CPUs.
        if args.tx_threads > 1 and ntxq:
            q = i % ntxq
            cmds += [(d, f"queue_map_min {q}"), (d, f"queue_map_max {q}")]

        if args.profile == "hit":
            # A bounded set of source ports => a bounded set of 5-tuples.  Once
            # the verdict cache holds them all, essentially every packet is a
            # cache hit.  Every thread draws from the same port range, so the
            # flow set stays the size the profile asked for however many
            # threads generate it.
            lo = 1024
            hi = min(65535, lo + args.flows - 1)
            cmds += [
                (d, f"udp_src_min {lo}"),
                (d, f"udp_src_max {hi}"),
                (d, "flag UDPSRC_RND"),
                (d, "flag !IPSRC_RND"),
            ]
        else:  # miss
            # Randomise the source address too, over a range far larger than the
            # cache, so a 5-tuple essentially never recurs: every packet misses
            # the verdict cache and walks the LPM trie.
            cmds += [
                (d, "udp_src_min 1024"),
                (d, "udp_src_max 65535"),
                (d, "flag UDPSRC_RND"),
                (d, f"src_min {args.miss_src_min}"),
                (d, f"src_max {args.miss_src_max}"),
                (d, "flag IPSRC_RND"),
            ]

    # One ssh round trip for the lot.  Sending each setting individually meant
    # ~16 round trips per thread -- 48 for a 3-thread run, tens of seconds of
    # setup, and a long window in which an interrupt leaves pktgen half
    # configured.  Each write still reports itself by name if it fails, so a
    # rejected setting is as easy to spot as it was one-per-ssh.
    script = "\n".join(
        f"echo {shlex.quote(val)} > {path} || "
        f"{{ echo 'pktgen rejected: {val} > {path}' >&2; exit 1; }}"
        for path, val in cmds
    )
    tx.sudo(script)

    return devs


def pktgen_start(tx):
    # pgctrl blocks for the life of the run (count 0 == until stopped), so
    # detach it from this ssh session.  One start drives every configured
    # thread.
    tx.sh(f"sudo sh -c 'nohup sh -c \"echo start > {PKTGEN}/pgctrl\" "
          f">/dev/null 2>&1 &' </dev/null", check=False)


def pktgen_stop(tx):
    tx.sudo(f"echo stop > {PKTGEN}/pgctrl", check=False)


def pktgen_sent(tx, devs):
    n, _ = pktgen_sent_at(tx, devs)
    return n


def pktgen_sent_at(tx, devs):
    """(packets transmitted, remote timestamp), summed over generating threads.

    Sampled either side of a window this yields the load actually offered during
    it -- unlike the `pps` line in the pktgen report, which is an average over
    the generator's whole lifetime (including warmup and idle).  As with the RX
    counter, the timestamp comes from the generator's own clock so the rate is
    divided by the window that really elapsed, not the one we asked for.
    """
    paths = " ".join(shlex.quote(f"{PKTGEN}/{d}") for d in devs)
    r = tx.sudo(f"cat {paths}; date +%s.%N", check=False)
    out = r.stdout or ""
    sofar = [int(m) for m in re.findall(r"pkts-sofar:\s*(\d+)", out)]
    ts = re.findall(r"^\s*(\d+\.\d+)\s*$", out, re.M)
    if not sofar or not ts:
        return None, None
    return sum(sofar), float(ts[-1])


def pktgen_set_rate(tx, devs, pps_total):
    """Throttle the generator to `pps_total`, or None for full tilt.

    The generator MUST be stopped first: pktgen silently ignores parameter
    writes to a device its thread is currently transmitting on, so setting a
    rate on a running device leaves it going at whatever speed it liked and the
    resulting sweep is a fiction.  Callers stop, set, then start.

    pktgen implements ratep as an inter-packet delay, so the rate is per device:
    split the target across the generating threads.  `ratep 0` is rejected by
    the kernel -- removing the limit means writing `delay 0`.
    """
    if pps_total is None:
        cmds = [(f"{PKTGEN}/{d}", "delay 0") for d in devs]
    else:
        per_thread = max(1, int(pps_total // len(devs)))
        cmds = [(f"{PKTGEN}/{d}", f"ratep {per_thread}") for d in devs]
    script = "\n".join(
        f"echo {shlex.quote(v)} > {p} || "
        f"{{ echo 'pktgen rejected: {v} > {p}' >&2; exit 1; }}"
        for p, v in cmds
    )
    tx.sudo(script)


def pktgen_retarget(tx, devs, pps_total):
    """Stop, re-rate, restart.  The only way a rate change actually lands."""
    pktgen_stop(tx)
    time.sleep(0.5)
    pktgen_set_rate(tx, devs, pps_total)
    pktgen_start(tx)
    time.sleep(SWEEP_SETTLE)


def measure_load(rx, iface, tx, devs, duration):
    """Offered and received pps over one window.  No perf, just counters.

    Each side divides by the elapsed time it measured on its own clock, so ssh
    latency inflates neither rate.
    """
    s0, ts0 = pktgen_sent_at(tx, devs)
    r0, tr0 = rx_packets_at(rx, iface)
    time.sleep(duration)
    s1, ts1 = pktgen_sent_at(tx, devs)
    r1, tr1 = rx_packets_at(rx, iface)

    rx_pps = (r1 - r0) / (tr1 - tr0) if tr1 > tr0 else None
    offered = None
    if None not in (s0, s1, ts0, ts1) and ts1 > ts0:
        offered = (s1 - s0) / (ts1 - ts0)
    return {"offered_pps": offered, "rx_pps": rx_pps}


def sweep_load(tx, rx, args, devs):
    """Walk the offered load and find where the DUT stops keeping up.

    This is the only honest way to establish that the DUT is the bottleneck.
    Drops alone do not prove it: a NIC ring overflowing on bursty traffic sheds
    a roughly constant *fraction* of whatever it is offered, so rx pps keeps
    climbing with offered pps and "delivered < 100%" says nothing about
    capacity.  A DUT at its ceiling behaves differently -- rx pps flattens while
    offered keeps rising.  Look for that flattening, or admit there isn't one.
    """
    print(f"  sweep: walking the offered load ({args.sweep_steps} steps x "
          f"{args.sweep_duration}s) ...")

    # Full tilt first, to learn what the generator can actually offer.
    pktgen_retarget(tx, devs, None)
    top = measure_load(rx, args.rx_iface, tx, devs, args.sweep_duration)
    ceiling = top["offered_pps"]
    if not ceiling:
        print("  sweep: cannot read the TX counter; skipping")
        return None

    def show(p, note=""):
        got = p["offered_pps"]
        miss = ""
        if p["target_pps"]:
            err = abs(got - p["target_pps"]) / p["target_pps"] * 100
            # A rate that did not land makes this point meaningless; say so
            # rather than quietly plotting it.
            if err > 20:
                miss = f"  !! asked {p['target_pps']:,.0f}, rate did not land"
        print(f"    offered {got:>10,.0f}  ->  rx {p['rx_pps']:>10,.0f}"
              f"   ({100 * p['rx_pps'] / got:5.1f}% delivered){note}{miss}")

    points = []
    for i in range(1, args.sweep_steps):
        target = int(ceiling * i / args.sweep_steps)
        pktgen_retarget(tx, devs, target)
        p = measure_load(rx, args.rx_iface, tx, devs, args.sweep_duration)
        p["target_pps"] = target
        points.append(p)
        show(p)

    top["target_pps"] = None
    points.append(top)
    show(top, "  [unlimited]")

    # Leave the generator at full tilt for the measured runs that follow.
    pktgen_retarget(tx, devs, None)

    return {"points": points, **find_knee(points)}


def find_knee(points):
    """Did rx pps flatten while offered kept climbing?

    Plateau == the DUT is the bottleneck and its ceiling is the flat value.
    No plateau == rx still tracks offered, so the generator is still the limit
    and pps is not a property of the DUT at all.
    """
    pts = sorted((p for p in points if p["offered_pps"]),
                 key=lambda p: p["offered_pps"])
    if len(pts) < 3:
        return {"plateau": False, "ceiling_pps": None, "knee_offered_pps": None}

    best = max(p["rx_pps"] for p in pts)
    # Walk up: the knee is the lowest offered load whose rx is already within
    # PLATEAU_TOL of the best rx seen -- beyond it, more load buys nothing.
    for i, p in enumerate(pts):
        if p["rx_pps"] < best * (1 - PLATEAU_TOL):
            continue
        # Everything at or above this point must also be flat, and there must
        # be a meaningful rise in offered load across them, or "flat" is just
        # a short lever arm.
        above = pts[i:]
        if len(above) < 2:
            break
        span = (above[-1]["offered_pps"] - p["offered_pps"]) / p["offered_pps"]
        flat = all(q["rx_pps"] >= best * (1 - PLATEAU_TOL) for q in above)
        if flat and span >= PLATEAU_MIN_SPAN:
            return {"plateau": True,
                    "ceiling_pps": sum(q["rx_pps"] for q in above) / len(above),
                    "knee_offered_pps": p["offered_pps"]}
        break
    return {"plateau": False, "ceiling_pps": None, "knee_offered_pps": None}


def pktgen_report(tx, devs):
    """Lifetime pps per generating thread, and their sum."""
    per_thread, raw = [], []
    for d in devs:
        out = tx.sudo(f"cat {PKTGEN}/{shlex.quote(d)}", check=False).stdout or ""
        m = re.search(r"(\d+)pps", out)
        per_thread.append({"device": d, "pps": int(m.group(1)) if m else None})
        raw.append(out.strip())
    known = [t["pps"] for t in per_thread if t["pps"] is not None]
    return {
        "tx_pps": sum(known) if known else None,
        "threads": len(devs),
        "per_thread": per_thread,
        "raw": "\n\n".join(raw),
    }


# --------------------------------------------------------------------------
# measurement
# --------------------------------------------------------------------------


def measure_once(rx, iface, events, duration, tx=None, tx_devs=None):
    """One perf window on RX, normalised by packets received in that window.

    The TX counter is sampled over the same window so `offered_pps` is directly
    comparable to the received pps.  That comparison is the only way to know
    whether pps means anything: if the DUT receives everything offered it is
    not the bottleneck, and pps is measuring the generator.
    """
    ev = ",".join(events)

    # Counter reads bracket the perf window INSIDE one ssh, on the DUT's clock.
    # Done as separate round trips the packet window silently included the ssh
    # latency, so the packet count covered a longer period than perf did and
    # every per-packet figure came out low (and pps came out impossibly high).
    cnt = (f"ethtool -S {shlex.quote(iface)} 2>/dev/null "
           f"| awk '/^[[:space:]]*rx_packets:/ {{print $2; found=1}} "
           f"END {{if (!found) exit 1}}' "
           f"|| cat /sys/class/net/{shlex.quote(iface)}/statistics/rx_packets")
    script = (
        f"P0=$({cnt}); T0=$(date +%s.%N); "
        f"perf stat -a -e {ev} -x, -- sleep {duration} 2>/tmp/.xdp_bench_perf; "
        f"T1=$(date +%s.%N); P1=$({cnt}); "
        f"echo \"BENCH $P0 $P1 $T0 $T1\"; cat /tmp/.xdp_bench_perf"
    )

    sent_before, ts_before = pktgen_sent_at(tx, tx_devs) if tx else (None, None)
    r = rx.sudo(script)
    sent_after, ts_after = pktgen_sent_at(tx, tx_devs) if tx else (None, None)

    m = re.search(r"^BENCH (\d+) (\d+) ([\d.]+) ([\d.]+)$", r.stdout, re.M)
    if not m:
        die(f"[rx {rx.host}] could not read the packet counters around the "
            f"perf window")
    p0, p1 = int(m.group(1)), int(m.group(2))
    elapsed = float(m.group(4)) - float(m.group(3))
    packets = p1 - p0
    if packets <= 0:
        die("no packets arrived during the measurement window -- is traffic running?")
    if elapsed <= 0:
        die(f"[rx {rx.host}] non-monotonic clock across the measurement window")

    counters = {}
    for line in r.stdout.splitlines():
        parts = line.split(",")
        if len(parts) < 3:
            continue
        value, name = parts[0], parts[2]
        if name in events and value not in ("<not counted>", "<not supported>"):
            try:
                counters[name] = float(value)
            except ValueError:
                pass

    pps = packets / elapsed
    # perf counted over exactly `duration` (the sleep it wrapped), while the
    # packet counters span `elapsed` (duration plus the two local reads).
    # Normalise the packet count onto perf's window rather than mixing them.
    packets_in_perf_window = pps * duration

    per_pkt = {f"{k}/pkt": v / packets_in_perf_window for k, v in counters.items()}
    if counters.get("cycles"):
        per_pkt["ipc"] = counters["instructions"] / counters["cycles"]
    per_pkt["pps"] = pps

    out = {"packets": packets, "elapsed": elapsed, "raw": counters,
           "per_packet": per_pkt}

    if None not in (sent_before, sent_after, ts_before, ts_after):
        sent = sent_after - sent_before
        tx_elapsed = ts_after - ts_before
        if sent > 0 and tx_elapsed > 0:
            offered = sent / tx_elapsed
            out["sent"] = sent
            per_pkt["offered_pps"] = offered
            # Fraction of the offered load the DUT took.  Loss does NOT prove
            # the DUT is the bottleneck -- see saturation() -- it is reported
            # so a sweep can be interpreted, not as a verdict on its own.
            per_pkt["delivered_pct"] = min(100.0, 100.0 * pps / offered)

    return out


def aggregate(runs):
    """Median and spread across repeats.

    Spread is reported so a reader can see whether a delta between two builds is
    bigger than the run-to-run noise.  A 5% "improvement" with 8% spread is not
    an improvement.
    """
    keys = set()
    for r in runs:
        keys |= set(r["per_packet"])

    out = {}
    for k in sorted(keys):
        vals = [r["per_packet"][k] for r in runs if k in r["per_packet"]]
        if not vals:
            continue
        out[k] = {
            "median": statistics.median(vals),
            "min": min(vals),
            "max": max(vals),
            "stdev": statistics.stdev(vals) if len(vals) > 1 else 0.0,
            "n": len(vals),
        }
    return out


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------


def fmt(v):
    if v >= 1000:
        return f"{v:,.0f}"
    if v >= 10:
        return f"{v:.1f}"
    return f"{v:.3f}"


def print_result(res):
    p, c = res["platform"], res["config"]
    caches = ", ".join(f"{k} {v}" for k, v in p.get("caches", {}).items())
    print()
    print(f"  rx        {p['host']}: {p.get('cpu')} ({p.get('cores')} cores)")
    print(f"  caches    {caches or 'unknown'}")
    if not any(k.startswith("L3") for k in p.get("caches", {})):
        print("            (no L3 -- last-level cache is L2; large maps will not fit)")
    print(f"  kernel    {p.get('kernel')}  jit={p.get('bpf_jit_enable')} "
          f"harden={p.get('bpf_jit_harden')} clocksource={p.get('clocksource')}")
    print(f"  nic       {p['nic'].get('driver')} {p['nic'].get('iface')}")
    fp = p.get("bpf")
    if fp:
        tags = " ".join(f"{n}={t[:12]}" for n, t in sorted(fp["prog_tags"].items()))
        sizes = " ".join(f"{n}={v}B" for n, v in sorted(fp["map_value_sizes"].items()))
        print(f"  datapath  {tags or 'no policy programs loaded'}")
        if sizes:
            print(f"            {sizes}")
    flows = c["flows"] if c["profile"] == "hit" else "unbounded"
    print(f"  traffic   {c['profile']} profile, {c['pkt_size']}B frames, "
          f"flows={flows}, {c['repeats']}x{c['duration']}s, "
          f"{c.get('tx_threads', 1)} tx thread(s)")
    print()

    stats = res["stats"]
    print(f"  {'metric':<24} {'median':>12} {'min':>12} {'max':>12} {'spread':>8}")
    print(f"  {'-'*24} {'-'*12} {'-'*12} {'-'*12} {'-'*8}")
    for k in sorted(stats):
        s = stats[k]
        spread = (s["stdev"] / s["median"] * 100) if s["median"] else 0
        print(f"  {k:<24} {fmt(s['median']):>12} {fmt(s['min']):>12} "
              f"{fmt(s['max']):>12} {spread:>7.1f}%")
    print()
    print_flow_control(res)
    print_saturation(res)


def paused_frames(res):
    """Total XOFF frames seen during the run (0 == the rig stayed open-loop)."""
    fc = res.get("flow_control") or {}
    return sum(v for host in fc.get("pause_frames", {}).values()
               for k, v in host.items() if k.endswith("_xoff"))


def print_flow_control(res):
    fc = res.get("flow_control")
    if not fc:
        return
    xoff = paused_frames(res)
    if xoff:
        print(f"  flow ctl    WARNING: {xoff:,} PAUSE (xoff) frames during the run.")
        print("              The DUT back-pressured the generator, so offered load")
        print("              tracks DUT capacity and pps/delivered% are circular.")
    else:
        print("  flow ctl    open-loop (no PAUSE frames) -- offered load is "
              "independent of the DUT")
    print()


def saturation(res):
    """Is the DUT provably the bottleneck?

    Returns (state, delivered_pct) where state is:
      "saturated"  -- a load sweep found rx pps flattening: pps is a real result
      "keeping_up" -- the DUT takes everything offered: pps measures the generator
      "unproven"   -- it drops packets, but nothing here shows it hit a ceiling

    "unproven" is the important one, and it is the common case.  Packet loss on
    its own does NOT mean the DUT is at capacity: a NIC ring overflowing on
    bursty traffic sheds a roughly constant fraction of whatever it is offered,
    so rx pps keeps rising with offered pps.  An earlier version of this tool
    read any loss as saturation and duly promoted pps to a real result -- which
    was wrong, and flattered a build that had not actually got faster.  Only a
    sweep can settle it, so without one we refuse to claim.
    """
    d = res["stats"].get("delivered_pct")
    pct = d["median"] if d else None

    sweep = res.get("sweep")
    if sweep and sweep.get("plateau"):
        offered = res["stats"].get("offered_pps")
        knee = sweep.get("knee_offered_pps")
        # The plateau only certifies runs driven at or past the knee.
        if offered and knee and offered["median"] >= knee * (1 - PLATEAU_TOL):
            return "saturated", pct

    if pct is None:
        return None, None
    if pct >= 99.0:
        return "keeping_up", pct
    return "unproven", pct


def print_saturation(res):
    state, pct = saturation(res)
    sweep = res.get("sweep")

    if sweep:
        if sweep.get("plateau"):
            print(f"  sweep       rx pps flattened at "
                  f"{sweep['ceiling_pps']:,.0f} pps (knee at "
                  f"{sweep['knee_offered_pps']:,.0f} offered)")
        else:
            print("  sweep       NO plateau: rx pps still climbs with offered load,")
            print("              so the DUT never reached a ceiling -- the generator")
            print("              is still the limit. Raise --tx-threads / add a")
            print("              second generator before believing any pps number.")

    if state is None:
        print("  saturation  unknown (no TX counter sampled; old result file?)")
    elif state == "saturated":
        print(f"  saturation  DUT is the bottleneck (took {pct:.1f}% of offered "
              f"load, and\n              a sweep proved its rx pps plateaus) -- "
              f"pps is a real result.")
    elif state == "keeping_up":
        print(f"  saturation  DUT took {pct:.1f}% of offered load -- it kept up with")
        print("              the generator, so pps measures the GENERATOR, not the DUT.")
    else:
        print(f"  saturation  UNPROVEN. The DUT dropped {100 - pct:.1f}% of the offered")
        print("              load, but loss alone does not mean it hit a ceiling --")
        print("              a bursty overflowing RX ring sheds a fixed fraction of")
        print("              whatever it is given. Run with --sweep to find out")
        print("              whether rx pps actually plateaus. Until then only the")
        print("              per-packet columns say anything about the DUT.")
    print()


def compare(path_a, path_b):
    """Diff two results, and refuse to call noise a win."""
    with open(path_a) as f:
        a = json.load(f)
    with open(path_b) as f:
        b = json.load(f)

    if a["config"]["profile"] != b["config"]["profile"]:
        die(f"refusing to compare different traffic profiles "
            f"({a['config']['profile']} vs {b['config']['profile']}) -- "
            f"they measure different code paths")
    if a["platform"].get("cpu") != b["platform"].get("cpu"):
        print(f"  WARNING: different RX CPUs ({a['platform'].get('cpu')} vs "
              f"{b['platform'].get('cpu')}); per-packet figures are not comparable.\n")

    # Did the two runs actually measure two different datapaths?  Forgetting to
    # redeploy yields a flawlessly precise comparison of a build against itself,
    # and every column then reads "noise" for the most boring possible reason.
    fa = a["platform"].get("bpf")
    fb = b["platform"].get("bpf")
    if fa and fb:
        if fa == fb:
            tag = " ".join(f"{n}={t[:12]}" for n, t in sorted(fa["prog_tags"].items()))
            print("  WARNING: A and B loaded the SAME datapath -- identical program")
            print(f"           tags and map layouts ({tag}).")
            print("           These two files measure one build against itself; any")
            print("           delta below is noise. Redeploy and re-run B.\n")
    elif fa or fb:
        print("  WARNING: only one file records a datapath fingerprint; cannot "
              "confirm\n           the two runs measured different builds.\n")

    # PAUSE frames make offered load a function of DUT capacity (see the flow
    # control section): the throughput columns stop being causal.
    xa, xb = paused_frames(a), paused_frames(b)
    if xa or xb:
        print(f"  WARNING: PAUSE frames fired during the run(s) "
              f"(A={xa:,} B={xb:,} xoff).")
        print("           The DUT back-pressured the generator, so a faster build is")
        print("           offered more load and pps is circular. Re-run without")
        print("           --keep-flow-control.\n")

    # Offered load, not received: an open-loop generator should offer the same
    # load to both builds, and if it did not, the runs were not equivalent.
    oa, ob = a["stats"].get("offered_pps"), b["stats"].get("offered_pps")
    if oa and ob and oa["median"]:
        drift = abs(ob["median"] - oa["median"]) / oa["median"] * 100
        if drift > 5:
            print(f"  WARNING: offered load differed by {drift:.0f}% between runs "
                  f"({oa['median']:,.0f} vs {ob['median']:,.0f} pps).")
            print("           Per-packet figures normalise for this, but pps does not:")
            print("           the two runs were not load-equivalent.\n")

    # pps is only a statement about the DUT when the DUT is provably the thing
    # running out of headroom -- which takes a sweep, not just packet loss.
    sat_a, pct_a = saturation(a)
    sat_b, pct_b = saturation(b)
    pps_is_real = sat_a == "saturated" and sat_b == "saturated"

    print()
    print(f"  A = {path_a}  {a.get('label') or ''}")
    print(f"  B = {path_b}  {b.get('label') or ''}")
    print(f"  profile: {a['config']['profile']}   rx: {a['platform']['host']}")
    if pct_a is not None and pct_b is not None:
        why = {
            "saturated": "a real result (sweep proved the DUT plateaus)",
            "keeping_up": "OFFERED LOAD ONLY (the DUT kept up)",
            "unproven": "OFFERED LOAD ONLY (no sweep: loss != saturation)",
        }
        state = "saturated" if pps_is_real else (
            "keeping_up" if "keeping_up" in (sat_a, sat_b) else "unproven")
        print(f"  DUT took {pct_a:.1f}% (A) / {pct_b:.1f}% (B) of offered load"
              f"  ->  pps is {why[state]}")
    print()
    print(f"  {'metric':<24} {'A':>12} {'B':>12} {'delta':>10}   verdict")
    print(f"  {'-'*24} {'-'*12} {'-'*12} {'-'*10}   {'-'*8}")

    saw_load = False
    for k in sorted(set(a["stats"]) | set(b["stats"])):
        sa, sb = a["stats"].get(k), b["stats"].get(k)
        if not sa or not sb or not sa["median"]:
            continue
        # Bookkeeping, not results: these exist to qualify pps, not to be read
        # as wins.
        if k in ("offered_pps", "delivered_pct"):
            continue
        delta = (sb["median"] - sa["median"]) / sa["median"] * 100

        # Call it noise unless the change clears the combined run-to-run spread
        # of the two measurements.  This is the guard against reading a story
        # into a 2% wobble.
        noise = (sa["stdev"] + sb["stdev"]) / sa["median"] * 100
        if k == "pps" and not pps_is_real:
            # The DUT absorbed everything offered in at least one run, so pps
            # just reflects how fast TX felt like going (common: clone_skb 0
            # makes pktgen allocate an skb per packet, and a single generating
            # thread tops out well below line rate).  Calling a wobble in it
            # "better" would be exactly the misreading per-packet normalisation
            # exists to prevent.
            verdict = "load"
            saw_load = True
        elif abs(delta) <= max(noise, 1.0):
            verdict = "noise"
        elif k in ("ipc", "pps"):
            verdict = "better" if delta > 0 else "worse"
        else:
            verdict = "better" if delta < 0 else "worse"

        print(f"  {k:<24} {fmt(sa['median']):>12} {fmt(sb['median']):>12} "
              f"{delta:>+9.1f}%   {verdict}")

    print()
    print("  'noise'  within the combined run-to-run spread of the two runs;")
    print("           collect more repeats before believing it.")
    if saw_load:
        print("  'load'   offered load, not a result: the DUT kept up with the")
        print("           generator, so this column measures TX. Raise --tx-threads")
        print("           until the DUT starts dropping, then pps becomes real.")
    print()


# --------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(
        description="Per-packet datapath benchmark for the XDP policy engine. "
                    "Runs from a dev box; drives TX and RX over SSH.")
    ap.add_argument("--compare", nargs=2, metavar=("A.json", "B.json"),
                    help="diff two saved results and exit (no ssh needed)")

    ap.add_argument("--tx", help="traffic generator host")
    ap.add_argument("--tx-iface", help="TX egress interface")
    ap.add_argument("--tx-user")
    ap.add_argument("--tx-threads", type=int, default=1, metavar="N",
                    help="pktgen kernel threads generating traffic (default 1). "
                         "One thread cannot saturate a fast DUT at small frame "
                         "sizes, which leaves pps measuring the generator; raise "
                         "this until the reported delivered%% drops below 100. "
                         "Capped by the TX host's CPU count.")

    ap.add_argument("--rx", help="device under test (runs the XDP program)")
    ap.add_argument("--rx-iface", help="RX ingress interface")
    ap.add_argument("--rx-user")
    ap.add_argument("--rx-ip", help="RX address for pktgen (default: auto-detect)")

    ap.add_argument("--ssh-opts", default="-o BatchMode=yes -o ConnectTimeout=5")
    ap.add_argument("--dst-port", type=int, default=5201)
    ap.add_argument("--keep-flow-control", action="store_true",
                    help="do not disable Ethernet PAUSE for the run. Off by "
                         "default because a saturated DUT pauses the generator, "
                         "making the offered load a function of DUT capacity -- "
                         "a faster datapath then gets offered more traffic and "
                         "every throughput number becomes circular. Original "
                         "settings are restored on exit either way.")

    ap.add_argument("--profile", choices=["hit", "miss"], default="hit",
                    help="hit: bounded flow set, exercises the verdict-cache fast "
                         "path (steady-state traffic). miss: every packet a new "
                         "5-tuple, exercises the LPM rule-matching slow path.")
    ap.add_argument("--flows", type=int, default=64512,
                    help="distinct 5-tuples for the hit profile (default 64512)")
    ap.add_argument("--pkt-size", type=int, default=60,
                    help="pktgen frame size excluding FCS; 60 => 64B on the wire")
    ap.add_argument("--miss-src-min", default="10.128.0.1")
    ap.add_argument("--miss-src-max", default="10.191.255.254")

    ap.add_argument("--sweep", action="store_true",
                    help="before measuring, walk the offered load and find where "
                         "rx pps flattens. This is the ONLY thing that proves the "
                         "DUT is the bottleneck -- packet loss alone does not, "
                         "since an overflowing RX ring sheds a fixed fraction of "
                         "whatever it is offered. Without a sweep, pps is reported "
                         "as offered load rather than a result.")
    ap.add_argument("--sweep-steps", type=int, default=6, metavar="N",
                    help="load points in the sweep (default 6)")
    ap.add_argument("--sweep-duration", type=int, default=5, metavar="SECS",
                    help="seconds per sweep point (default 5)")

    ap.add_argument("--duration", type=int, default=10, help="seconds per repeat")
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--warmup", type=int, default=15,
                    help="seconds of traffic before measuring, so the verdict "
                         "cache reaches steady state")
    ap.add_argument("-o", "--output", help="write the result as JSON")
    ap.add_argument("--label", default="", help="free-text label stored in the result")

    args = ap.parse_args()

    if args.compare:
        compare(*args.compare)
        return

    for req in ("tx", "tx_iface", "rx", "rx_iface"):
        if not getattr(args, req):
            die(f"--{req.replace('_', '-')} is required (or use --compare)")

    if args.tx_threads < 1:
        die("--tx-threads must be at least 1")

    tx = Node(args.tx, args.tx_user, args.ssh_opts, role="tx")
    rx = Node(args.rx, args.rx_user, args.ssh_opts, role="rx")

    print(f"  checking {tx.host} (tx) and {rx.host} (rx) ...")
    tx.preflight([])                       # pktgen is a module, not a binary
    rx.preflight(["perf", "ethtool"])

    platform = describe_platform(rx, args.rx_iface)
    rx_mac = platform["nic"]["mac"]
    if not rx_mac:
        die(f"[rx {rx.host}] cannot read the MAC of {args.rx_iface}")

    dst_ip = args.rx_ip or rx_ipv4(rx, args.rx_iface)
    if not dst_ip:
        die(f"[rx {rx.host}] {args.rx_iface} has no IPv4 address; pass --rx-ip")

    events = probe_events(rx)
    dropped = [e for e in CANDIDATE_EVENTS if e not in events]
    if dropped:
        print(f"  note: {rx.host} does not implement {', '.join(dropped)} -- skipping")

    print(f"  pktgen: {tx.host}/{args.tx_iface} -> {dst_ip} ({rx_mac}) "
          f"[{args.profile} profile, {args.tx_threads} thread(s)]")

    endpoints = [(tx, args.tx_iface), (rx, args.rx_iface)]
    saved_pause = []
    if not args.keep_flow_control:
        saved_pause = flow_control_disable(endpoints)

    runs = []
    sweep = None
    pause_before = {n.host: pause_counters(n, i) for n, i in endpoints}
    try:
        devs = pktgen_configure(tx, args, rx_mac, dst_ip)
        pktgen_start(tx)
        print(f"  warming up {args.warmup}s ...")
        time.sleep(args.warmup)

        seen = rx_packets(rx, args.rx_iface)
        time.sleep(1)
        if rx_packets(rx, args.rx_iface) == seen:
            die("no traffic arriving at RX. Check cabling, that the TX interface "
                "faces RX, and that pktgen started (ssh to TX and read "
                f"{PKTGEN}/{devs[0]}).")

        if args.sweep:
            sweep = sweep_load(tx, rx, args, devs)

        for i in range(args.repeats):
            print(f"  measuring {i+1}/{args.repeats} ({args.duration}s) ...")
            runs.append(measure_once(rx, args.rx_iface, events, args.duration,
                                     tx=tx, tx_devs=devs))
        tx_report = pktgen_report(tx, devs)
    finally:
        # Always stop the generator and hand the NICs back the way we found
        # them -- including on Ctrl-C, a dead ssh, or a die() mid-run.  Leaving
        # a box with flow control silently off is a booby trap for whatever
        # runs on it next.
        pktgen_stop(tx)
        flow_control_restore(saved_pause)

    pause_after = {n.host: pause_counters(n, i) for n, i in endpoints}
    flow_control = {
        "disabled_for_run": bool(saved_pause) and not args.keep_flow_control,
        "pause_frames": {
            host: {k: v - pause_before.get(host, {}).get(k, 0)
                   for k, v in after.items()}
            for host, after in pause_after.items()
        },
    }

    result = {
        "label": args.label,
        "platform": platform,
        "config": {
            "profile": args.profile,
            "flows": args.flows,
            "pkt_size": args.pkt_size,
            "duration": args.duration,
            "repeats": args.repeats,
            "tx_threads": args.tx_threads,
            "events": events,
        },
        "flow_control": flow_control,
        "sweep": sweep,
        "tx": tx_report,
        "runs": runs,
        "stats": aggregate(runs),
    }

    print_result(result)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"  written to {args.output}")
        print(f"  compare with: {sys.argv[0]} --compare <baseline.json> {args.output}")
        print()


if __name__ == "__main__":
    main()
