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

    return info


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
    r = rx.sudo(f"ethtool -S {iface}", check=False)
    if r.returncode == 0:
        for line in r.stdout.splitlines():
            m = re.match(r"\s*rx_packets:\s*(\d+)", line)
            if m:
                return int(m.group(1))
    v = rx.read(f"/sys/class/net/{iface}/statistics/rx_packets")
    if v is None:
        die(f"[rx {rx.host}] cannot read a receive counter for {iface}")
    return int(v)


# --------------------------------------------------------------------------
# pktgen, on the TX node
# --------------------------------------------------------------------------


def pktgen_configure(tx, args, rx_mac, dst_ip):
    dev = args.tx_iface
    tx.sudo("modprobe pktgen")

    if not tx.exists(f"{PKTGEN}/kpktgend_0"):
        die(f"[tx {tx.host}] {PKTGEN}/kpktgend_0 not present after modprobe pktgen")

    cmds = [
        (f"{PKTGEN}/kpktgend_0", "rem_device_all"),
        (f"{PKTGEN}/kpktgend_0", f"add_device {dev}"),
        (f"{PKTGEN}/{dev}", "count 0"),
        # A fresh skb per packet.  With clone_skb > 0 pktgen reuses one skb, so
        # the randomisation flags below would be applied once and every packet
        # would carry the same 5-tuple -- silently turning either profile into a
        # single-flow test.
        (f"{PKTGEN}/{dev}", "clone_skb 0"),
        (f"{PKTGEN}/{dev}", f"pkt_size {args.pkt_size}"),
        (f"{PKTGEN}/{dev}", "delay 0"),
        (f"{PKTGEN}/{dev}", f"dst {dst_ip}"),
        (f"{PKTGEN}/{dev}", f"dst_mac {rx_mac}"),
        (f"{PKTGEN}/{dev}", f"udp_dst_min {args.dst_port}"),
        (f"{PKTGEN}/{dev}", f"udp_dst_max {args.dst_port}"),
    ]

    if args.profile == "hit":
        # A bounded set of source ports => a bounded set of 5-tuples.  Once the
        # verdict cache holds them all, essentially every packet is a cache hit.
        lo = 1024
        hi = min(65535, lo + args.flows - 1)
        cmds += [
            (f"{PKTGEN}/{dev}", f"udp_src_min {lo}"),
            (f"{PKTGEN}/{dev}", f"udp_src_max {hi}"),
            (f"{PKTGEN}/{dev}", "flag UDPSRC_RND"),
            (f"{PKTGEN}/{dev}", "flag !IPSRC_RND"),
        ]
    else:  # miss
        # Randomise the source address too, over a range far larger than the
        # cache, so a 5-tuple essentially never recurs: every packet misses the
        # verdict cache and walks the LPM trie.
        cmds += [
            (f"{PKTGEN}/{dev}", "udp_src_min 1024"),
            (f"{PKTGEN}/{dev}", "udp_src_max 65535"),
            (f"{PKTGEN}/{dev}", "flag UDPSRC_RND"),
            (f"{PKTGEN}/{dev}", f"src_min {args.miss_src_min}"),
            (f"{PKTGEN}/{dev}", f"src_max {args.miss_src_max}"),
            (f"{PKTGEN}/{dev}", "flag IPSRC_RND"),
        ]

    for path, val in cmds:
        tx.sudo(f"echo {shlex.quote(val)} > {path}")


def pktgen_start(tx):
    # pgctrl blocks for the life of the run (count 0 == until stopped), so
    # detach it from this ssh session.
    tx.sh(f"sudo sh -c 'nohup sh -c \"echo start > {PKTGEN}/pgctrl\" "
          f">/dev/null 2>&1 &' </dev/null", check=False)


def pktgen_stop(tx):
    tx.sudo(f"echo stop > {PKTGEN}/pgctrl", check=False)


def pktgen_report(tx, dev):
    out = tx.sudo(f"cat {PKTGEN}/{dev}", check=False).stdout or ""
    m = re.search(r"(\d+)pps", out)
    return {"tx_pps": int(m.group(1)) if m else None, "raw": out.strip()}


# --------------------------------------------------------------------------
# measurement
# --------------------------------------------------------------------------


def measure_once(rx, iface, events, duration):
    """One perf window on RX, normalised by packets received in that window."""
    ev = ",".join(events)
    before = rx_packets(rx, iface)
    r = rx.sudo(f"perf stat -a -e {ev} -x, -- sleep {duration}")
    after = rx_packets(rx, iface)

    packets = after - before
    if packets <= 0:
        die("no packets arrived during the measurement window -- is traffic running?")

    counters = {}
    for line in r.stderr.splitlines():
        parts = line.split(",")
        if len(parts) < 3:
            continue
        value, name = parts[0], parts[2]
        if name in events and value not in ("<not counted>", "<not supported>"):
            try:
                counters[name] = float(value)
            except ValueError:
                pass

    per_pkt = {f"{k}/pkt": v / packets for k, v in counters.items()}
    if counters.get("cycles"):
        per_pkt["ipc"] = counters["instructions"] / counters["cycles"]
    per_pkt["pps"] = packets / duration

    return {"packets": packets, "raw": counters, "per_packet": per_pkt}


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
    flows = c["flows"] if c["profile"] == "hit" else "unbounded"
    print(f"  traffic   {c['profile']} profile, {c['pkt_size']}B frames, "
          f"flows={flows}, {c['repeats']}x{c['duration']}s")
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

    pa, pb = a["stats"].get("pps"), b["stats"].get("pps")
    if pa and pb and pa["median"]:
        drift = abs(pb["median"] - pa["median"]) / pa["median"] * 100
        if drift > 10:
            print(f"  WARNING: offered load differed by {drift:.0f}% between runs "
                  f"({pa['median']:,.0f} vs {pb['median']:,.0f} pps).")
            print("           Per-packet figures normalise for this, but a large drift")
            print("           can mean the two runs were not load-equivalent.\n")

    print()
    print(f"  A = {path_a}  {a.get('label') or ''}")
    print(f"  B = {path_b}  {b.get('label') or ''}")
    print(f"  profile: {a['config']['profile']}   rx: {a['platform']['host']}")
    print()
    print(f"  {'metric':<24} {'A':>12} {'B':>12} {'delta':>10}   verdict")
    print(f"  {'-'*24} {'-'*12} {'-'*12} {'-'*10}   {'-'*8}")

    for k in sorted(set(a["stats"]) | set(b["stats"])):
        sa, sb = a["stats"].get(k), b["stats"].get(k)
        if not sa or not sb or not sa["median"]:
            continue
        delta = (sb["median"] - sa["median"]) / sa["median"] * 100

        # Call it noise unless the change clears the combined run-to-run spread
        # of the two measurements.  This is the guard against reading a story
        # into a 2% wobble.
        noise = (sa["stdev"] + sb["stdev"]) / sa["median"] * 100
        if k == "pps":
            # NOT a verdict.  pps is the *offered load*, and it is only a
            # statement about the DUT if the DUT is what's saturating.  When the
            # generator is the bottleneck (common: clone_skb 0 makes pktgen
            # allocate an skb per packet), pps just reflects how fast TX felt
            # like going, and calling a 1% wobble in it "worse" would be exactly
            # the misreading the per-packet normalisation exists to prevent.
            verdict = "load"
        elif abs(delta) <= max(noise, 1.0):
            verdict = "noise"
        elif k == "ipc":
            verdict = "better" if delta > 0 else "worse"
        else:
            verdict = "better" if delta < 0 else "worse"

        print(f"  {k:<24} {fmt(sa['median']):>12} {fmt(sb['median']):>12} "
              f"{delta:>+9.1f}%   {verdict}")

    print()
    print("  'noise'  within the combined run-to-run spread of the two runs;")
    print("           collect more repeats before believing it.")
    print("  'load'   offered load, not a result. It only measures the DUT if the")
    print("           DUT is the bottleneck -- compare rx pps against tx_pps in the")
    print("           JSON: if they match, the generator was the limit, and the")
    print("           per-packet columns above are the real answer.")
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

    ap.add_argument("--rx", help="device under test (runs the XDP program)")
    ap.add_argument("--rx-iface", help="RX ingress interface")
    ap.add_argument("--rx-user")
    ap.add_argument("--rx-ip", help="RX address for pktgen (default: auto-detect)")

    ap.add_argument("--ssh-opts", default="-o BatchMode=yes -o ConnectTimeout=5")
    ap.add_argument("--dst-port", type=int, default=5201)

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
          f"[{args.profile} profile]")
    pktgen_configure(tx, args, rx_mac, dst_ip)

    runs = []
    try:
        pktgen_start(tx)
        print(f"  warming up {args.warmup}s ...")
        time.sleep(args.warmup)

        seen = rx_packets(rx, args.rx_iface)
        time.sleep(1)
        if rx_packets(rx, args.rx_iface) == seen:
            die("no traffic arriving at RX. Check cabling, that the TX interface "
                "faces RX, and that pktgen started (ssh to TX and read "
                f"{PKTGEN}/{args.tx_iface}).")

        for i in range(args.repeats):
            print(f"  measuring {i+1}/{args.repeats} ({args.duration}s) ...")
            runs.append(measure_once(rx, args.rx_iface, events, args.duration))
    finally:
        pktgen_stop(tx)

    result = {
        "label": args.label,
        "platform": platform,
        "config": {
            "profile": args.profile,
            "flows": args.flows,
            "pkt_size": args.pkt_size,
            "duration": args.duration,
            "repeats": args.repeats,
            "events": events,
        },
        "tx": pktgen_report(tx, args.tx_iface),
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
