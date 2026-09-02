// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Per-packet cost of the XDP datapath, measured with BPF_PROG_TEST_RUN.
//!
//! Usage, profiles, and how to read the numbers: `scripts/bench/README.md`.

use anyhow::{bail, Context, Result};
use clap::Parser;
use policy_engine::server::BpfManager;
use policy_engine::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;

const XDP_DROP: u32 = 1;
const XDP_PASS: u32 = 2;

const PERF_TYPE_HARDWARE: u32 = 0;
const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;
const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
const PERF_EVENT_IOC_DISABLE: libc::c_ulong = 0x2401;
const PERF_EVENT_IOC_RESET: libc::c_ulong = 0x2403;

/// `struct perf_event_attr`; not in the libc crate.  `size` makes this only have
/// to be prefix-compatible with the kernel's, not an exact copy.
#[repr(C)]
#[derive(Default)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    /// Bit 0 is `disabled`.  `exclude_kernel` must stay unset: the BPF program
    /// runs in kernel context, so excluding it would count nothing.
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    config1: u64,
    config2: u64,
    branch_sample_type: u64,
    sample_regs_user: u64,
    sample_stack_user: u32,
    clockid: i32,
    sample_regs_intr: u64,
    aux_watermark: u32,
    sample_max_stack: u16,
    reserved_2: u16,
    aux_sample_size: u32,
    reserved_3: u32,
    sig_data: u64,
    config3: u64,
}

/// A hardware counter scoped to this thread (pid=0), not to a CPU:
/// `prog_test_run` runs the program in our own thread's syscall context, so this
/// counts exactly our work and nothing else landing on the same core.
struct PerfCounter {
    fd: i32,
}

impl PerfCounter {
    fn new(config: u64) -> Option<Self> {
        let mut attr = PerfEventAttr {
            type_: PERF_TYPE_HARDWARE,
            size: std::mem::size_of::<PerfEventAttr>() as u32,
            config,
            flags: 1, // start disabled
            ..Default::default()
        };
        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &mut attr as *mut PerfEventAttr,
                0,  // pid: this thread
                -1, // cpu: any (we are pinned)
                -1, // group_fd
                0,  // flags
            )
        };
        if fd < 0 {
            return None;
        }
        Some(PerfCounter { fd: fd as i32 })
    }

    fn start(&self) {
        unsafe {
            libc::ioctl(self.fd, PERF_EVENT_IOC_RESET, 0);
            libc::ioctl(self.fd, PERF_EVENT_IOC_ENABLE, 0);
        }
    }

    fn stop(&self) -> u64 {
        let mut v: u64 = 0;
        unsafe {
            libc::ioctl(self.fd, PERF_EVENT_IOC_DISABLE, 0);
            libc::read(self.fd, &mut v as *mut u64 as *mut libc::c_void, 8);
        }
        v
    }
}

impl Drop for PerfCounter {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// The counters for one measurement, if the CPU exposes them.
struct Counters {
    cycles: PerfCounter,
    instructions: PerfCounter,
}

impl Counters {
    fn open() -> Option<Self> {
        Some(Counters {
            cycles: PerfCounter::new(PERF_COUNT_HW_CPU_CYCLES)?,
            instructions: PerfCounter::new(PERF_COUNT_HW_INSTRUCTIONS)?,
        })
    }
}

/// One measured round: the three numbers, all already per-packet.
#[derive(Clone, Copy)]
struct Sample {
    ns: f64,
    cycles: f64,
    instructions: f64,
}

/// `struct xdp_md` as the kernel expects it in `ctx_in` (six u32s).  The
/// program reads `ingress_ifindex` to key its stats, FIB config and policy
/// lookups, so this cannot be left NULL -- with no context the program would
/// run against ifindex 0 and take a path no real packet takes.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct XdpMd {
    data: u32,
    data_end: u32,
    data_meta: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    egress_ifindex: u32,
}

#[derive(Parser)]
#[command(
    name = "policy-progbench",
    about = "Per-packet cost of the XDP datapath, via BPF_PROG_TEST_RUN (no NIC, no generator)"
)]
struct Args {
    /// Diff two saved results and exit (no root, no BPF).
    #[arg(long, num_args = 2, value_names = ["A.json", "B.json"])]
    compare: Option<Vec<String>>,

    /// verdict: hit the flow verdict cache (the steady-state fast path).
    /// policy: walk the LPM trie (once-per-flow cost).
    #[arg(long, default_value = "verdict")]
    profile: Profile,

    /// Threads, each pinned to its own CPU, all driving the same maps.
    #[arg(long, default_value_t = 1)]
    threads: usize,

    /// shared: all threads drive one 5-tuple (contends on the verdict entry).
    /// distinct: each thread its own (contends on the map's LRU list).
    #[arg(long, default_value = "shared")]
    flows: FlowMode,

    /// Program invocations per round.
    #[arg(long, default_value_t = 2_000_000)]
    repeat: u32,

    /// Measurement rounds within one load of the BPF object.
    #[arg(long, default_value_t = 5)]
    rounds: u32,

    /// Teardown-and-reload cycles.  Spread across these is the reported error bar.
    #[arg(long, default_value_t = 5)]
    reloads: u32,

    /// Frame size on the wire, excluding FCS.
    #[arg(long, default_value_t = 64)]
    pkt_size: usize,

    /// Decoy dst prefixes installed alongside the matching rule.
    #[arg(long, default_value_t = 64)]
    rules: u32,

    /// Interface index used as `ctx->ingress_ifindex`.  The kernel requires a
    /// real netdev here but never sends anything; 1 (lo) always exists.
    #[arg(long, default_value_t = 1)]
    ifindex: u32,

    /// First CPU to pin to.
    #[arg(long, default_value_t = 0)]
    cpu: usize,

    /// Run even if a live policy-engine has XDP attached to an interface.
    #[arg(long)]
    force: bool,

    /// Write the result as JSON.
    #[arg(short, long)]
    output: Option<String>,

    /// Free-text label stored in the result.
    #[arg(long, default_value = "")]
    label: String,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum Profile {
    Policy,
    Verdict,
}

/// Whether the threads share one flow or each get their own.  See `--flows`.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum FlowMode {
    Shared,
    Distinct,
}

impl FlowMode {
    fn as_str(&self) -> &'static str {
        match self {
            FlowMode::Shared => "shared",
            FlowMode::Distinct => "distinct",
        }
    }
}

/// The source port thread `t` sends from.  In shared mode every thread uses the
/// same one, so they collide on a single verdict-cache entry by design.
fn thread_sport(mode: FlowMode, t: usize) -> u16 {
    match mode {
        FlowMode::Shared => BENCH_SPORT,
        FlowMode::Distinct => BENCH_SPORT + t as u16,
    }
}

impl Profile {
    fn as_str(&self) -> &'static str {
        match self {
            Profile::Policy => "policy",
            Profile::Verdict => "verdict",
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Result_ {
    label: String,
    profile: String,
    /// Hash of the JITed instructions: changes iff the datapath changed, which
    /// is how a forgotten rebuild gets caught.
    prog_tag: Option<String>,
    cpu_model: Option<String>,
    kernel: Option<String>,
    config: Config,
    /// Verdict the program returned, and the stats counters it moved.  Together
    /// these prove the packet took the path the profile claims -- see
    /// `check_path`.
    /// False if the CPU exposed no hardware counter, in which case only the
    /// clock-dependent ns figures exist and every verdict is worth less.
    have_cycles: bool,
    retval: u32,
    path_evidence: PathEvidence,

    /// THE metric.  Cycles per packet, invariant to whatever the core clock is
    /// doing, which on a turbo part is a great deal.
    median_cycles: f64,
    min_cycles: f64,
    max_cycles: f64,
    stdev_cycles: f64,
    instructions: f64,
    ipc: f64,

    /// Wall time, for a sense of what the box did on the day.  Not a basis for
    /// comparing two builds -- see the note at the top of the file.
    median_ns: f64,
    stdev_ns: f64,

    /// One entry per reload (each already the median of its rounds).  The
    /// spread of *these* is the measurement's real uncertainty; the spread
    /// within a reload is not, because its rounds share maps and JIT placement.
    reload_cycles: Vec<f64>,
    reload_ns: Vec<f64>,
}

#[derive(Serialize, Deserialize)]
struct Config {
    repeat: u32,
    rounds: u32,
    reloads: u32,
    threads: usize,
    flows: String,
    pkt_size: usize,
    rules: u32,
    ifindex: u32,
    cpu: usize,
}

#[derive(Serialize, Deserialize)]
struct PathEvidence {
    rx_packets: u64,
    policy_matches: u64,
    verdict_pass_packets: u64,
    parse_errors: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(files) = &args.compare {
        return compare(&files[0], &files[1]);
    }

    // Pin before loading: the kernel runs the program on the calling CPU (it
    // only disables migration for the duration), so thread affinity is what
    // decides where the measurement lands.  XDP's test_run rejects the
    // BPF_F_TEST_RUN_ON_CPU flag, so this is the only lever there is.
    let cores = core_affinity::get_core_ids().unwrap_or_default();
    let core = cores
        .get(args.cpu)
        .with_context(|| format!("--cpu {} does not exist ({} CPUs)", args.cpu, cores.len()))?;
    if !core_affinity::set_for_current(*core) {
        bail!("could not pin the measuring thread to CPU {}", args.cpu);
    }

    // A running policy-engine shares these pins.  Loading here would reuse its
    // maps and then install bench rules into them -- corrupting the policy of a
    // box that is serving traffic.  Refuse rather than surprise.
    let attached = BpfManager::get_pinned_attachments(None);
    if !attached.is_empty() && !args.force {
        let ifaces: Vec<&str> = attached.iter().map(|(n, _, _)| n.as_str()).collect();
        bail!(
            "policy-engine has XDP attached to {} -- this bench installs its own rules \
             into the shared pinned maps and would corrupt a live policy.\n\
             Stop the service (systemctl stop policy-engine) or pass --force if you are \
             certain the box is idle.",
            ifaces.join(", ")
        );
    }

    if args.threads == 0 {
        bail!("--threads must be at least 1");
    }
    if args.cpu + args.threads > cores.len() {
        bail!(
            "--threads {} from --cpu {} needs CPUs {}..{}, but this box has {}. Threads must \
             not share a core: two threads on one CPU serialise, which is not contention, it \
             is queueing -- and it would look exactly like the contention you are hunting.",
            args.threads,
            args.cpu,
            args.cpu,
            args.cpu + args.threads - 1,
            cores.len()
        );
    }

    check_no_smt_siblings(args.cpu, args.threads)?;

    // One packet per thread.  In `--flows distinct` these differ in source
    // port, which is what puts the threads on different verdict-cache entries.
    let pkts: Vec<Vec<u8>> = (0..args.threads)
        .map(|t| build_packet(&args, thread_sport(args.flows, t)))
        .collect::<Result<_>>()?;

    let have_cycles = Counters::open().is_some();
    if !have_cycles {
        eprintln!("  WARNING: perf_event_open failed; no cycle counter, falling back to ns/pkt");
    }

    let mut reloads: Vec<Sample> = Vec::with_capacity(args.reloads as usize);
    let mut last: Option<(u32, PathEvidence, Option<String>)> = None;

    for reload in 0..args.reloads {
        // Reusing the pins would hand back the same maps at the same addresses,
        // which is one of the things a reload exists to vary.
        BpfManager::cleanup_pinned_state();

        let mut mgr = BpfManager::new().context("load BPF programs")?;
        if !mgr.xdp_loaded() {
            bail!("XDP programs did not load -- run as root (CAP_BPF + CAP_NET_ADMIN)");
        }
        install_policy(&mut mgr, &args)?;

        let prog_fd = mgr
            .xdp_main_prog()
            .expect("xdp_loaded() is true, so the skeleton is present")
            .as_raw_fd();

        // Baseline the stats, then run each thread's packet once to establish
        // the verdict (and, in the verdict profile, to let the datapath seed the
        // cache entry for that flow), then a longer warm-up so first-touch costs
        // -- map page faults, JIT warm-up -- land outside the measured rounds.
        let before = mgr.get_global_stats(args.ifindex, Direction::Ingress)?;
        let mut retval = 0;
        for pkt in &pkts {
            let (rv, _) = prog_run(prog_fd, pkt, &args, 1, None)?;
            retval = rv;
        }
        let _ = prog_run(prog_fd, &pkts[0], &args, args.repeat.min(100_000), None)?;

        let mut rounds: Vec<Sample> = Vec::with_capacity(args.rounds as usize);
        for _ in 0..args.rounds {
            rounds.push(run_round(prog_fd, &pkts, &args, &cores, retval)?);
        }

        // Median, not mean: a round that collided with a timer interrupt reads
        // 20% high (155 among 133s, in practice), and a mean would carry that
        // straight into the reload sample.
        let m = median_sample(&rounds);
        reloads.push(m);
        eprintln!(
            "  reload {}/{}: {:.1} cycles/pkt, {:.1} ns/pkt",
            reload + 1,
            args.reloads,
            m.cycles,
            m.ns
        );

        let after = mgr.get_global_stats(args.ifindex, Direction::Ingress)?;
        let evidence = PathEvidence {
            rx_packets: after.rx_packets.saturating_sub(before.rx_packets),
            policy_matches: after.policy_matches.saturating_sub(before.policy_matches),
            verdict_pass_packets: after
                .verdict_pass_packets
                .saturating_sub(before.verdict_pass_packets),
            parse_errors: after.parse_errors.saturating_sub(before.parse_errors),
        };
        last = Some((retval, evidence, prog_tag(prog_fd)));
    }

    let (retval, evidence, tag) = last.expect("--reloads is at least 1");

    let cycles: Vec<f64> = reloads.iter().map(|s| s.cycles).collect();
    let ns: Vec<f64> = reloads.iter().map(|s| s.ns).collect();
    let ipc = {
        let c = median(&cycles);
        if c > 0.0 {
            median(&reloads.iter().map(|s| s.instructions).collect::<Vec<_>>()) / c
        } else {
            0.0
        }
    };

    let result = Result_ {
        label: args.label.clone(),
        profile: args.profile.as_str().to_string(),
        prog_tag: tag,
        cpu_model: cpu_model(),
        kernel: read_trim("/proc/sys/kernel/osrelease"),
        have_cycles,
        config: Config {
            repeat: args.repeat,
            rounds: args.rounds,
            reloads: args.reloads,
            threads: args.threads,
            flows: args.flows.as_str().to_string(),
            pkt_size: args.pkt_size,
            rules: args.rules,
            ifindex: args.ifindex,
            cpu: args.cpu,
        },
        retval,
        path_evidence: evidence,
        median_cycles: median(&cycles),
        min_cycles: cycles.iter().cloned().fold(f64::MAX, f64::min),
        max_cycles: cycles.iter().cloned().fold(f64::MIN, f64::max),
        stdev_cycles: stdev(&cycles),
        instructions: median(&reloads.iter().map(|s| s.instructions).collect::<Vec<_>>()),
        ipc,
        median_ns: median(&ns),
        stdev_ns: stdev(&ns),
        reload_cycles: cycles,
        reload_ns: ns,
    };

    print_result(&result, &args);

    if let Some(path) = &args.output {
        std::fs::write(path, serde_json::to_string_pretty(&result)?)?;
        println!("  written to {path}");
        println!("  compare with: policy-progbench --compare <baseline.json> {path}\n");
    }
    Ok(())
}

/// One BPF_PROG_TEST_RUN call.  Returns (verdict, per-packet sample).
///
/// The kernel hands back `duration` already divided by `repeat`.  The cycle
/// counters bracket the whole syscall, so they also catch its entry and the
/// xdp_buff setup -- once, amortised across `repeat`.  Both are reasons to keep
/// `repeat` large.
fn prog_run(
    prog_fd: i32,
    pkt: &[u8],
    args: &Args,
    repeat: u32,
    counters: Option<&Counters>,
) -> Result<(u32, Sample)> {
    let ctx = XdpMd {
        // The kernel requires data == 0 (no metadata ahead of the packet) and
        // data_end == data_size_in; it rejects anything else.
        data: 0,
        data_end: pkt.len() as u32,
        data_meta: 0,
        ingress_ifindex: args.ifindex,
        rx_queue_index: 0,
        egress_ifindex: 0,
    };

    let mut opts: libbpf_sys::bpf_test_run_opts = unsafe { std::mem::zeroed() };
    opts.sz = std::mem::size_of::<libbpf_sys::bpf_test_run_opts>() as u64;
    opts.data_in = pkt.as_ptr() as *const _;
    opts.data_size_in = pkt.len() as u32;
    opts.ctx_in = &ctx as *const _ as *const _;
    opts.ctx_size_in = std::mem::size_of::<XdpMd>() as u32;
    opts.repeat = repeat as i32;

    if let Some(c) = counters {
        c.cycles.start();
        c.instructions.start();
    }
    let rc = unsafe { libbpf_sys::bpf_prog_test_run_opts(prog_fd, &mut opts) };
    let (cycles, instructions) = match counters {
        Some(c) => (c.cycles.stop() as f64, c.instructions.stop() as f64),
        None => (0.0, 0.0),
    };

    if rc != 0 {
        let e = std::io::Error::last_os_error();
        bail!("BPF_PROG_TEST_RUN failed: {e}");
    }
    if opts.retval == u32::MAX {
        bail!("the program returned XDP_ABORTED -- it is erroring out, not running");
    }

    let n = repeat.max(1) as f64;
    Ok((
        opts.retval,
        Sample {
            ns: opts.duration as f64,
            cycles: cycles / n,
            instructions: instructions / n,
        },
    ))
}

/// One round: every thread runs the program on its own CPU, all at once.
///
/// The threads must overlap in time or there is no contention to measure, hence
/// the barrier: without it an early thread finishes its million invocations
/// before the others arrive and each effectively runs alone.
///
/// The returned sample is the mean per-packet cost across threads.
/// Refuse a CPU set that puts two threads on the SMT siblings of one physical
/// core: siblings share execution units, so cycles/pkt roughly doubles for
/// reasons that are nothing to do with our maps, and it looks exactly like the
/// map contention being measured.  Sibling numbering is not adjacent (here CPU
/// 0 pairs with CPU 8), so the bad case is not guessable from the CPU indices.
fn check_no_smt_siblings(cpu_base: usize, threads: usize) -> Result<()> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    for t in 0..threads {
        let cpu = cpu_base + t;
        let path = format!("/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list");
        // No topology exposed (a VM, an odd arch): nothing to check, and
        // guessing would be worse than not checking.
        let Some(group) = read_trim(&path) else {
            return Ok(());
        };
        if let Some(other) = seen.insert(group.clone(), cpu) {
            bail!(
                "CPUs {other} and {cpu} are SMT siblings of the same physical core \
                 (thread_siblings_list = {group}).\n\
                 Two threads there share execution units, so cycles/pkt roughly doubles for \
                 reasons that have nothing to do with map contention -- and it looks just \
                 like the contention you are trying to measure.\n\
                 Use --threads {t} here, or pick a --cpu base whose range holds one thread \
                 per physical core.",
                t = t
            );
        }
    }
    Ok(())
}

/// `cores` MUST be the list captured before the main thread pinned itself.
/// `core_affinity::get_core_ids()` reports only the CPUs in the caller's
/// current affinity mask, so asking it again in here -- after main has pinned
/// itself to one CPU -- returns a list of length one, and every thread but the
/// first indexes off the end of it.
fn run_round(
    prog_fd: i32,
    pkts: &[Vec<u8>],
    args: &Args,
    cores: &[core_affinity::CoreId],
    expect_retval: u32,
) -> Result<Sample> {
    let n = args.threads;
    if n == 1 {
        let counters = Counters::open();
        let (rv, s) = prog_run(prog_fd, &pkts[0], args, args.repeat, counters.as_ref())?;
        check_retval(rv, expect_retval)?;
        return Ok(s);
    }

    let barrier = std::sync::Barrier::new(n);

    let samples: Vec<Result<(u32, Sample)>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..n)
            .map(|t| {
                let barrier = &barrier;
                let pkt = &pkts[t];
                let core = cores.get(args.cpu + t).copied();
                scope.spawn(move || {
                    // Pin before opening the counters: perf_event_open(pid=0)
                    // attaches to the calling thread.
                    let pinned = core.map(core_affinity::set_for_current).unwrap_or(false);
                    let counters = Counters::open();

                    // Every thread must reach the barrier, including one about
                    // to fail: bailing out before it leaves the others blocked
                    // here forever.  Carry the failure past it instead.
                    barrier.wait();

                    if !pinned {
                        bail!("could not pin thread {t} to CPU {}", args.cpu + t);
                    }
                    prog_run(prog_fd, pkt, args, args.repeat, counters.as_ref())
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| bail!("a measuring thread panicked"))
            })
            .collect()
    });

    let mut cycles = 0.0;
    let mut instructions = 0.0;
    let mut ns = 0.0;
    for r in samples {
        let (rv, s) = r?;
        check_retval(rv, expect_retval)?;
        cycles += s.cycles;
        instructions += s.instructions;
        ns += s.ns;
    }
    let n = n as f64;
    Ok(Sample {
        // Mean per-packet cost across the threads.  Each thread already
        // divided by its own `repeat`, and every thread ran the same number,
        // so the mean of the per-thread rates is the aggregate rate.
        cycles: cycles / n,
        instructions: instructions / n,
        ns: ns / n,
    })
}

fn check_retval(got: u32, expect: u32) -> Result<()> {
    if got != expect {
        bail!(
            "the program changed its verdict mid-run ({expect} then {got}) -- the packet or a \
             map is being mutated between rounds, so these numbers mean nothing"
        );
    }
    Ok(())
}

/// Field-wise median across rounds.  Each field is medianed independently:
/// they are three views of the same work, and taking "the round with the median
/// cycles" would let one interrupted round veto the others' ns.
fn median_sample(rounds: &[Sample]) -> Sample {
    Sample {
        ns: median(&rounds.iter().map(|s| s.ns).collect::<Vec<_>>()),
        cycles: median(&rounds.iter().map(|s| s.cycles).collect::<Vec<_>>()),
        instructions: median(&rounds.iter().map(|s| s.instructions).collect::<Vec<_>>()),
    }
}

/// Build the Ethernet/IPv4/UDP frame a thread replays.  `sport` is what
/// separates one thread's flow from another's in `--flows distinct`.
fn build_packet(args: &Args, sport: u16) -> Result<Vec<u8>> {
    const MIN: usize = 14 + 20 + 8;
    if args.pkt_size < MIN {
        bail!("--pkt-size must be at least {MIN} (eth + ipv4 + udp)");
    }
    let mut p = vec![0u8; args.pkt_size];

    // Ethernet: unicast both ways, so the program does not classify it as BUM.
    p[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x01]); // dst
    p[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x02]); // src
    p[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4

    let ip_len = (args.pkt_size - 14) as u16;
    p[14] = 0x45; // v4, IHL 5
    p[16..18].copy_from_slice(&ip_len.to_be_bytes());
    p[22] = 64; // TTL
    p[23] = 17; // UDP
    p[26..30].copy_from_slice(&bench_src().octets());
    p[30..34].copy_from_slice(&bench_dst().octets());
    let csum = ipv4_checksum(&p[14..34]);
    p[24..26].copy_from_slice(&csum.to_be_bytes());

    let udp_len = (args.pkt_size - 34) as u16;
    p[34..36].copy_from_slice(&sport.to_be_bytes());
    p[36..38].copy_from_slice(&BENCH_DPORT.to_be_bytes());
    p[38..40].copy_from_slice(&udp_len.to_be_bytes());
    // UDP checksum 0 = not computed, which is legal for IPv4 and is what the
    // datapath sees from plenty of real senders.

    Ok(p)
}

fn ipv4_checksum(hdr: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for pair in hdr.chunks(2) {
        sum += u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

const BENCH_SPORT: u16 = 12345;
const BENCH_DPORT: u16 = 5201;
fn bench_src() -> Ipv4Addr {
    Ipv4Addr::new(10, 1, 2, 3)
}
fn bench_dst() -> Ipv4Addr {
    Ipv4Addr::new(192, 168, 200, 10)
}

/// The verdict-cache key for the flow the bench replays.
fn bench_verdict_key(ifindex: u32) -> FlowVerdictKey {
    let mut key = FlowVerdictKey {
        sport: BENCH_SPORT,
        dport: BENCH_DPORT,
        protocol: libc::IPPROTO_UDP as u8,
        af: AF_INET,
        ifindex,
        ..Default::default()
    };
    key.saddr[0..4].copy_from_slice(&bench_src().octets());
    key.daddr[0..4].copy_from_slice(&bench_dst().octets());
    key
}

/// Install the policy the packet is measured against.  The action on the
/// matching rule is what selects the profile -- see the `match` below.
fn install_policy(mgr: &mut BpfManager, args: &Args) -> Result<()> {
    mgr.set_default_action(PolicyAction::Pass, Direction::Ingress, args.ifindex)?;

    let src_key = SrcLpmKeyV4::new(args.ifindex, Ipv4Addr::new(10, 0, 0, 0), 8);

    // Decoys first, so the matching rule is not simply the trie's only leaf.
    for i in 0..args.rules {
        let dst = Ipv4Addr::new(192, 168, (i % 200) as u8, 0);
        let dst_key = LpmKeyV4::new(dst, 24);
        let mut rule = L4Rule {
            protocol: libc::IPPROTO_UDP as u8,
            dport: BENCH_DPORT,
            rule_id: 1000 + i as u64,
            ..Default::default()
        };
        rule.set_actions(&[(PolicyAction::Pass, 0, ActionParams::None)]);
        mgr.add_policy_rule_v4(&src_key, &dst_key, &rule, Direction::Ingress)?;
    }

    // The rule the bench packet actually matches.
    let dst_key = LpmKeyV4::new(bench_dst(), 24);
    let mut rule = L4Rule {
        protocol: libc::IPPROTO_UDP as u8,
        dport: BENCH_DPORT,
        rule_id: BENCH_RULE_ID,
        ..Default::default()
    };
    match args.profile {
        // A pure PASS rule is cacheable, so the datapath seeds the verdict cache
        // itself and every packet after the first hits it.
        Profile::Verdict => {
            rule.set_actions(&[(PolicyAction::Pass, 0, ActionParams::None)]);
        }
        // A LOG action clears the datapath's `cacheable` flag (actions.h), so
        // the flow is never cached and every packet re-walks the LPM.  That is
        // the only way to make a once-per-flow cost repeat: there is no runtime
        // switch to disable the verdict cache.  LOG's own cost (a rule_stats
        // lookup and a timestamp compare; the rate limit keeps it off the
        // ringbuf) is in the absolute number, but identical in both halves of
        // an A/B.
        Profile::Policy => {
            rule.set_actions(&[
                (
                    PolicyAction::Log,
                    0,
                    ActionParams::Log {
                        rate_limit_ns: 1_000_000_000,
                    },
                ),
                (PolicyAction::Pass, 1, ActionParams::None),
            ]);
        }
    }
    mgr.add_policy_rule_v4(&src_key, &dst_key, &rule, Direction::Ingress)?;

    // Pins outlive the process, and a policy-seeded verdict never expires
    // (POLICY_VERDICT_EXPIRES_NS == 0), so a stale one would sit here
    // short-circuiting the very LPM walk the policy profile measures.
    let key = bench_verdict_key(args.ifindex);
    let _ = mgr.delete_flow_verdict(&key, Direction::Ingress);

    Ok(())
}

const BENCH_RULE_ID: u64 = 9_999;

/// Did the packet take the path the profile claims?
///
/// This is the guard against the most expensive kind of wrong answer: a rule
/// that silently failed to match, or a verdict that was not seeded, leaves the
/// program running a *different* path very fast and every number below looks
/// like a triumph.  The stats counters the program itself bumped are the only
/// witness that cannot be talked into agreeing with us.
fn check_path(res: &Result_) -> Vec<String> {
    let mut problems = Vec::new();
    let e = &res.path_evidence;

    if e.rx_packets == 0 {
        problems.push("rx_packets = 0".into());
    }
    if e.parse_errors > 0 {
        problems.push(format!(
            "parse_errors = {} (malformed packet)",
            e.parse_errors
        ));
    }
    // A counter being merely non-zero proves very little: under replay the
    // *first* packet of the run always walks the policy path, so `policy_matches
    // == 1` is consistent with a million cache hits.  Insist that the counter
    // for the claimed path accounts for essentially all the traffic.
    let nearly_all = e.rx_packets.saturating_sub(e.rx_packets / 100).max(1);

    match res.profile.as_str() {
        "verdict" => {
            if e.verdict_pass_packets < nearly_all {
                problems.push(format!(
                    "only {} of {} packets hit the verdict cache (measured the policy path)",
                    e.verdict_pass_packets, e.rx_packets
                ));
            }
        }
        "policy" => {
            if e.verdict_pass_packets > 0 {
                problems.push(format!(
                    "{} packets hit the verdict cache (measured the cache hit, not the LPM walk)",
                    e.verdict_pass_packets
                ));
            }
            if e.policy_matches < nearly_all {
                problems.push(format!(
                    "only {} of {} packets matched a rule (rest hit the default action)",
                    e.policy_matches, e.rx_packets
                ));
            }
        }
        _ => {}
    }
    problems
}

fn print_result(res: &Result_, args: &Args) {
    let verdict = match res.retval {
        XDP_PASS => "XDP_PASS",
        XDP_DROP => "XDP_DROP",
        other => return println!("  unexpected verdict {other}"),
    };
    println!();
    println!(
        "  cpu       {} (pinned to CPU {})",
        res.cpu_model.as_deref().unwrap_or("unknown"),
        args.cpu
    );
    println!("  kernel    {}", res.kernel.as_deref().unwrap_or("unknown"));
    println!(
        "  datapath  xdp_policy_main tag={}",
        res.prog_tag.as_deref().unwrap_or("unknown")
    );
    println!(
        "  traffic   {} profile, {}B frame, {} rules",
        res.profile, res.config.pkt_size, res.config.rules
    );
    println!(
        "  threads   {} (CPUs {}..{}), {} flow(s)",
        res.config.threads,
        res.config.cpu,
        res.config.cpu + res.config.threads - 1,
        res.config.flows
    );
    println!(
        "  sampling  {} reloads x {} rounds x {} invocations/thread",
        res.config.reloads, res.config.rounds, res.config.repeat
    );
    println!("  verdict   {verdict}");
    println!();
    println!(
        "  {:<20} {:>10} {:>10} {:>10} {:>8}",
        "metric", "median", "min", "max", "spread"
    );
    println!(
        "  {:-<20} {:->10} {:->10} {:->10} {:->8}",
        "", "", "", "", ""
    );
    let pct = |s: f64, m: f64| if m > 0.0 { s / m * 100.0 } else { 0.0 };
    if res.have_cycles {
        println!(
            "  {:<20} {:>10.1} {:>10.1} {:>10.1} {:>7.1}%",
            "cycles/pkt",
            res.median_cycles,
            res.min_cycles,
            res.max_cycles,
            pct(res.stdev_cycles, res.median_cycles)
        );
        println!("  {:<20} {:>10.1}", "instructions/pkt", res.instructions);
        println!("  {:<20} {:>10.2}", "ipc", res.ipc);
    }
    println!(
        "  {:<20} {:>10.1} {:>10} {:>10} {:>7.1}%",
        "ns/pkt",
        res.median_ns,
        "",
        "",
        pct(res.stdev_ns, res.median_ns)
    );
    println!();

    let problems = check_path(res);
    if problems.is_empty() {
        println!(
            "  path      confirmed: {} rx, {} policy match(es), {} verdict-cache hit(s)",
            res.path_evidence.rx_packets,
            res.path_evidence.policy_matches,
            res.path_evidence.verdict_pass_packets
        );
    } else {
        println!("  path      WRONG PATH:");
        for p in &problems {
            println!("            - {p}");
        }
    }
    println!();
}

fn compare(path_a: &str, path_b: &str) -> Result<()> {
    let a: Result_ = serde_json::from_str(&std::fs::read_to_string(path_a)?)
        .with_context(|| format!("parse {path_a}"))?;
    let b: Result_ = serde_json::from_str(&std::fs::read_to_string(path_b)?)
        .with_context(|| format!("parse {path_b}"))?;

    if a.profile != b.profile {
        bail!(
            "refusing to compare different profiles ({} vs {}) -- they measure different \
             code paths",
            a.profile,
            b.profile
        );
    }
    // Contention is a function of how many CPUs are pounding the map and whether
    // they share a flow.  Two runs at different settings are two different
    // experiments, and a "win" between them is just the settings.
    if a.config.threads != b.config.threads || a.config.flows != b.config.flows {
        bail!(
            "refusing to compare different contention setups (A: {} thread(s), {} flows; \
             B: {} thread(s), {} flows) -- contention IS the thing being measured, so a \
             delta between these two says nothing about the code",
            a.config.threads,
            a.config.flows,
            b.config.threads,
            b.config.flows
        );
    }
    println!();
    println!("  A = {path_a}  {}", a.label);
    println!("  B = {path_b}  {}", b.label);
    println!("  profile: {}", a.profile);

    if a.cpu_model != b.cpu_model {
        println!(
            "  WARNING: different CPUs (A: {:?}, B: {:?})",
            a.cpu_model, b.cpu_model
        );
    }
    // Forgetting to rebuild between runs yields a flawlessly precise comparison
    // of one build against itself, and every column then reads "noise".
    if a.prog_tag.is_some() && a.prog_tag == b.prog_tag {
        println!(
            "  WARNING: A and B are the same program (tag {}); rebuild and re-run B",
            a.prog_tag.as_deref().unwrap_or("?")
        );
    }
    for (name, res) in [("A", &a), ("B", &b)] {
        for p in check_path(res) {
            println!("  WARNING: {name} wrong path: {p}");
        }
    }
    if !a.have_cycles || !b.have_cycles {
        println!("  WARNING: no cycle counter in at least one run; verdict rests on ns/pkt");
    }
    println!();

    println!(
        "  {:<20} {:>10} {:>10} {:>10}   verdict",
        "metric", "A", "B", "delta"
    );
    println!(
        "  {:-<20} {:->10} {:->10} {:->10}   {:-<8}",
        "", "", "", "", ""
    );

    // Noise floor: the combined reload-to-reload spread of the two runs.  A
    // delta that does not clear it is not a result, however much we would like
    // it to be.  The 1% floor covers the case where both runs were unusually
    // steady and the spread collapses to near zero.
    let call = |m_a: f64, s_a: f64, m_b: f64, s_b: f64| -> (f64, &'static str) {
        let delta = (m_b - m_a) / m_a * 100.0;
        let noise = (s_a + s_b) / m_a * 100.0;
        let v = if delta.abs() <= noise.max(1.0) {
            "noise"
        } else if delta < 0.0 {
            "better"
        } else {
            "worse"
        };
        (delta, v)
    };

    if a.have_cycles && b.have_cycles {
        let (d, v) = call(
            a.median_cycles,
            a.stdev_cycles,
            b.median_cycles,
            b.stdev_cycles,
        );
        println!(
            "  {:<20} {:>10.1} {:>10.1} {:>+9.1}%   {}",
            "cycles/pkt", a.median_cycles, b.median_cycles, d, v
        );
        let (d, _) = call(a.instructions, 0.0, b.instructions, 0.0);
        println!(
            "  {:<20} {:>10.1} {:>10.1} {:>+9.1}%",
            "instructions/pkt", a.instructions, b.instructions, d
        );
        println!("  {:<20} {:>10.2} {:>10.2}", "ipc", a.ipc, b.ipc);
    }

    // ns is shown but never used to call a winner when cycles exist: it moves
    // with the clock, and the clock moves with whatever else the box was doing.
    let (d, v) = call(a.median_ns, a.stdev_ns, b.median_ns, b.stdev_ns);
    println!(
        "  {:<20} {:>10.1} {:>10.1} {:>+9.1}%   {}",
        "ns/pkt",
        a.median_ns,
        b.median_ns,
        d,
        if a.have_cycles && b.have_cycles {
            "informational"
        } else {
            v
        }
    );

    println!();
    Ok(())
}

// --------------------------------------------------------------------------
// platform facts, so a number from one box can be read honestly against another
// --------------------------------------------------------------------------

fn read_trim(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn cpu_model() -> Option<String> {
    let info = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    info.lines()
        .find(|l| l.starts_with("model name"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
}

/// The JIT'd program's tag, straight from the kernel via bpf_obj_get_info_by_fd.
fn prog_tag(prog_fd: i32) -> Option<String> {
    let mut info: libbpf_sys::bpf_prog_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libbpf_sys::bpf_prog_info>() as u32;
    let rc = unsafe {
        libbpf_sys::bpf_obj_get_info_by_fd(prog_fd, &mut info as *mut _ as *mut _, &mut len)
    };
    if rc != 0 {
        return None;
    }
    Some(info.tag.iter().map(|b| format!("{b:02x}")).collect())
}

fn median(v: &[f64]) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = s.len();
    if n == 0 {
        return 0.0;
    }
    if n.is_multiple_of(2) {
        (s[n / 2 - 1] + s[n / 2]) / 2.0
    } else {
        s[n / 2]
    }
}

fn stdev(v: &[f64]) -> f64 {
    if v.len() < 2 {
        return 0.0;
    }
    let mean = v.iter().sum::<f64>() / v.len() as f64;
    let var = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (v.len() - 1) as f64;
    var.sqrt()
}

// --------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Result_` with the shape of a healthy run, for the path checks to
    /// pick apart.  Only the fields `check_path` reads are meaningful.
    fn result(profile: &str, e: PathEvidence) -> Result_ {
        Result_ {
            label: String::new(),
            profile: profile.into(),
            prog_tag: None,
            cpu_model: None,
            kernel: None,
            have_cycles: true,
            config: Config {
                repeat: 1,
                rounds: 1,
                reloads: 1,
                threads: 1,
                flows: "shared".into(),
                pkt_size: 64,
                rules: 0,
                ifindex: 1,
                cpu: 0,
            },
            retval: XDP_PASS,
            path_evidence: e,
            median_cycles: 600.0,
            min_cycles: 600.0,
            max_cycles: 600.0,
            stdev_cycles: 1.0,
            instructions: 2000.0,
            ipc: 3.3,
            median_ns: 130.0,
            stdev_ns: 1.0,
            reload_cycles: vec![600.0],
            reload_ns: vec![130.0],
        }
    }

    fn args(pkt_size: usize) -> Args {
        Args {
            compare: None,
            profile: Profile::Policy,
            threads: 1,
            flows: FlowMode::Shared,
            repeat: 1,
            rounds: 1,
            reloads: 1,
            pkt_size,
            rules: 0,
            ifindex: 1,
            cpu: 0,
            force: false,
            output: None,
            label: String::new(),
        }
    }

    #[test]
    fn packet_is_a_well_formed_ipv4_udp_frame() {
        let p = build_packet(&args(64), BENCH_SPORT).unwrap();
        assert_eq!(p.len(), 64);
        assert_eq!(&p[12..14], &[0x08, 0x00], "ethertype must be IPv4");
        assert_eq!(p[14] >> 4, 4, "IP version");
        assert_eq!(p[14] & 0x0f, 5, "IHL, in 32-bit words");
        assert_eq!(p[23], 17, "protocol must be UDP");
        assert_eq!(u16::from_be_bytes([p[16], p[17]]), 50, "IP total length");
        assert_eq!(u16::from_be_bytes([p[34], p[35]]), BENCH_SPORT);
        assert_eq!(u16::from_be_bytes([p[36], p[37]]), BENCH_DPORT);
        assert_eq!(&p[26..30], &bench_src().octets());
        assert_eq!(&p[30..34], &bench_dst().octets());
    }

    /// A frame the datapath rejects would send it down the parse-error path and
    /// every number would describe that instead, so the header has to be right.
    /// Checksumming the header *including* its own checksum field yields 0 iff
    /// the checksum is correct.
    #[test]
    fn ipv4_checksum_verifies() {
        let p = build_packet(&args(64), BENCH_SPORT).unwrap();
        assert_eq!(ipv4_checksum(&p[14..34]), 0);
    }

    #[test]
    fn packet_smaller_than_the_headers_is_refused() {
        assert!(build_packet(&args(41), BENCH_SPORT).is_err());
        assert!(build_packet(&args(42), BENCH_SPORT).is_ok());
    }

    #[test]
    fn healthy_runs_report_no_problems() {
        let policy = result(
            "policy",
            PathEvidence {
                rx_packets: 1000,
                policy_matches: 1000,
                verdict_pass_packets: 0,
                parse_errors: 0,
            },
        );
        assert!(check_path(&policy).is_empty());

        let verdict = result(
            "verdict",
            PathEvidence {
                rx_packets: 1000,
                policy_matches: 1000,
                verdict_pass_packets: 1000,
                parse_errors: 0,
            },
        );
        assert!(check_path(&verdict).is_empty());
    }

    /// The failure this whole guard exists for: a cached verdict short-circuits
    /// the LPM walk, so the policy profile silently measures the cache hit and
    /// reports a spectacular improvement that is really a different code path.
    #[test]
    fn policy_profile_rejects_a_flow_served_from_the_verdict_cache() {
        let r = result(
            "policy",
            PathEvidence {
                rx_packets: 1000,
                policy_matches: 1000,
                verdict_pass_packets: 999,
                parse_errors: 0,
            },
        );
        let problems = check_path(&r);
        assert!(!problems.is_empty());
        assert!(problems.iter().any(|p| p.contains("verdict cache")));
    }

    /// A single policy match among a million packets means the first packet
    /// walked the trie and the rest were cached -- the counter is non-zero, and
    /// non-zero is exactly the check that would wave this through.
    #[test]
    fn verdict_profile_rejects_a_barely_used_cache() {
        let r = result(
            "verdict",
            PathEvidence {
                rx_packets: 1_000_000,
                policy_matches: 1_000_000,
                verdict_pass_packets: 1,
                parse_errors: 0,
            },
        );
        assert!(!check_path(&r).is_empty());
    }

    #[test]
    fn parse_errors_invalidate_the_run() {
        let r = result(
            "policy",
            PathEvidence {
                rx_packets: 1000,
                policy_matches: 1000,
                verdict_pass_packets: 0,
                parse_errors: 3,
            },
        );
        assert!(check_path(&r).iter().any(|p| p.contains("parse_errors")));
    }

    #[test]
    fn median_and_stdev() {
        assert_eq!(median(&[3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median(&[4.0, 1.0, 3.0, 2.0]), 2.5);
        assert_eq!(median(&[]), 0.0);
        assert_eq!(stdev(&[5.0]), 0.0);
        assert!((stdev(&[2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]) - 2.138).abs() < 0.01);
    }

    /// An interrupted round reads high in every column at once.  Medianing the
    /// fields independently keeps that round from dragging the sample, and it
    /// must not smear across fields either.
    #[test]
    fn median_sample_is_field_wise() {
        let rounds = [
            Sample {
                ns: 130.0,
                cycles: 600.0,
                instructions: 2000.0,
            },
            Sample {
                ns: 131.0,
                cycles: 610.0,
                instructions: 2001.0,
            },
            Sample {
                ns: 200.0,
                cycles: 900.0,
                instructions: 2002.0,
            },
        ];
        let m = median_sample(&rounds);
        assert_eq!(m.ns, 131.0);
        assert_eq!(m.cycles, 610.0);
        assert_eq!(m.instructions, 2001.0);
    }
}
