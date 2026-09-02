// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

const SRC_XDP: &str = "src/bpf/xdp/xdp_policy.bpf.c";
const SRC_TC: &str = "src/bpf/tc/tc_policy.bpf.c";

/// Embed a build fingerprint (git sha + dirty flag + UTC build time) as
/// PE_BUILD_INFO so `policy-engine --version` and the GraphQL status query
/// can identify exactly which build is running — deployed binaries lagging
/// the source tree are otherwise painful to detect.
fn emit_build_info() {
    let run = |cmd: &str, args: &[&str]| -> Option<String> {
        std::process::Command::new(cmd)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    };

    let sha = run("git", &["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".into());
    // Untracked files don't affect the built code — only count tracked changes.
    let dirty = run("git", &["status", "--porcelain", "--untracked-files=no"])
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    let built = run("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]).unwrap_or_else(|| "unknown".into());

    println!(
        "cargo:rustc-env=PE_BUILD_INFO={}{}, built {}",
        sha,
        if dirty { "-dirty" } else { "" },
        built
    );
    // Refresh the sha when the checked-out commit changes.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
}

fn main() {
    emit_build_info();

    // OUT_DIR, not the source tree.  The skeletons are compiled with different
    // clang flags per feature (-DSURICATA_IPS below), so a single shared path
    // under src/ makes them a cross-configuration hazard: `cargo build
    // --all-features` would leave an IPS-compiled skeleton behind, and a later
    // default build — whose build-script fingerprint is still valid, so this
    // file never reruns — would link it and silently run the IPS datapath.
    // OUT_DIR is per-configuration, so each feature set gets its own.
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"));

    std::fs::create_dir_all(&out_dir).unwrap();

    let suricata = env::var("CARGO_FEATURE_SURICATA").is_ok();

    let mut args = vec![
        "-I",
        "src/bpf/include",
        "-Wno-compare-distinct-pointer-types",
        "-mllvm",
        "-unroll-threshold=500000",
    ];
    if suricata {
        args.push("-DSURICATA_IPS");
    }

    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".to_string());

    let xdp_skel = out_dir.join("xdp_policy.skel.rs");
    SkeletonBuilder::new()
        .source(SRC_XDP)
        .clang(&clang)
        .clang_args(args.clone())
        .build_and_generate(&xdp_skel)
        .expect("Failed to build XDP skeleton");

    let tc_skel = out_dir.join("tc_policy.skel.rs");
    SkeletonBuilder::new()
        .source(SRC_TC)
        .clang(&clang)
        .clang_args(args)
        .build_and_generate(&tc_skel)
        .expect("Failed to build TC skeleton");

    println!("cargo:rerun-if-changed={}", SRC_XDP);
    println!("cargo:rerun-if-changed={}", SRC_TC);
    println!("cargo:rerun-if-changed=src/bpf/xdp");
    println!("cargo:rerun-if-changed=src/bpf/tc");
    println!("cargo:rerun-if-changed=src/bpf/include");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_SURICATA");
}
