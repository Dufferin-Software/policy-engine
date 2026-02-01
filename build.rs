// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

const SRC_XDP: &str = "src/bpf/xdp/xdp_policy.bpf.c";
const SRC_TC: &str = "src/bpf/tc/tc_policy.bpf.c";

fn main() {
    let out_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"))
            .join("src")
            .join("bpf")
            .join(".output");

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
