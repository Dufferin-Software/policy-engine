use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

const SRC_XDP: &str = "src/bpf/xdp_policy.bpf.c";

fn main() {
    let out_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"),
    )
    .join("src")
    .join("bpf")
    .join(".output");

    std::fs::create_dir_all(&out_dir).unwrap();

    let xdp_skel = out_dir.join("xdp_policy.skel.rs");
    SkeletonBuilder::new()
        .source(SRC_XDP)
        .clang_args([
            "-I",
            "src/bpf/include",
            "-Wno-compare-distinct-pointer-types",
        ])
        .build_and_generate(&xdp_skel)
        .expect("Failed to build XDP skeleton");

    println!("cargo:rerun-if-changed={}", SRC_XDP);
    println!("cargo:rerun-if-changed=src/bpf/include");
}
