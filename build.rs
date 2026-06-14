//! Compiles the C23 bpf/ and proto/ directories into a static library
//! linked into the arwah binary.
//!
//! Requires clang >= 18 for full C23 support.

fn main() {
    let bpf_sources = ["bpf/bpf_exec.c"];

    let proto_sources = [
        "proto/eth.c",
        "proto/ip4.c",
        "proto/ip6.c",
        "proto/tcp.c",
        "proto/udp.c",
        "proto/icmp.c",
        "proto/dns.c",
        "proto/tls.c",
        "proto/checksum.c",
    ];

    cc::Build::new()
        .compiler("clang")
        .std("c23")
        .flag("-Wall")
        .flag("-Wextra")
        .flag("-Wpedantic")
        .flag("-Wformat=2")
        .flag("-Wshadow")
        .flag("-O3")
        .include("bpf")
        .include("proto")
        .files(bpf_sources)
        .files(proto_sources)
        .compile("arwah_native");

    for src in bpf_sources.iter().chain(proto_sources.iter()) {
        println!("cargo:rerun-if-changed={src}");
    }
    println!("cargo:rerun-if-changed=bpf/bpf.h");
    println!("cargo:rerun-if-changed=proto/proto.h");
    println!("cargo:rerun-if-changed=build.rs");
}
