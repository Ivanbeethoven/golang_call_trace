use libbpf_cargo::SkeletonBuilder;

fn main() {
    SkeletonBuilder::new()
        .source("src/bpf/gotrace.bpf.c")
        .clang_args(
            String::from("-I./src/bpf -I/usr/include ") +
            &format!("-I/lib/modules/{}/build", std::env::var("KERNEL_RELEASE").unwrap_or_else(|_| String::from_utf8_lossy(&std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default().into_bytes()).trim().to_string()))
        )
        .build_and_generate("src/trace_skel.rs")
        .unwrap();
}
