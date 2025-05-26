// build.rs
use libbpf_cargo::SkeletonBuilder;
use std::process::Command;

fn main() {
    // 获取内核源路径
    let kernel_release = String::from_utf8(
        Command::new("uname").arg("-r").output().unwrap().stdout
    ).unwrap().trim().to_owned();
    let kdir = format!("/usr/lib/modules/{}/build", kernel_release);

    SkeletonBuilder::new()
        .source("src/bpf/systemcall.bpf.c")
        .clang_args([
            "-I./src/bpf" ,
            &format!("-I{}/include", kdir),
        ].as_slice())
        .build_and_generate("src/trace_skel.rs")
        .unwrap();
}
