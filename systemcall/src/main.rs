// src/main.rs
mod trace_skel;

use libbpf_rs::skel::{SkelBuilder, OpenSkel, Skel};
use libbpf_rs::PerfBufferBuilder;
use libbpf_sys::bpf_map_update_elem;
use std::{env, mem::MaybeUninit, time::Duration};
use std::ffi::CStr;

const BPF_ANY: u64 = 0;

#[repr(C)]
struct Event {
    ts: u64,
    pid: u32,
    tid: u32,
    syscall_id: i64,
    comm: [u8; 16],
}

fn handle_event(_cpu: i32, data: &[u8]) {
    let evt = unsafe { &*(data.as_ptr() as *const Event) };
    let comm = CStr::from_bytes_until_nul(&evt.comm).unwrap_or_default();
    println!(
        "[{}] {} (TID {}) → syscall {}",
        evt.ts,
        comm.to_string_lossy(),
        evt.tid,
        evt.syscall_id
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1) 从命令行读取要跟踪的 PID
    let pid: u32 = env::args()
        .nth(1)
        .expect("Usage: trace_syscalls_rust <PID>")
        .parse()?;
    eprintln!("🔍 Tracing PID={} syscalls…", pid);

    // 2) open skeleton（传入 MaybeUninit）
    let mut builder = trace_skel::SystemcallSkelBuilder::default();
    let mut skel_uninit = MaybeUninit::uninit();
    let mut skel = builder.open(&mut skel_uninit)?;

    // 3) load BPF bytecode
    skel.load()?;

    // 4) runtime 写入 PID 到 filter_pid map
    let key: u32 = 0;
    let fd = skel.maps.filter_pid.set_initial_value(pid);
    

    // 5) attach all programs
    //skel.attach()?;



    // 7) 事件轮询
    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
