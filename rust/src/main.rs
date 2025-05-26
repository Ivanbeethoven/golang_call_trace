use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder}, Link, PerfBufferBuilder 
};
use libc::{rlimit, RLIMIT_MEMLOCK, setrlimit, RLIM_INFINITY};
use std::{
    ffi::CStr, io::Error, path::Path, sync::{atomic::{AtomicBool, Ordering}, Arc}, time::{Duration, SystemTime, UNIX_EPOCH}
};
mod trace_skel;
use goblin::elf::Elf;
use std::fs::File;
use std::io::Read;


fn bump_memlock_rlimit() -> Result<(), Error> {
    // struct rlimit { rlim_cur, rlim_max }
    let lim = rlimit {
        rlim_cur: RLIM_INFINITY,
        rlim_max: RLIM_INFINITY,
    };
    let ret = unsafe { setrlimit(RLIMIT_MEMLOCK, &lim) };
    if ret != 0 {
        Err(Error::last_os_error())
    } else {
        Ok(())
    }
}


// 严格对齐C结构体，使用packed确保无填充
#[repr(C, packed)]
#[derive(Debug)]
struct Event {
    goid: u64,
    tid: u32,
    syscall_id: i32,
    comm: [u8; 16],
    filename: [u8; 256],
    timestamp: u64,
}

// 安全转换封装
struct SafeEvent<'a>(&'a Event);

impl<'a> SafeEvent<'a> {
    fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < std::mem::size_of::<Event>() {
            return None;
        }
        Some(unsafe { Self(&*(data.as_ptr() as *const Event)) })
    }

    fn comm(&self) -> String {
        CStr::from_bytes_until_nul(&self.0.comm)
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "[BAD_COMM]".into())
    }

    fn filename(&self) -> String {
        CStr::from_bytes_until_nul(&self.0.filename)
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "[BAD_FILENAME]".into())
    }

    fn timestamp(&self) -> String {
        let nanos = self.0.timestamp;
        let duration = UNIX_EPOCH + Duration::from_nanos(nanos);
        SystemTime::now()
            .duration_since(duration)
            .map(|d| format!("+{:.3}s", d.as_secs_f64()))
            .unwrap_or_else(|_| "[INVALID_TIME]".into())
    }
}

fn print_event(cpu: i32, data: &[u8]) {
    let Some(event) = SafeEvent::parse(data) else {
        eprintln!("Invalid event data (len={})", data.len());
        return;
    };

    let tid = event.0.tid;
    let goid = event.0.goid;
    println!(
        "[{:<8}] CPU#{:<2} G#{:<6} TID:{:<5} {:12} → {}",
        event.timestamp(),
        cpu,
        goid,
        tid,
        event.comm(),
        event.filename()
    );
}

// 增强错误处理
fn attach_uprobe(
    skel: &mut trace_skel::GotraceSkel,
    prog_name: &str,
    bin_path: &Path,
    symbol: &str,
) -> Result<Link, Box<dyn std::error::Error>> {
    // 1. 查找BPF程序
    let prog = skel.object_mut()
        .progs_iter_mut()
        .find(|p| p.name() == prog_name)
        .ok_or_else(|| format!("Program {} not found", prog_name))?;
    // 2. 解析目标二进制获取符号地址
    let mut file = File::open(bin_path)
        .map_err(|e| format!("Open {} failed: {}", bin_path.display(), e))?;
    
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|e| format!("Read {} failed: {}", bin_path.display(), e))?;
    let elf = Elf::parse(&buffer)
        .map_err(|e| format!("Parse ELF failed: {}", e))?;

    let sym_addr = elf.syms.iter()
        .find(|sym| elf.strtab.get_at(sym.st_name).unwrap() == symbol)
        .map(|sym| sym.st_value)
        .ok_or_else(|| format!("Symbol {} not found", symbol))?;
    // 3. 规范化路径并附加uprobe
    let abs_path = bin_path.canonicalize()
        .map_err(|e| format!("Canonicalize failed: {}", e))?;
    // 4. 创建并返回Link对象
    prog.attach_uprobe(
        false,   // 非retprobe
        -1,      // 所有进程
        abs_path,
        sym_addr as usize // 使用实际符号地址
    ).map_err(|e| format!("Attach {} failed: {}", prog_name, e).into())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    bump_memlock_rlimit().expect("failed to increase RLIMIT_MEMLOCK");


    let go_bin = Path::new("../main");
    
    // 预检二进制文件
    if !go_bin.exists() {
        return Err("Target Go binary not found".into());
    }

    // 初始化BPF骨架
    let builder = trace_skel::GotraceSkelBuilder::default();

    let open = builder.open()?;
    let mut skel = open.load()?;


    // 附加探针（保存Link对象）
    let mut links = Vec::new();
    links.push(attach_uprobe(&mut skel, "trace_execute", go_bin, "runtime.execute")?);
    links.push(attach_uprobe(&mut skel, "trace_goexit", go_bin, "runtime.goexit")?);

    // 初始化事件通道（正确访问maps字段）
    let perf = PerfBufferBuilder::new(&skel.maps().events()) // 去除非法括号
        .sample_cb(print_event)
        .lost_cb(|cpu, count| eprintln!("Lost {} events on CPU {}", count, cpu))
        .build()?;

    // 信号处理
    let running = Arc::new(AtomicBool::new(true));
    ctrlc::set_handler({
        let r = Arc::clone(&running);
        move || r.store(false, Ordering::SeqCst)
    })?;

    println!("Monitoring Go syscalls (Ctrl-C to stop)");
    while running.load(Ordering::SeqCst) {
        perf.poll(Duration::from_millis(100))?;
    }

    println!("\nDetaching probes...");
    Ok(())
}
