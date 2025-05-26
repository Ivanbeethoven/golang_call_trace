from bcc import BPF
import time
import sys
from datetime import datetime

# eBPF 程序代码（使用 tracepoint）
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

int probe_hello(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid & 0xFFFFFFFF;
    bpf_trace_printk("HELLO called by PID %d, TID %d\\n", pid, tid);
    return 0;
}
"""

def main():
 
    binary_path = "/home/luxian/github/golang_call_trace/hello_bin"
    # 初始化 BPF 程序，指定内核头文件路径
    try:
        bpf = BPF(text=bpf_program, cflags=["-I/lib/modules/$(uname -r)/build/include"])
        
        bpf.attach_uprobe(name=binary_path, sym="main.hello",
                  fn_name="probe_hello", pid=-1)
    except Exception as e:
        print(f"Failed to load BPF program: {e}")
        sys.exit(1)
        
    try:
        while True:
            (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
            print(f"{ts} {msg}")
    except KeyboardInterrupt:
        print("Detaching...")

if __name__ == "__main__":
    main()