from bcc import BPF
import time
import sys
from datetime import datetime

# eBPF 程序代码（使用 tracepoint）
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(syscalls, u32, u64);  // 存储系统调用计数
BPF_PERF_OUTPUT(events);        // 用于发送事件到用户空间

struct event_t {
    u32 pid;    // 进程 ID (TGID)
    u32 tid;    // 线程 ID (TID)
    u32 sysid;  // 系统调用号
    char comm[TASK_COMM_LEN];  // 进程名称
    u64 ts;     // 时间戳
};



// 使用 raw_syscalls:sys_enter 跟踪系统调用入口
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;  // 提取 TGID (进程 ID)
    u32 tid = pid_tgid;        // 提取 TID (线程 ID)

    struct event_t event = {};
    event.pid = pid;
    event.tid = tid;
    event.sysid = args->id;  // 从 tracepoint 参数获取系统调用 ID
    event.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    events.perf_submit(args, &event, sizeof(event));

    // 更新系统调用计数
    u64 *count = syscalls.lookup(&event.sysid);
    if (count) {
        (*count)++;
    } else {
        u64 one = 1;
        syscalls.update(&event.sysid, &one);
    }

    return 0;
}

int probe_hello(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    bpf_trace_printk("HELLO called by PID %d\\n", pid);
    return 0;
}
"""

def main():
    if len(sys.argv) != 2:
        print("Usage: python syscall_trace.py")
        sys.exit(1)

    pid = int(sys.argv[1])    

    # 初始化 BPF 程序，指定内核头文件路径
    try:
        bpf = BPF(text=bpf_program, cflags=["-I/lib/modules/$(uname -r)/build/include"])
        bpf.attach_uprobe(name="probe_hello", sym="probe_hello", pid=-1,)
    except Exception as e:
        print(f"Failed to load BPF program: {e}")
        sys.exit(1)
    
    # 定义回调函数，确保 bpf 在作用域内
    def print_event(cpu, data, size):
        try:
            event = bpf["events"].event(data)  # 解析 perf buffer 事件
            print(f"{datetime.now().strftime('%H:%M:%S.%f')} "
                  f"PID: {event.pid} TID: {event.tid} "
                  f"Comm: {event.comm.decode('utf-8')} "
                  f"Syscall: {event.sysid} "
                  f"Time: {event.ts}")
        except Exception as e:
            print(f"Error processing event: {e}")

    # 设置输出回调
    try:
        bpf["events"].open_perf_buffer(print_event)
    except Exception as e:
        print(f"Failed to open perf buffer: {e}")
        sys.exit(1)

    print("Tracing syscalls for PID %d... Hit Ctrl-C to end." % pid)
    print("Time             PID     TID     Command         Syscall#    Timestamp")

    try:
        while True:
            bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\n\nSystem call summary:")
        for k, v in bpf["syscalls"].items():
            print(f"Syscall {k.value}: {v.value} times")

if __name__ == "__main__":
    main()