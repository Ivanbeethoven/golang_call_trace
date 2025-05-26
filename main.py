from bcc import BPF
import time
import sys
from datetime import datetime

# eBPF 程序代码（仅使用 tracepoint）
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(syscalls, u32, u64);  // 存储系统调用计数
BPF_PERF_OUTPUT(events);        // 用于发送事件到用户空间

struct event_t {
    u32 pid;
    u32 sysid;
    char comm[TASK_COMM_LEN];
    u64 ts;
};

// 手动定义 raw_syscalls:sys_enter 的 tracepoint 结构


// 使用 raw_syscalls:sys_enter 跟踪系统调用入口
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != TRACE_PID) {  // 只跟踪指定 PID
        return 0;
    }

    struct event_t event = {};
    event.pid = pid;
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
"""



def main():
    if len(sys.argv) != 2:
        print("Usage: python syscall_trace_tracepoint.py <pid>")
        sys.exit(1)

    pid = int(sys.argv[1])
    
    # 将要跟踪的 PID 注入到 eBPF 程序中
    bpf_text = bpf_program.replace('TRACE_PID', str(pid))
    
    # 初始化 BPF 程序，指定内核头文件路径
    try:
        bpf = BPF(text=bpf_text, cflags=["-I/lib/modules/$(uname -r)/build/include"])
    except Exception as e:
        print(f"Failed to load BPF program: {e}")
        sys.exit(1)
    
    def print_event(cpu, data, size):
        try:
            event = bpf["events"].event(data)  # 解析 perf buffer 事件
            print(f"{datetime.now().strftime('%H:%M:%S.%f')} PID: {event.pid} "
                  f"Comm: {event.comm.decode('utf-8')} "
                  f"Syscall: {event.sysid} "
                  f"Time: {event.ts}")
        except Exception as e:
            print(f"Error processing event: {e}")
    
    # 设置输出回调
    bpf["events"].open_perf_buffer(print_event)

    print("Tracing syscalls for PID %d... Hit Ctrl-C to end." % pid)
    print("Time             PID     Command         Syscall#    Timestamp")

    try:
        while True:
            bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\n\nSystem call summary:")
        for k, v in bpf["syscalls"].items():
            print(f"Syscall {k.value}: {v.value} times")

if __name__ == "__main__":
    main()