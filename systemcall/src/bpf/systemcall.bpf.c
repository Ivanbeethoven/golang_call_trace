// bpf/trace_syscalls.bpf.c
#include "vmlinux.h"            // 从 BTF 生成，提供 trace_event_raw_sys_enter 定义
#include <bpf/bpf_helpers.h>    // bpf_* 辅助函数

struct event_t {
    u64 ts;
    u32 pid;
    u32 tid;
    u64 syscall_id;
    char comm[16];             // TASK_COMM_LEN == 16
};

// 运行时写入的过滤 PID
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} filter_pid SEC(".maps");

// 输出事件
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 key = 0;

    // 读取用户态写入的目标 PID
    u32 *target = bpf_map_lookup_elem(&filter_pid, &key);
    if (!target || pid != *target)
        return 0;

    struct event_t evt = {};
    evt.ts         = bpf_ktime_get_ns();
    evt.pid        = pid;
    evt.tid        = (u32)pid_tgid;
    evt.syscall_id = ctx->id;  // ctx->id 来自 vmlinux.h 中定义
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
