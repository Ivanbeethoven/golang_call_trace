// trace_gosyscall.bpf.c - 主BPF程序
#include "gotrace.h"

// 版本自适应Goroutine ID获取
static __always_inline u64 get_goid(void *g) {
    u64 goid = 0;
    // 安全地从用户空间结构体 g + 偏移量 中读取一个 u64
    bpf_core_read(&goid, sizeof(goid), (char *)g + GO_1_20_AMD64_GOID_OFFSET);
    return goid;
}

SEC("uprobe/runtime.execute")
int trace_execute(struct pt_regs *ctx) {
    void *g = (void *)PT_REGS_PARM1(ctx);
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFF;
    u64 goid = get_goid(g);  // 显式指定版本
    
    if (bpf_map_update_elem(&goid_map, &tid, &goid, BPF_ANY)) {
        bpf_printk("更新goid_map失败 TID:%u", tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    struct go_event evt = {
        .timestamp = bpf_ktime_get_ns(),
    };
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFF;
    u64 *goid = bpf_map_lookup_elem(&goid_map, &tid);

    if (!goid) return 0;

    evt.goid = *goid;
    evt.tid = tid;
    evt.syscall_id = ctx->id;
    
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    
    const char *filename = (const char *)ctx->args[1];
    if (bpf_probe_read_user_str(evt.filename, sizeof(evt.filename), filename)) {
        evt.filename[0] = '\0';  // 清空无效数据
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

SEC("uprobe/runtime.goexit")
int trace_goexit(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFF;
    bpf_map_delete_elem(&goid_map, &tid);
    return 0;
}

char _license[] SEC("license") = "GPL";
