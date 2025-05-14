#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Go 1.20 amd64 的偏移量为 160
#define GOID_OFFSET 160

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);    // TID
    __type(value, u64);  // Goroutine ID
} goid_map SEC(".maps");

struct event {
    u64 goid;
    u32 tid;
    int syscall_id;
    char comm[16];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline u64 get_goid(void *g) {
    return *(u64 *)(g + GOID_OFFSET);
}

SEC("uprobe/runtime.execute")
int trace_execute(struct pt_regs *ctx) {
    void *g = (void *)PT_REGS_PARM1(ctx);
    u64 goid = get_goid(g);
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFF;

    if (bpf_map_update_elem(&goid_map, &tid, &goid, BPF_ANY) < 0) {
        bpf_printk("Failed to update goid_map for TID %d", tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct syscall_enter_openat *ctx) {
    struct event evt = {};
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFF;
    u64 *goid = bpf_map_lookup_elem(&goid_map, &tid);

    if (goid) {
        evt.goid = *goid;
        evt.tid = tid;
        evt.syscall_id = __NR_openat;
        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
        
        if (bpf_probe_read_user_str(evt.filename, sizeof(evt.filename), (void *)ctx->filename) < 0) {
            __builtin_memcpy(evt.filename, "[TRUNCATED]", 12);
        }
        
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    }
    return 0;
}

SEC("uprobe/runtime.goexit")
int trace_goexit(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFF;
    bpf_map_delete_elem(&goid_map, &tid);
    return 0;
}

char _license[] SEC("license") = "GPL";