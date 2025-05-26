/* gotrace.h - Go运行时跟踪核心定义 */
#ifndef __GOTRACE_H
#define __GOTRACE_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* 架构定义 */
#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86
#endif

/* Go版本相关偏移量 */
#define GO_1_20_AMD64_GOID_OFFSET 160  // Go 1.20 amd64的goroutine ID偏移量

/* 映射定义 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);        // 增大以适应高并发
    __type(key, u32);                  // TID
    __type(value, u64);                // Goroutine ID
    __uint(pinning, LIBBPF_PIN_BY_NAME);// 支持持久化映射
} goid_map SEC(".maps");

/* 事件数据结构 */
struct go_event {
    u64 goid;           // Goroutine ID
    u32 tid;            // 线程ID
    int syscall_id;     // 系统调用号（带符号）
    char comm[16];      // 进程名
    char filename[256]; // 文件名（用户空间路径）
    u64 timestamp;      // 新增时间戳字段
} __attribute__((packed));

/* 性能事件映射 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} events SEC(".maps");

/* 辅助函数声明 */
static __always_inline u64 get_goid(void *g);

#endif /* __GOTRACE_H */
