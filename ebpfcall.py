from bcc import BPF
import ctypes
import signal

# 定义与eBPF程序匹配的事件结构
class Event(ctypes.Structure):
    _fields_ = [
        ("goid",    ctypes.c_ulonglong),
        ("tid",     ctypes.c_uint),
        ("syscall_id", ctypes.c_int),
        ("comm",   ctypes.c_char * 16),
        ("filename", ctypes.c_char * 256),
    ]

def main():
    # 初始化BPF（自动编译eBPF程序）
    bpf = BPF(src_file="c/src/trace_gosyscall.c",hdr_file="c/src/vmlinux.h")  # 确保C文件路径正确
    
    try:
        # 附加到Go二进制（示例路径，需替换为实际路径）
        go_bin_path = "./main"
        
        # 附加uprobe（调试前先用nm命令验证符号是否存在）
        bpf.attach_uprobe(
            name=go_bin_path,
            sym="runtime.execute",
            fn_name="trace_execute"
        )
        bpf.attach_uprobe(
            name=go_bin_path,
            sym="runtime.goexit",
            fn_name="trace_goexit"
        )
        print(f"Successfully attached to {go_bin_path}")
    except Exception as e:
        print(f"Failed to attach uprobes: {str(e)}")
        return

    # 定义性能事件回调
    def print_event(cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(Event)).contents
        try:
            filename = event.filename.decode('utf-8', errors='replace')
            comm = event.comm.decode('utf-8', errors='replace')
            print(f"Goroutine[{event.goid}] (TID:{event.tid}) {comm} called openat: {filename}")
        except Exception as e:
            print(f"Error decoding event: {str(e)}")

    # 打开性能事件缓冲区
    bpf["events"].open_perf_buffer(print_event)
    
    # 注册优雅退出
    def shutdown(signal, frame):
        print("\nDetaching probes...")
        exit()
    signal.signal(signal.SIGINT, shutdown)

    # 主事件循环
    print("Monitoring Golang syscalls (Ctrl-C to exit)...")
    while True:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    main()
