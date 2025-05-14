from bcc import BPF
import ctypes
import struct

class Event(ctypes.Structure):
    _fields_ = [
        ("goid", ctypes.c_ulonglong),
        ("tid", ctypes.c_uint),
        ("syscall_id", ctypes.c_int),
        ("comm", ctypes.c_char * 16),
        ("filename", ctypes.c_char * 256),
    ]

bpf = BPF(src_file="trace_gosyscall.c")

# 附加 uprobe（需替换为你的 Go 程序路径）
bpf.attach_uprobe(name="/path/to/your/go/program", sym="runtime.execute", fn_name="trace_execute")
bpf.attach_uprobe(name="/path/to/your/go/program", sym="runtime.goexit", fn_name="trace_goexit")

def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    print(f"Goroutine {event.goid} (TID {event.tid}) -> {event.comm.decode()} called openat: {event.filename.decode()}")

bpf["events"].open_perf_buffer(print_event)
print("Monitoring Golang syscalls by Goroutine...")

while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()