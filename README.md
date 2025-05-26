
sudo apt update
sudo apt install -y build-essential clang llvm libelf-dev

sudo apt install -y python3 python3-pip

# 安装 Python 3 和 pip
sudo apt install -y python3 python3-pip

# 安装 BCC 工具链和 Python 绑定
sudo apt install -y bpfcc-tools libbpfcc-dev python3-bpfcc

sudo apt install linux-tools-common


```bash
sudo pacman -Syu            # 同等于 apt update + 升级系统

# 1. 基础构建工具 + clang/llvm + elf 头文件
sudo pacman -S --needed base-devel clang llvm elfutils

# 2. Python3 和 pip
sudo pacman -S --needed python python-pip

# 3. 安装 BCC 工具链（用户空间 eBPF 工具）
sudo pacman -S --needed bcc bcc-tools python-bcc

# 4. 安装 perf 工具（等效于 linux-tools-common）
sudo pacman -S --needed perf

sudo pacman -S linux-tools

pacman -S bcc bcc-tools python-bcc

```

bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./src/vmlinux.h


go build -gcflags "all=-N -l" -o hello_bin hello.go