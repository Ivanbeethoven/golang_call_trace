# eBPF 程序编译配置
# ----------------------------
# 用法:
# make          - 默认编译 (开发模式)
# make debug    - 带调试信息的编译
# make release  - 优化编译
# make clean    - 清理构建文件
# make install  - 安装到系统目录
# make uninstall - 卸载程序

# 自定义配置区
# ----------------------------
BUILD_DIR    := build
SRC_DIR      := src
OUTPUT_NAME  := trace_gosyscall
KERNEL_HEADERS := /lib/modules/5.15.0-139-generic/build

# 编译器配置
# ----------------------------
CC           := clang
CLANG_VERSION:= $(shell clang --version | grep -oP '(?<=version )\d+')
CFLAGS       := -target bpf \
                -I$(KERNEL_HEADERS)/arch/x86/include \
                -I$(KERNEL_HEADERS)/arch/x86/include/generated \
                -I$(KERNEL_HEADERS)/include \
                -Wall \
                -Wno-address-of-packed-member \
                -Wno-compare-distinct-pointer-types

# 自动推导文件路径
# ----------------------------
SRC          := $(wildcard $(SRC_DIR)/*.c)
OBJ          := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRC))
DEPS         := $(patsubst $(BUILD_DIR)/%.o,$(BUILD_DIR)/%.d,$(OBJ))

# 构建目标配置
# ----------------------------
.PHONY: all debug release clean install uninstall

all: CFLAGS += -O2
all: $(BUILD_DIR)/$(OUTPUT_NAME).o

debug: CFLAGS += -O0 -g -DDEBUG
debug: $(BUILD_DIR)/$(OUTPUT_NAME).o

release: CFLAGS += -O3 -DNDEBUG
release: $(BUILD_DIR)/$(OUTPUT_NAME).o

# 包含依赖文件
# ----------------------------
-include $(DEPS)

# 编译规则
# ----------------------------
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -MD -c $< -o $@
	@echo "\n>> 生成对象文件: $@ (clang v$(CLANG_VERSION))"

# 自动生成构建目录
# ----------------------------
$(BUILD_DIR):
	@mkdir -p $@
	@echo "\n>> 创建构建目录: $@"

# 清理规则
# ----------------------------
clean:
	@rm -rf $(BUILD_DIR)
	@echo ">> 清理构建文件"

# 安装规则 (需sudo)
# ----------------------------
INSTALL_PATH := /usr/local/bpf_programs

install: release
	@sudo mkdir -p $(INSTALL_PATH)
	@sudo cp $(BUILD_DIR)/$(OUTPUT_NAME).o $(INSTALL_PATH)
	@echo ">> 安装到系统目录: $(INSTALL_PATH)"

uninstall:
	@sudo rm -f $(INSTALL_PATH)/$(OUTPUT_NAME).o
	@echo ">> 从系统目录移除"

# 依赖检查
# ----------------------------
check-deps:
	@echo "\n>> 依赖检查:"
	@which clang >/dev/null || (echo "错误: clang 未安装"; exit 1)
	@test -d $(KERNEL_HEADERS) || (echo "错误: 内核头文件未找到，尝试执行: sudo apt install linux-headers-$$(uname -r)"; exit 1)
	@echo "√ clang 已安装 (版本 $(CLANG_VERSION))"
	@echo "√ 内核头文件存在于 $(KERNEL_HEADERS)"
	@echo ">> 所有依赖满足\n"