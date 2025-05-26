# eBPF 程序编译配置
# ----------------------------
# 用法:
# make          - 开发模式编译 (默认)
# make debug    - 带调试信息的编译
# make release  - 优化编译
# make clean    - 清理构建文件
# make install  - 安装到系统目录
# make uninstall- 卸载程序
# make check-deps - 检查编译依赖

# 自定义配置区 (用户可按需覆盖)
# ----------------------------
BUILD_DIR     ?= build
SRC_DIR       ?= src
OUTPUT_NAME   ?= trace_gosyscall
INSTALL_PATH  ?= /usr/local/bpf_programs  # 可通过环境变量覆盖

# 自动检测内核版本和头文件路径
KERNEL_VERSION := $(shell uname -r)
KERNEL_HEADERS := /lib/modules/$(KERNEL_VERSION)/build

# 编译器配置
# ----------------------------
CC            := clang
CLANG_VERSION := $(shell clang --version | awk '/clang version/ {print $$3}' | cut -d'.' -f1)
CFLAGS        := -target bpf \
                 -D__TARGET_ARCH_x86 \
                 -I$(SRC_DIR) \
                 -I$(KERNEL_HEADERS)/arch/x86/include \
                 -I$(KERNEL_HEADERS)/arch/x86/include/generated \
                 -I$(KERNEL_HEADERS)/include \
                 -Wall \
                 -Wno-address-of-packed-member \
                 -Wno-compare-distinct-pointer-types
# 文件路径推导
SRC           := $(wildcard $(SRC_DIR)/*.c)
OBJ           := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRC))
DEPS          := $(OBJ:.o=.d)

# 构建目标
# ----------------------------
.PHONY: all debug release clean install uninstall check-deps

all: CFLAGS += -O2
all: $(BUILD_DIR)/$(OUTPUT_NAME).o

debug: CFLAGS += -O0 -g3 -DDEBUG
debug: $(BUILD_DIR)/$(OUTPUT_NAME).o

release: CFLAGS += -O3 -DNDEBUG
release: $(BUILD_DIR)/$(OUTPUT_NAME).o

# 依赖处理
-include $(DEPS)

# 编译规则
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	@echo ">> 编译 $< (clang v$(CLANG_VERSION))"
	$(CC) $(CFLAGS) -MD -c $< -o $@
	@echo "  生成对象文件: $@"

# 创建构建目录
$(BUILD_DIR):
	@mkdir -p $@ || (echo "错误: 无法创建构建目录 $@"; exit 1)

# 清理
clean:
	@rm -rfv $(BUILD_DIR)
	@echo ">> 清理完成"

# 安装/卸载
install: release
	@if [ ! -f $(BUILD_DIR)/$(OUTPUT_NAME).o ]; then \
		echo "错误: 发布版本未构建，请先执行 'make release'"; exit 1; \
	fi
	@sudo mkdir -p $(INSTALL_PATH) || (echo "错误: 无法创建安装目录"; exit 1)
	@sudo install -v -m 755 $(BUILD_DIR)/$(OUTPUT_NAME).o $(INSTALL_PATH)
	@echo ">> 已安装到 $(INSTALL_PATH)"

uninstall:
	@sudo rm -fv $(INSTALL_PATH)/$(OUTPUT_NAME).o
	@echo ">> 卸载完成"

# 依赖检查
check-deps:
	@echo "\n>> 检查编译依赖:"
	@# 检查 clang
	@which clang >/dev/null 2>&1 || (echo "错误: clang 未安装，请通过包管理器安装"; exit 1)
	@# 检查内核头文件
	@if [ ! -d "$(KERNEL_HEADERS)" ]; then \
		echo "错误: 内核头文件未找到，路径: $(KERNEL_HEADERS)"; \
		if [ -f /etc/arch-release ]; then \
			echo "建议(Arch): sudo pacman -S linux$(shell uname -r | cut -d. -f1-2 | tr -d .)-headers"; \
		elif [ -f /etc/debian_version ]; then \
			echo "建议(Debian/Ubuntu): sudo apt install linux-headers-$(KERNEL_VERSION)"; \
		else \
			echo "请安装与当前内核版本匹配的 headers 包"; \
		fi; \
		exit 1; \
	fi
	@echo "√ clang v$(CLANG_VERSION) 可用"
	@echo "√ 内核头文件位于 $(KERNEL_HEADERS)"
	@echo ">> 所有依赖已满足\n"