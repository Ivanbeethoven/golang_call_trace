#include "textflag.h"

// 定义 getg 函数的汇编实现
TEXT ·getg(SB), NOSPLIT, $0-8
    MOVQ (TLS), AX    // TLS 寄存器存储当前 g 指针
    MOVQ AX, ret+0(FP)
    RET
