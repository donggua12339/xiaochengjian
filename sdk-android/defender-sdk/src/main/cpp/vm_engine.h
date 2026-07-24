/**
 * vm_engine.h - 小城笺加固 v0.3: 代码虚拟化 VM 引擎
 *
 * 设计原则(参考 360 VMP 文档):
 *  - 只保护关键函数,不全量 VMP(性能下降 15-20%)
 *  - IDA 看到"巨大的 switch-case 分发表",原始 ARM 指令消失
 *  - GDB 单步跟踪:每条原始指令对应数十次 VM 循环
 *
 * VM 架构:
 *  - 16 个 64 位虚拟寄存器 V0-V15
 *  - V0-V3: 参数/返回值(类似 ARM64 x0-x3)
 *  - V4-V12: 临时寄存器
 *  - V13: 栈指针
 *  - V14: 帧指针
 *  - V15: 程序计数器(内部使用)
 *  - 1 个标志寄存器(Z=零, N=负, C=进位)
 *
 * 对抗效果:
 *  - 静态分析:只能看到 dispatch loop 的 switch-case,无法还原原始逻辑
 *  - 动态调试:每步 VM 指令都经过 dispatch,单步效率极低
 *  - hook:无法定位原始函数边界(没有函数 prologue/epilogue)
 */
#ifndef VM_ENGINE_H
#define VM_ENGINE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============= VM 操作码 ============= */
enum vm_opcode {
    VM_NOP      = 0x00,
    VM_MOV_RI   = 0x01,  /* Vd = imm32 (sign-extended to 64) */
    VM_MOV_RR   = 0x02,  /* Vd = Vs */
    VM_ADD      = 0x03,  /* Vd = Va + Vb */
    VM_SUB      = 0x04,  /* Vd = Va - Vb */
    VM_XOR      = 0x05,  /* Vd = Va ^ Vb */
    VM_AND      = 0x06,  /* Vd = Va & Vb */
    VM_OR       = 0x07,  /* Vd = Va | Vb */
    VM_SHL      = 0x08,  /* Vd = Va << Vb */
    VM_SHR      = 0x09,  /* Vd = Va >> Vb (logical) */
    VM_CMP      = 0x0A,  /* flags = (Va - Vb), 不存结果 */
    VM_JMP      = 0x0B,  /* PC += offset (signed) */
    VM_JZ       = 0x0C,  /* if Z: PC += offset */
    VM_JNZ      = 0x0D,  /* if !Z: PC += offset */
    VM_LOAD8    = 0x0E,  /* Vd = *(uint8_t*)(Va + imm16) */
    VM_LOAD32   = 0x0F,  /* Vd = *(uint32_t*)(Va + imm16) */
    VM_STORE8   = 0x10,  /* *(uint8_t*)(Va + imm16) = Vb */
    VM_CALL_EXT = 0x11,  /* V0 = native_func(V0,V1,V2,V3) — 调用原生 C 函数 */
    VM_RET      = 0x12,  /* return V0 */
    VM_MOV_RI64 = 0x13,  /* Vd = imm64 (8 bytes following) */
    VM_NOT      = 0x14,  /* Vd = ~Va */
    VM_NEG      = 0x15,  /* Vd = -Va */
};

/* ============= VM 指令编码格式 ============= */
/*
 * 每条指令: 1 byte opcode + 变长操作数
 *
 * 寄存器编码: 4 bit (0-15)
 * 立即数编码: 取决于指令类型
 *
 * 格式 A (3 寄存器):  [opcode][dst:4|src1:4][src2:4|pad:4]
 * 格式 B (2 寄存器):  [opcode][dst:4|src:4]
 * 格式 C (寄存器+imm32): [opcode][reg:4|pad:4][imm32: 4 bytes]
 * 格式 D (寄存器+imm16): [opcode][reg:4|pad:4][imm16: 2 bytes]
 * 格式 E (imm32 跳转): [opcode][imm32: 4 bytes signed]
 * 格式 F (imm64): [opcode][reg:4|pad:4][imm64: 8 bytes]
 */

/* 编码辅助宏 */
#define VM_ENC_REG2(op, dst, src)    ((op) | ((uint8_t)(dst) << 8) | ((uint8_t)(src) << 12))
#define VM_ENC_REG3(op, dst, a, b)   /* 使用两字节编码 */
#define VM_PACK_REG2(dst, src)       (((uint8_t)(dst) & 0xF) | (((uint8_t)(src) & 0xF) << 4))

/* ============= VM 上下文 ============= */

#define VM_REG_COUNT 16

typedef struct {
    uint64_t regs[VM_REG_COUNT];  /* V0-V15 */
    uint32_t flags;               /* bit0=Z, bit1=N, bit2=C */
    const uint8_t *code;          /* 字节码起始 */
    size_t code_size;             /* 字节码大小 */
    uint32_t pc;                  /* 程序计数器(字节偏移) */
    int halted;                   /* 1=已停止(RET 或错误) */
} vm_context_t;

/* flags 位定义 */
#define VM_FLAG_Z  (1 << 0)  /* Zero */
#define VM_FLAG_N  (1 << 1)  /* Negative */
#define VM_FLAG_C  (1 << 2)  /* Carry */

/* ============= VM 引擎 API ============= */

/**
 * 初始化 VM 上下文
 * @param ctx 上下文
 * @param bytecode VM 字节码
 * @param bytecode_size 字节码大小
 */
void vm_init(vm_context_t *ctx, const uint8_t *bytecode, size_t bytecode_size);

/**
 * 设置函数参数(调用 VM 函数前)
 * @param ctx 上下文
 * @param arg_index 参数索引(0-3 → V0-V3)
 * @param value 参数值
 */
void vm_set_arg(vm_context_t *ctx, int arg_index, uint64_t value);

/**
 * 执行 VM 字节码直到 RET 或错误
 * @param ctx 上下文
 * @return V0 的值(返回值)
 */
uint64_t vm_execute(vm_context_t *ctx);

/**
 * 单步执行一条 VM 指令(调试用)
 * @param ctx 上下文
 * @return 0=正常 / -1=停止 / -2=错误
 */
int vm_step(vm_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* VM_ENGINE_H */
