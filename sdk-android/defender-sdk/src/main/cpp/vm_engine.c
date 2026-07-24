/**
 * vm_engine.c - 小城笺加固 v0.3: VM 解释器实现
 *
 * 核心: dispatch loop (switch-case 分发表)
 * IDA 反编译结果: 一个巨大的 switch-case,无法还原原始逻辑。
 *
 * 指令编码格式:
 *   [opcode:1B] [operands:变长]
 *
 * 操作数编码:
 *   格式 R2:  [dst:4|src:4]              — 1 byte
 *   格式 R3:  [dst:4|a:4] [b:4|pad:4]   — 2 bytes
 *   格式 RI32:[reg:4|pad:4] [imm32:4B]   — 5 bytes
 *   格式 RI16:[reg:4|pad:4] [imm16:2B]   — 3 bytes
 *   格式 I32: [imm32:4B signed]          — 4 bytes
 *   格式 RI64:[reg:4|pad:4] [imm64:8B]   — 9 bytes
 *   格式 R1I16:[dst:4|src:4] [imm16:2B]  — 3 bytes
 */

#include "vm_engine.h"
#include <string.h>
#include <android/log.h>

#define TAG "DefenderVM"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ============= 读取辅助 ============= */

static inline uint8_t fetch8(vm_context_t *ctx) {
    return ctx->code[ctx->pc++];
}

static inline uint8_t peek8(vm_context_t *ctx, int offset) {
    return ctx->code[ctx->pc + offset];
}

static inline uint16_t fetch16(vm_context_t *ctx) {
    uint16_t v = (uint16_t)ctx->code[ctx->pc] | ((uint16_t)ctx->code[ctx->pc + 1] << 8);
    ctx->pc += 2;
    return v;
}

static inline uint32_t fetch32(vm_context_t *ctx) {
    uint32_t v = (uint32_t)ctx->code[ctx->pc]
               | ((uint32_t)ctx->code[ctx->pc + 1] << 8)
               | ((uint32_t)ctx->code[ctx->pc + 2] << 16)
               | ((uint32_t)ctx->code[ctx->pc + 3] << 24);
    ctx->pc += 4;
    return v;
}

static inline uint64_t fetch64(vm_context_t *ctx) {
    uint64_t lo = fetch32(ctx);
    uint64_t hi = fetch32(ctx);
    return lo | (hi << 32);
}

/* 解码寄存器对: byte = [dst:4 | src:4] */
static inline void decode_r2(uint8_t byte, uint8_t *dst, uint8_t *src) {
    *dst = byte & 0xF;
    *src = (byte >> 4) & 0xF;
}

/* 解码三寄存器: b0 = [dst:4 | a:4], b1 = [b:4 | pad:4] */
static inline void decode_r3(uint8_t b0, uint8_t b1, uint8_t *dst, uint8_t *a, uint8_t *b) {
    *dst = b0 & 0xF;
    *a = (b0 >> 4) & 0xF;
    *b = b1 & 0xF;
}

/* ============= VM 初始化 ============= */

void vm_init(vm_context_t *ctx, const uint8_t *bytecode, size_t bytecode_size) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->code = bytecode;
    ctx->code_size = bytecode_size;
    ctx->pc = 0;
    ctx->halted = 0;
    /* V13 = 栈指针(指向栈顶,简化:不用真实栈) */
    ctx->regs[13] = 0;
}

void vm_set_arg(vm_context_t *ctx, int arg_index, uint64_t value) {
    if (arg_index >= 0 && arg_index < 4) {
        ctx->regs[arg_index] = value;
    }
}

/* ============= 外部函数调用表 ============= */

/*
 * CALL_EXT 的操作数是一个索引,映射到原生 C 函数。
 * 这允许 VM 字节码调用 strlen、strcmp 等外部函数。
 *
 * 函数签名统一为: uint64_t fn(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
 */
typedef uint64_t (*vm_ext_fn)(uint64_t, uint64_t, uint64_t, uint64_t);

static uint64_t ext_strlen(uint64_t s, uint64_t a1, uint64_t a2, uint64_t a3) {
    (void)a1; (void)a2; (void)a3;
    const char *p = (const char *)s;
    uint64_t len = 0;
    while (p[len]) len++;
    return len;
}

static uint64_t ext_memcmp(uint64_t a, uint64_t b, uint64_t n, uint64_t a3) {
    (void)a3;
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    for (uint64_t i = 0; i < n; i++) {
        if (pa[i] != pb[i]) return pa[i] - pb[i];
    }
    return 0;
}

static const vm_ext_fn g_ext_funcs[] = {
    ext_strlen,   /* index 0 */
    ext_memcmp,   /* index 1 */
};
#define VM_EXT_FUNC_COUNT (sizeof(g_ext_funcs) / sizeof(g_ext_funcs[0]))

/* ============= 单步执行 ============= */

int vm_step(vm_context_t *ctx) {
    if (ctx->halted) return -1;
    if (ctx->pc >= ctx->code_size) {
        ctx->halted = 1;
        return -1;
    }

    uint8_t op = fetch8(ctx);

    switch (op) {
    case VM_NOP:
        break;

    case VM_MOV_RI: {
        uint8_t rb = fetch8(ctx);
        uint8_t dst = rb & 0xF;
        int32_t imm = (int32_t)fetch32(ctx);
        ctx->regs[dst] = (uint64_t)(int64_t)imm;
        break;
    }

    case VM_MOV_RR: {
        uint8_t rb = fetch8(ctx);
        uint8_t dst, src;
        decode_r2(rb, &dst, &src);
        ctx->regs[dst] = ctx->regs[src];
        break;
    }

    case VM_ADD: {
        uint8_t b0 = fetch8(ctx), b1 = fetch8(ctx);
        uint8_t dst, a, b;
        decode_r3(b0, b1, &dst, &a, &b);
        ctx->regs[dst] = ctx->regs[a] + ctx->regs[b];
        break;
    }

    case VM_SUB: {
        uint8_t b0 = fetch8(ctx), b1 = fetch8(ctx);
        uint8_t dst, a, b;
        decode_r3(b0, b1, &dst, &a, &b);
        ctx->regs[dst] = ctx->regs[a] - ctx->regs[b];
        break;
    }

    case VM_XOR: {
        uint8_t b0 = fetch8(ctx), b1 = fetch8(ctx);
        uint8_t dst, a, b;
        decode_r3(b0, b1, &dst, &a, &b);
        ctx->regs[dst] = ctx->regs[a] ^ ctx->regs[b];
        break;
    }

    case VM_AND: {
        uint8_t b0 = fetch8(ctx), b1 = fetch8(ctx);
        uint8_t dst, a, b;
        decode_r3(b0, b1, &dst, &a, &b);
        ctx->regs[dst] = ctx->regs[a] & ctx->regs[b];
        break;
    }

    case VM_OR: {
        uint8_t b0 = fetch8(ctx), b1 = fetch8(ctx);
        uint8_t dst, a, b;
        decode_r3(b0, b1, &dst, &a, &b);
        ctx->regs[dst] = ctx->regs[a] | ctx->regs[b];
        break;
    }

    case VM_SHL: {
        uint8_t b0 = fetch8(ctx), b1 = fetch8(ctx);
        uint8_t dst, a, b;
        decode_r3(b0, b1, &dst, &a, &b);
        ctx->regs[dst] = ctx->regs[a] << (ctx->regs[b] & 63);
        break;
    }

    case VM_SHR: {
        uint8_t b0 = fetch8(ctx), b1 = fetch8(ctx);
        uint8_t dst, a, b;
        decode_r3(b0, b1, &dst, &a, &b);
        ctx->regs[dst] = ctx->regs[a] >> (ctx->regs[b] & 63);
        break;
    }

    case VM_CMP: {
        uint8_t rb = fetch8(ctx);
        uint8_t a, b;
        decode_r2(rb, &a, &b);
        uint64_t result = ctx->regs[a] - ctx->regs[b];
        ctx->flags = 0;
        if (result == 0) ctx->flags |= VM_FLAG_Z;
        if ((int64_t)result < 0) ctx->flags |= VM_FLAG_N;
        break;
    }

    case VM_JMP: {
        int32_t offset = (int32_t)fetch32(ctx);
        ctx->pc = (uint32_t)((int32_t)ctx->pc + offset);
        break;
    }

    case VM_JZ: {
        int32_t offset = (int32_t)fetch32(ctx);
        if (ctx->flags & VM_FLAG_Z) {
            ctx->pc = (uint32_t)((int32_t)ctx->pc + offset);
        }
        break;
    }

    case VM_JNZ: {
        int32_t offset = (int32_t)fetch32(ctx);
        if (!(ctx->flags & VM_FLAG_Z)) {
            ctx->pc = (uint32_t)((int32_t)ctx->pc + offset);
        }
        break;
    }

    case VM_LOAD8: {
        uint8_t rb = fetch8(ctx);
        uint8_t dst, src;
        decode_r2(rb, &dst, &src);
        int16_t off = (int16_t)fetch16(ctx);
        ctx->regs[dst] = *(uint8_t *)(ctx->regs[src] + off);
        break;
    }

    case VM_LOAD32: {
        uint8_t rb = fetch8(ctx);
        uint8_t dst, src;
        decode_r2(rb, &dst, &src);
        int16_t off = (int16_t)fetch16(ctx);
        ctx->regs[dst] = *(uint32_t *)(ctx->regs[src] + off);
        break;
    }

    case VM_STORE8: {
        uint8_t rb = fetch8(ctx);
        uint8_t dst, src;
        decode_r2(rb, &dst, &src);
        int16_t off = (int16_t)fetch16(ctx);
        *(uint8_t *)(ctx->regs[dst] + off) = (uint8_t)ctx->regs[src];
        break;
    }

    case VM_CALL_EXT: {
        uint8_t func_idx = fetch8(ctx);
        if (func_idx < VM_EXT_FUNC_COUNT) {
            ctx->regs[0] = g_ext_funcs[func_idx](
                ctx->regs[0], ctx->regs[1], ctx->regs[2], ctx->regs[3]);
        } else {
            LOGE("VM: 无效外部函数索引 %d", func_idx);
            ctx->halted = 1;
            return -2;
        }
        break;
    }

    case VM_RET:
        ctx->halted = 1;
        return -1;

    case VM_MOV_RI64: {
        uint8_t rb = fetch8(ctx);
        uint8_t dst = rb & 0xF;
        ctx->regs[dst] = fetch64(ctx);
        break;
    }

    case VM_NOT: {
        uint8_t rb = fetch8(ctx);
        uint8_t dst, a;
        decode_r2(rb, &dst, &a);
        ctx->regs[dst] = ~ctx->regs[a];
        break;
    }

    case VM_NEG: {
        uint8_t rb = fetch8(ctx);
        uint8_t dst, a;
        decode_r2(rb, &dst, &a);
        ctx->regs[dst] = (uint64_t)(-(int64_t)ctx->regs[a]);
        break;
    }

    default:
        LOGE("VM: 未知操作码 0x%02x at PC=%u", op, ctx->pc - 1);
        ctx->halted = 1;
        return -2;
    }

    return 0;
}

/* ============= 执行到结束 ============= */

uint64_t vm_execute(vm_context_t *ctx) {
    while (!ctx->halted) {
        int r = vm_step(ctx);
        if (r == -2) return 0;  /* 错误 */
    }
    return ctx->regs[0];  /* V0 = 返回值 */
}
