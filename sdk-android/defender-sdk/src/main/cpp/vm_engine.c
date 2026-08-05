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

#include <android/log.h>
#include <string.h>

#include "vm_bytecode.h"

#define TAG "DefenderVM"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ADR 0098 P0-C:-ffunction-sections+--gc-sections 下函数布局无序,
 * 自引用 CRC 保护对象必须强制同段(vmself_code),由 __start_/__stop_ 定界。
 * 段名取合法 C 标识符(无点号)才能拿到链接器 __start_/__stop_ 符号。 */
#define VM_SELF_REF_SECTION __attribute__((section("vmself_code"), noinline))
/* __start_/__stop_ 为 ELF 链接器特性(Android lld / Linux GNU ld)。
 * 非 ELF(host Windows/PE)无此符号 → compute_crc 返回 0 跳过自引用,
 * 保证跨平台可编译;真防护在 ELF 目标(Android)生效。 */
#if defined(__ELF__)
extern const uint8_t __start_vmself_code[];
extern const uint8_t __stop_vmself_code[];
#endif

/* ============= 读取辅助(opcode XOR 解码) ============= */

#define VM_DEC(b) ((uint8_t) ((b) ^ VM_OPCODE_XOR_KEY))

static inline uint8_t fetch8(vm_context_t *ctx)
{
    return VM_DEC(ctx->code[ctx->pc++]);
}

static inline uint8_t peek8(vm_context_t *ctx, int offset)
{
    return VM_DEC(ctx->code[ctx->pc + offset]);
}

static inline uint16_t fetch16(vm_context_t *ctx)
{
    uint16_t v =
        (uint16_t) VM_DEC(ctx->code[ctx->pc]) | ((uint16_t) VM_DEC(ctx->code[ctx->pc + 1]) << 8);
    ctx->pc += 2;
    return v;
}

static inline uint32_t fetch32(vm_context_t *ctx)
{
    uint32_t v = (uint32_t) VM_DEC(ctx->code[ctx->pc]) |
                 ((uint32_t) VM_DEC(ctx->code[ctx->pc + 1]) << 8) |
                 ((uint32_t) VM_DEC(ctx->code[ctx->pc + 2]) << 16) |
                 ((uint32_t) VM_DEC(ctx->code[ctx->pc + 3]) << 24);
    ctx->pc += 4;
    return v;
}

static inline uint64_t fetch64(vm_context_t *ctx)
{
    uint64_t lo = fetch32(ctx);
    uint64_t hi = fetch32(ctx);
    return lo | (hi << 32);
}

/* 解码寄存器对: byte = [dst:4 | src:4] */
static inline void decode_r2(uint8_t byte, uint8_t *dst, uint8_t *src)
{
    *dst = byte & 0xF;
    *src = (byte >> 4) & 0xF;
}

/* 解码三寄存器: b0 = [dst:4 | a:4], b1 = [b:4 | pad:4] */
static inline void decode_r3(uint8_t b0, uint8_t b1, uint8_t *dst, uint8_t *a, uint8_t *b)
{
    *dst = b0 & 0xF;
    *a = (b0 >> 4) & 0xF;
    *b = b1 & 0xF;
}

/* ============= VM 初始化 ============= */

void vm_init(vm_context_t *ctx, const uint8_t *bytecode, size_t bytecode_size)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->code = bytecode;
    ctx->code_size = bytecode_size;
    ctx->pc = 0;
    ctx->halted = 0;
    /* V13 = 栈指针(指向栈顶,简化:不用真实栈) */
    ctx->regs[13] = 0;
}

void vm_set_arg(vm_context_t *ctx, int arg_index, uint64_t value)
{
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

static uint64_t ext_strlen(uint64_t s, uint64_t a1, uint64_t a2, uint64_t a3)
{
    (void) a1;
    (void) a2;
    (void) a3;
    const char *p = (const char *) s;
    uint64_t len = 0;
    while (p[len])
        len++;
    return len;
}

static uint64_t ext_memcmp(uint64_t a, uint64_t b, uint64_t n, uint64_t a3)
{
    (void) a3;
    const uint8_t *pa = (const uint8_t *) a;
    const uint8_t *pb = (const uint8_t *) b;
    for (uint64_t i = 0; i < n; i++) {
        if (pa[i] != pb[i])
            return pa[i] - pb[i];
    }
    return 0;
}

static const vm_ext_fn g_ext_funcs[] = {
    ext_strlen, /* index 0 */
    ext_memcmp, /* index 1 */
};
#define VM_EXT_FUNC_COUNT (sizeof(g_ext_funcs) / sizeof(g_ext_funcs[0]))

/* ============= 单步执行 ============= */

/* VM_SELF_REF_SECTION:dispatch 函数入 vmself_code 段,
 * 供自引用 CRC 覆盖(ADR 0098 P0-C),noinline 防内联逃逸校验范围 */
VM_SELF_REF_SECTION int vm_step(vm_context_t *ctx)
{
    if (ctx->halted)
        return -1;
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
            int32_t imm = (int32_t) fetch32(ctx);
            ctx->regs[dst] = (uint64_t) (int64_t) imm;
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
            if (result == 0)
                ctx->flags |= VM_FLAG_Z;
            if ((int64_t) result < 0)
                ctx->flags |= VM_FLAG_N;
            break;
        }

        case VM_JMP: {
            int32_t offset = (int32_t) fetch32(ctx);
            ctx->pc = (uint32_t) ((int32_t) ctx->pc + offset);
            break;
        }

        case VM_JZ: {
            int32_t offset = (int32_t) fetch32(ctx);
            if (ctx->flags & VM_FLAG_Z) {
                ctx->pc = (uint32_t) ((int32_t) ctx->pc + offset);
            }
            break;
        }

        case VM_JNZ: {
            int32_t offset = (int32_t) fetch32(ctx);
            if (!(ctx->flags & VM_FLAG_Z)) {
                ctx->pc = (uint32_t) ((int32_t) ctx->pc + offset);
            }
            break;
        }

        case VM_LOAD8: {
            uint8_t rb = fetch8(ctx);
            uint8_t dst, src;
            decode_r2(rb, &dst, &src);
            int16_t off = (int16_t) fetch16(ctx);
            ctx->regs[dst] = *(uint8_t *) (ctx->regs[src] + off);
            break;
        }

        case VM_LOAD32: {
            uint8_t rb = fetch8(ctx);
            uint8_t dst, src;
            decode_r2(rb, &dst, &src);
            int16_t off = (int16_t) fetch16(ctx);
            ctx->regs[dst] = *(uint32_t *) (ctx->regs[src] + off);
            break;
        }

        case VM_STORE8: {
            uint8_t rb = fetch8(ctx);
            uint8_t dst, src;
            decode_r2(rb, &dst, &src);
            int16_t off = (int16_t) fetch16(ctx);
            *(uint8_t *) (ctx->regs[dst] + off) = (uint8_t) ctx->regs[src];
            break;
        }

        case VM_CALL_EXT: {
            uint8_t func_idx = fetch8(ctx);
            if (func_idx < VM_EXT_FUNC_COUNT) {
                ctx->regs[0] =
                    g_ext_funcs[func_idx](ctx->regs[0], ctx->regs[1], ctx->regs[2], ctx->regs[3]);
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
            ctx->regs[dst] = (uint64_t) (-(int64_t) ctx->regs[a]);
            break;
        }

        default:
            LOGE("VM: 未知操作码 0x%02x at PC=%u", op, ctx->pc - 1);
            ctx->halted = 1;
            return -2;
    }

    return 0;
}

/* ============= 自引用完整性(ADR 0098 P0-C,改进清单 #13) =============
 *
 * Virbox Class A 教训反哺:纯叶子检测函数入口两条指令即可桩废;
 * 玄甲对策 = VM 引擎执行期对 dispatch 区段做 CRC 自校验。
 * 攻击者 patch vm_step/vm_execute 使 VM 恒返回 success 时,
 * 区段字节变化 → CRC 失配 → 检出(强证据 ⑦)。
 *
 * 校验范围:vmself_code 段全量 [__start_vmself_code, __stop_vmself_code)
 *   —— 覆盖 vm_step(dispatch)+ vm_execute + 本段校验代码自身,
 *      patch 其中任一函数都破坏 CRC。
 *   -ffunction-sections 下函数布局无序,故用专用段 + __start_/__stop_ 定界。
 *
 * 构建期闭环:patch_vm_self_ref.py(CMake POST_BUILD)
 *   按节名 vmself_code 定位段(节头在 strip 后仍存)算 CRC32,
 *   写入 g_vm_self_ref_ph 的 8 位 hex 位(占位符在 .rodata,不入段,自洽)。
 *   全 0 = 未 patch(host 测试/开发构建)→ 运行时跳过,不误杀。
 */

static int g_vm_self_ref_violation = 0;

/* patch 占位符:前 8 字节 "VMSREF01" 为幂等锚点,后 8 字节为 CRC32 hex。
 * 在 .rodata(段外),构建期写入不改变 vmself_code 段字节 → 自洽。
 * volatile 必需:占位符由构建期脚本在链接后改写;若无 volatile,-O2 会按
 * 编译期常量("00000000")把 parse 折叠成恒 return 0,引用消失后
 * --gc-sections 连占位符一起回收(实测教训)。 */
__attribute__((used)) static volatile const char g_vm_self_ref_ph[17] = "VMSREF0100000000";

/* CRC-32/IEEE(位运算实现,无表;每次 vm_execute 仅跑一次,范围数 KB)。
 * 入段保护:patch 此函数令其恒返回预期值同样破坏 CRC。 */
VM_SELF_REF_SECTION static uint32_t vm_crc32_ieee(const uint8_t *p, size_t n)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        crc ^= p[i];
        for (int b = 0; b < 8; b++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t) (0u - (crc & 1u)));
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

VM_SELF_REF_SECTION uint32_t vm_self_ref_compute_crc(void)
{
#if defined(__ELF__)
    const uint8_t *start = __start_vmself_code;
    const uint8_t *end = __stop_vmself_code;
    if (end <= start || (size_t) (end - start) > (2u << 20)) {
        return 0; /* 布局异常 → 跳过,宁可漏报不误杀 */
    }
    return vm_crc32_ieee(start, (size_t) (end - start));
#else
    return 0; /* 非 ELF(host)无 __start_/__stop_,跳过自引用 */
#endif
}

VM_SELF_REF_SECTION static int vm_self_ref_parse_expected(uint32_t *out)
{
    /* 逐字节 volatile 读,防编译期折叠(见 g_vm_self_ref_ph 注释) */
    uint32_t v = 0;
    int all_zero = 1;
    for (int i = 0; i < 8; i++) {
        char c = g_vm_self_ref_ph[8 + i]; /* 跳过 "VMSREF01" 锚点 */
        uint32_t d;
        if (c >= '0' && c <= '9') {
            d = (uint32_t) (c - '0');
        } else if (c >= 'a' && c <= 'f') {
            d = (uint32_t) (c - 'a' + 10);
        } else {
            return 0; /* 非法字符 → 按未 patch 处理 */
        }
        if (d != 0)
            all_zero = 0;
        v = (v << 4) | d;
    }
    if (all_zero)
        return 0; /* 未 patch → 跳过 */
    *out = v;
    return 1;
}

#ifdef VM_SELF_REF_TEST
/* host 单测注入钩子:模拟构建期 patch 写入任意预期值 */
static uint32_t g_vm_self_ref_test_override = 0;
static int g_vm_self_ref_test_override_on = 0;
void vm_self_ref_test_set_expected(uint32_t crc)
{
    g_vm_self_ref_test_override = crc;
    g_vm_self_ref_test_override_on = 1;
}
void vm_self_ref_test_clear(void)
{
    g_vm_self_ref_test_override_on = 0;
}
#endif

VM_SELF_REF_SECTION static void vm_self_ref_check(vm_context_t *ctx)
{
    uint32_t expected = 0;
#ifdef VM_SELF_REF_TEST
    if (g_vm_self_ref_test_override_on) {
        expected = g_vm_self_ref_test_override;
    } else
#endif
        if (!vm_self_ref_parse_expected(&expected)) {
        return; /* 未 patch → 跳过 */
    }
    uint32_t actual = vm_self_ref_compute_crc();
    if (actual == 0)
        return; /* 布局异常 → 跳过 */
    if (actual != expected) {
        g_vm_self_ref_violation = 1;
        ctx->halted = 1;
        LOGE("VM: dispatch self-ref integrity violated");
    }
}

int vm_self_ref_violated(void)
{
    return g_vm_self_ref_violation;
}

/* ============= 执行到结束 ============= */

VM_SELF_REF_SECTION uint64_t vm_execute(vm_context_t *ctx)
{
    vm_self_ref_check(ctx); /* 执行前先验引擎自身完整性(P0-C) */
    if (ctx->halted)
        return 0;
    while (!ctx->halted) {
        int r = vm_step(ctx);
        if (r == -2)
            return 0; /* 错误 */
    }
    return ctx->regs[0]; /* V0 = 返回值 */
}
