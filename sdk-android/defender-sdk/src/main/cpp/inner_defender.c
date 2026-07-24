/**
 * inner_defender.c - 小城笺加固 v0.1: 内层校验逻辑
 *
 * 编译为独立 .so,加密后嵌入外壳 libxcj_defender.so 的 .rodata 段。
 * 运行时通过 memfd_create + dlopen 从内存加载,不落盘。
 *
 * 对抗效果:
 *  - SRPatch/MT 静态分析只看到外壳中的加密数据,无法定位校验逻辑
 *  - IDA Pro 打开外壳 .so 看不到 inner 的函数
 *  - .so 不在磁盘上,无法被提取/patch
 *  - 加载路径为 /proc/self/fd/N,路径重定向无法匹配
 *
 * v0.1 包含:
 *  - inner_version: 版本号(防降级攻击)
 *  - inner_apk_hash_verify: APK hash 校验(与外壳的方案 A 交叉验证)
 *  - inner_env_check: 环境检测(与外壳的 patch_env_detect 交叉验证)
 */

#include <stdint.h>

/* 导出符号用 __attribute__((visibility("default"))) 确保 cl_dlsym 能找到 */
#define INNER_EXPORT __attribute__((visibility("default")))

/* ============= 自实现 libc 函数(-nostdlib 编译,无 libc 依赖) ============= */

static int il_strlen(const char *s) {
    int len = 0;
    while (s[len]) len++;
    return len;
}

static int il_strncmp(const char *a, const char *b, int n) {
    for (int i = 0; i < n; i++) {
        if (a[i] != b[i]) return a[i] - b[i];
        if (a[i] == '\0') return 0;
    }
    return 0;
}

static const char *il_strstr(const char *haystack, const char *needle) {
    int nlen = il_strlen(needle);
    if (nlen == 0) return haystack;
    for (int i = 0; haystack[i]; i++) {
        if (haystack[i] == needle[0] && il_strncmp(haystack + i, needle, nlen) == 0)
            return haystack + i;
    }
    return (const char *)0;
}

static void *il_memset(void *s, int c, unsigned long n) {
    unsigned char *p = (unsigned char *)s;
    for (unsigned long i = 0; i < n; i++) p[i] = (unsigned char)c;
    return s;
}

/* ============= 版本号 ============= */

#define INNER_VERSION_MAJOR 0
#define INNER_VERSION_MINOR 1
#define INNER_VERSION_PATCH 0

/**
 * 获取 inner 版本号(防降级攻击:外壳检查 inner 版本是否匹配)
 */
INNER_EXPORT uint32_t inner_get_version(void) {
    return (INNER_VERSION_MAJOR << 16) | (INNER_VERSION_MINOR << 8) | INNER_VERSION_PATCH;
}

/* ============= 简单完整性校验 ============= */

/* ============= 内嵌 VM 引擎(VMP 保护 inner_verify_hash) =============
 *
 * IDA 反编译结果: 巨大的 switch-case 分发表,无法还原比较逻辑。
 * GDB 单步: 每条原始比较对应 ~10 次 VM dispatch 循环。
 *
 * 精简版 VM 引擎(无日志,无外部依赖,-nostdlib 兼容)
 */
#include "vm_bytecode.h"

#define VM_FLAG_Z 1

typedef struct {
    uint64_t r[16];
    uint32_t flags;
    const uint8_t *code;
    uint32_t pc;
    int halted;
} ivm_ctx;

static inline uint8_t ivm8(ivm_ctx *c) { return c->code[c->pc++]; }
static inline uint16_t ivm16(ivm_ctx *c) { uint16_t v = c->code[c->pc]|(c->code[c->pc+1]<<8); c->pc+=2; return v; }
static inline uint32_t ivm32(ivm_ctx *c) {
    uint32_t v = (uint32_t)c->code[c->pc]|((uint32_t)c->code[c->pc+1]<<8)|
                 ((uint32_t)c->code[c->pc+2]<<16)|((uint32_t)c->code[c->pc+3]<<24);
    c->pc+=4; return v;
}

static uint64_t ivm_run(ivm_ctx *c) {
    while (!c->halted && c->pc < 120) {
        uint8_t op = ivm8(c);
        switch (op) {
        case 0x01: { uint8_t d=ivm8(c)&0xF; c->r[d]=(uint64_t)(int64_t)(int32_t)ivm32(c); break; }
        case 0x02: { uint8_t b=ivm8(c); c->r[b&0xF]=c->r[(b>>4)&0xF]; break; }
        case 0x03: { uint8_t b0=ivm8(c),b1=ivm8(c); c->r[b0&0xF]=c->r[(b0>>4)&0xF]+c->r[b1&0xF]; break; }
        case 0x04: { uint8_t b0=ivm8(c),b1=ivm8(c); c->r[b0&0xF]=c->r[(b0>>4)&0xF]-c->r[b1&0xF]; break; }
        case 0x05: { uint8_t b0=ivm8(c),b1=ivm8(c); c->r[b0&0xF]=c->r[(b0>>4)&0xF]^c->r[b1&0xF]; break; }
        case 0x07: { uint8_t b0=ivm8(c),b1=ivm8(c); c->r[b0&0xF]=c->r[(b0>>4)&0xF]|c->r[b1&0xF]; break; }
        case 0x0A: { uint8_t b=ivm8(c); uint64_t r=c->r[b&0xF]-c->r[(b>>4)&0xF]; c->flags=(r==0)?VM_FLAG_Z:0; break; }
        case 0x0B: { int32_t o=(int32_t)ivm32(c); c->pc=(uint32_t)((int32_t)c->pc+o); break; }
        case 0x0C: { int32_t o=(int32_t)ivm32(c); if(c->flags&VM_FLAG_Z) c->pc=(uint32_t)((int32_t)c->pc+o); break; }
        case 0x0D: { int32_t o=(int32_t)ivm32(c); if(!(c->flags&VM_FLAG_Z)) c->pc=(uint32_t)((int32_t)c->pc+o); break; }
        case 0x0E: { uint8_t b=ivm8(c); int16_t o=(int16_t)ivm16(c); c->r[b&0xF]=*(uint8_t*)(c->r[(b>>4)&0xF]+o); break; }
        case 0x12: c->halted=1; break;
        default: c->halted=1; break;
        }
    }
    return c->r[0];
}

/**
 * inner_verify_hash — VMP 保护版本
 *
 * 原始比较逻辑已被翻译为 120 字节 VM 字节码。
 * IDA/GDB 只能看到 switch-case dispatch,无法还原比较逻辑。
 */
INNER_EXPORT int inner_verify_hash(const char *hash_hex, const char *expected_hex) {
    ivm_ctx ctx;
    /* 零初始化(内联 memset,避免 libc 依赖) */
    unsigned char *p = (unsigned char *)&ctx;
    for (int i = 0; i < (int)sizeof(ctx); i++) p[i] = 0;

    ctx.code = VM_BC_verify_hash;
    ctx.r[0] = (uint64_t)(uintptr_t)hash_hex;
    ctx.r[1] = (uint64_t)(uintptr_t)expected_hex;
    return (int)ivm_run(&ctx);
}

/* ============= 环境检测(inner 层) ============= */

/**
 * inner 层环境检测
 *
 * 检查进程是否被注入/篡改的简单指标。
 * 与外壳的 patch_env_detect 交叉验证。
 *
 * @param maps_content /proc/self/maps 的内容(外壳传入,避免 inner 自己做 syscall)
 * @param maps_len maps 内容长度
 * @return 风险分数(0=安全)
 */
INNER_EXPORT int inner_env_check(const char *maps_content, int maps_len) {
    if (!maps_content || maps_len <= 0) return 50;

    int score = 0;

    /* 检测 Frida 特征 */
    if (il_strstr(maps_content, "frida")) score += 30;
    if (il_strstr(maps_content, "gum-js-loop")) score += 30;

    /* 检测 Xposed/LSPosed 特征 */
    if (il_strstr(maps_content, "XposedBridge")) score += 30;
    if (il_strstr(maps_content, "libxposed")) score += 30;

    /* 检测 SRPatch 特征(在应用私有目录下的 .apk 映射) */
    if (il_strstr(maps_content, "/data/data/") && il_strstr(maps_content, "base.apk")) score += 40;
    if (il_strstr(maps_content, "/data/user/") && il_strstr(maps_content, "srpatch")) score += 40;

    return score;
}

/* ============= 自检:inner .so 自身完整性 ============= */

/**
 * inner 自检:验证自身代码段未被 patch
 *
 * 计算 inner .text 段的简单 checksum,与编译时嵌入的值比对。
 * (编译时值由 patch 脚本写入,类似外壳的 self_integrity)
 *
 * @param text_base .text 段基址
 * @param text_size .text 段大小
 * @param expected_checksum 预期 checksum
 * @return 0=完整 / 1=被篡改
 */
INNER_EXPORT int inner_self_check(const void *text_base, uint32_t text_size, uint32_t expected_checksum) {
    if (!text_base || text_size == 0) return 1;

    /* 简单累加 checksum(非密码学安全,但足以检测简单 patch) */
    uint32_t sum = 0;
    const uint8_t *p = (const uint8_t *)text_base;
    for (uint32_t i = 0; i < text_size; i++) {
        sum += p[i];
        sum = (sum << 1) | (sum >> 31);  /* 循环左移 */
    }

    return (sum == expected_checksum) ? 0 : 1;
}
