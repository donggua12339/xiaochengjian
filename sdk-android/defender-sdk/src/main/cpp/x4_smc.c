/**
 * x4_smc.c - X4-5 L5 SMC 引擎实现(ADR 0093)
 *
 * 见 x4_smc.h 设计说明。两段式:明文机器码模板 XOR 混淆存 .rodata → init 解出后
 * 立即用运行时密钥 RC4 加密成缓存并清零明文 → run 时解密缓存到独立沙箱页执行并全擦除。
 *
 * 机器码模板(明文,build 期手算 XOR 0x5A 得下方 enc 数组):
 *   arm64: add w0,w0,w1 (00 00 01 0B) ; ret (C0 03 5F D6)         = 8 字节
 *   arm32 thumb: adds r0,r0,r1 (40 18) ; bx lr (70 47)            = 4 字节
 * host/x86 不执行机器码(smc_add 直算),但仍走解密/擦除数据流以验证纪律。
 */
#include "x4_smc.h"
#include "obfstr_poly.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#if defined(__ANDROID__)
#include <sys/mman.h>
#endif

/* XOR 混淆后的机器码模板(.rodata,静态不可直接执行/识别) */
#if defined(__aarch64__)
static const uint8_t SMC_ENC[] = { 0x5A,0x5A,0x5B,0x51,0x9A,0x59,0x05,0x8C };
#define SMC_LEN 8
#elif defined(__arm__)
static const uint8_t SMC_ENC[] = { 0x1A,0x42,0x2A,0x1D };
#define SMC_LEN 4
#else
/* host:用 arm64 模板做字节流自测(不执行) */
static const uint8_t SMC_ENC[] = { 0x5A,0x5A,0x5B,0x51,0x9A,0x59,0x05,0x8C };
#define SMC_LEN 8
#endif

#define SMC_PAGE 4096

static int      g_inited = 0;
static uint8_t *g_sandbox = 0;          /* 执行页(ANDROID: mmap; host: malloc) */
static uint8_t *g_cache = 0;            /* RC4 密文缓存(运行时密钥加密的模板) */
static int      g_cache_len = 0;
static uint8_t  g_key[8];
static volatile int g_ever_rwx = 0;     /* 纪律:从不 RWX */
static volatile int g_last_wiped = -1;

/* ============= 内联 RC4(与 so_cipher 同算法,独立一份避免头依赖顺序) ============= */
static void smc_rc4(const uint8_t *key, size_t klen,
                    const uint8_t *in, uint8_t *out, size_t n) {
    uint8_t S[256];
    for (int i = 0; i < 256; i++) S[i] = (uint8_t)i;
    uint8_t j = 0;
    for (int i = 0; i < 256; i++) { j = (uint8_t)(j + S[i] + key[i % klen]); uint8_t t = S[i]; S[i] = S[j]; S[j] = t; }
    uint8_t ii = 0; j = 0;
    for (size_t k = 0; k < n; k++) {
        ii = (uint8_t)(ii + 1); j = (uint8_t)(j + S[ii]);
        uint8_t t = S[ii]; S[ii] = S[j]; S[j] = t;
        out[k] = (uint8_t)(in[k] ^ S[(uint8_t)(S[ii] + S[j])]);
    }
}

#if defined(__ANDROID__)
static int smc_mprotect(void *p, size_t sz, int prot) {
    if ((prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC)) g_ever_rwx = 1;
    return mprotect(p, sz, prot);
}
#endif

/* 派生运行时密钥(进程内确定,静态不可复现) */
static void derive_key(void) {
    const char *s = OBF("X4S!");
    uint32_t pid = (uint32_t)getpid();
    uintptr_t a = (uintptr_t)&x4_smc_init;
    g_key[0] = (uint8_t)(s[0] ^ (pid & 0xff));
    g_key[1] = (uint8_t)(s[1] ^ ((pid >> 8) & 0xff));
    g_key[2] = (uint8_t)(s[2] ^ (a & 0xff));
    g_key[3] = (uint8_t)(s[3] ^ ((a >> 8) & 0xff));
    g_key[4] = (uint8_t)((pid ^ (a >> 16)) & 0xff);
    g_key[5] = (uint8_t)(((pid >> 16) ^ (a >> 24)) & 0xff);
    g_key[6] = (uint8_t)((a >> 32) & 0xff);
    g_key[7] = (uint8_t)(((a >> 40) ^ 0xA5) & 0xff);
}

int x4_smc_init(void) {
    if (g_inited) return 0;
    /* 1. 解 XOR 得明文模板到中转缓冲 */
    static volatile uint8_t plain[16];
    for (int i = 0; i < SMC_LEN; i++) plain[i] = (uint8_t)(SMC_ENC[i] ^ 0x5A);
    /* 2. 分配沙箱页 */
#if defined(__ANDROID__)
    g_sandbox = (uint8_t *)mmap(0, SMC_PAGE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_sandbox == MAP_FAILED) { g_sandbox = 0; return -1; }
#else
    g_sandbox = (uint8_t *)calloc(1, SMC_PAGE);
    if (!g_sandbox) return -1;
#endif
    /* 3. 派生密钥 + RC4 加密明文模板成缓存 */
    derive_key();
    g_cache_len = SMC_LEN;
    g_cache = (uint8_t *)malloc((size_t)g_cache_len);
    if (!g_cache) return -1;
    smc_rc4(g_key, sizeof(g_key), (const uint8_t *)plain, g_cache, (size_t)g_cache_len);
    /* 4. 立即清零明文模板(明文仅此一瞬存在) */
    for (int i = 0; i < 16; i++) plain[i] = 0;
    g_inited = 1;
    return 0;
}

int x4_smc_add(int a, int b) {
    if (!g_inited && x4_smc_init() != 0) return a + b;
    /* 解密缓存 → 中转明文 */
    static volatile uint8_t plain[16];
    smc_rc4(g_key, sizeof(g_key), g_cache, (uint8_t *)plain, (size_t)g_cache_len);
    int result;
#if defined(__ANDROID__)
    /* 写沙箱页:RW */
    smc_mprotect(g_sandbox, SMC_PAGE, PROT_READ | PROT_WRITE);
    for (int i = 0; i < g_cache_len; i++) g_sandbox[i] = plain[i];
    for (int i = 0; i < 16; i++) plain[i] = 0;          /* 清中转明文 */
    /* 执行:RX(零 rwx) */
    smc_mprotect(g_sandbox, SMC_PAGE, PROT_READ | PROT_EXEC);
#if defined(__aarch64__)
    typedef int (*fn_t)(int, int);
    result = ((fn_t)g_sandbox)(a, b);
#else  /* thumb:置位 0 */
    typedef int (*fn_t)(int, int);
    result = ((fn_t)((uintptr_t)g_sandbox | 1u))(a, b);
#endif
    /* 擦除沙箱页:RW → 清零 → NONE */
    smc_mprotect(g_sandbox, SMC_PAGE, PROT_READ | PROT_WRITE);
    for (int i = 0; i < SMC_PAGE; i++) g_sandbox[i] = 0;
    smc_mprotect(g_sandbox, SMC_PAGE, PROT_NONE);
    g_last_wiped = 1;
#else
    /* host:不执行机器码,直算;但仍擦中转 + 沙箱以验证纪律 */
    result = a + b;
    for (int i = 0; i < 16; i++) plain[i] = 0;
    for (int i = 0; i < SMC_PAGE; i++) g_sandbox[i] = 0;
    g_last_wiped = 1;
#endif
    return result;
}

int x4_smc_sandbox_wiped(void) {
    if (!g_sandbox) return -1;
    /* 临时可读检查(host 沙箱本就可读;ANDROID 沙箱当前 PROT_NONE,需 mprotect 读) */
#if defined(__ANDROID__)
    if (smc_mprotect(g_sandbox, SMC_PAGE, PROT_READ) != 0) return -1;
#endif
    int wiped = 1;
    for (int i = 0; i < 64; i++) { if (g_sandbox[i] != 0) { wiped = 0; break; } }
#if defined(__ANDROID__)
    smc_mprotect(g_sandbox, SMC_PAGE, PROT_NONE);
#endif
    return wiped;
}

int x4_smc_selftest(void) {
    /* RC4 往返 */
    uint8_t data[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t enc[16], dec[16];
    uint8_t tk[4] = {0x12,0x34,0x56,0x78};
    smc_rc4(tk, 4, data, enc, 16);
    smc_rc4(tk, 4, enc, dec, 16);
    for (int i = 0; i < 16; i++) if (dec[i] != data[i]) return 1;
    /* XOR 自洽:enc^k^k == enc */
    for (int i = 0; i < SMC_LEN; i++) {
        uint8_t p = (uint8_t)(SMC_ENC[i] ^ 0x5A);
        uint8_t e = (uint8_t)(p ^ 0x5A);
        if (e != SMC_ENC[i]) return 2;
    }
    /* 跑一次 + 擦除检查 + 零 rwx 纪律 */
    if (x4_smc_init() != 0) return 3;
    int r = x4_smc_add(3, 4);
    if (r != 7) return 4;
    if (x4_smc_sandbox_wiped() != 1) return 5;
    if (g_ever_rwx != 0) return 6;
    return 0;
}
