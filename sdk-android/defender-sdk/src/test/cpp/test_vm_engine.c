/**
 * test_vm_engine.c - VM 引擎 + Canary + 白盒 S-box host 端单测
 *
 * 编译: gcc -I../../main/cpp -o test_vm test_vm_engine.c ../../main/cpp/vm_engine.c -lm
 * 运行: ./test_vm
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>

/* 直接 include 源码(host 测试不需要 Android log) */
#define __android_log_print(...) ((void)0)
#define ANDROID_LOG_ERROR 0
#include "vm_engine.h"
#include "vm_bytecode.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  TEST %-40s ", #name); \
    if (test_##name()) { tests_passed++; printf("PASS\n"); } \
    else { printf("FAIL\n"); } \
} while(0)

/* ===== VM 引擎测试 ===== */

/* 辅助:对所有字节 XOR(VM 引擎 fetch 时全字节解码) */
#define XK VM_OPCODE_XOR_KEY
#define X(b) ((uint8_t)((b) ^ XK))

static int test_vm_mov_ri(void) {
    uint8_t code[] = {
        X(0x01), X(0x00), X(42), X(0), X(0), X(0),
        X(0x12), X(0x00),
    };
    vm_context_t ctx;
    vm_init(&ctx, code, sizeof(code));
    return vm_execute(&ctx) == 42;
}

static int test_vm_add(void) {
    uint8_t code[] = {
        X(0x01), X(0x00), X(10), X(0), X(0), X(0),
        X(0x01), X(0x01), X(32), X(0), X(0), X(0),
        X(0x03), X(0x00), X(0x01),  /* ADD V0, V0, V1: b0=(dst=0|a=0<<4)=0x00, b1=b=1 */
        X(0x12), X(0x00),
    };
    vm_context_t ctx;
    vm_init(&ctx, code, sizeof(code));
    return vm_execute(&ctx) == 42;
}

static int test_vm_xor(void) {
    uint8_t code[] = {
        X(0x01), X(0x00), X(0xFF), X(0), X(0), X(0),
        X(0x01), X(0x01), X(0x0F), X(0), X(0), X(0),
        X(0x05), X(0x00), X(0x01),  /* XOR V0, V0, V1 */
        X(0x12), X(0x00),
    };
    vm_context_t ctx;
    vm_init(&ctx, code, sizeof(code));
    return vm_execute(&ctx) == 0xF0;
}

static int test_vm_jmp(void) {
    uint8_t code[] = {
        X(0x01), X(0x00), X(1), X(0), X(0), X(0),
        X(0x0B), X(8), X(0), X(0), X(0),
        X(0x01), X(0x00), X(99), X(0), X(0), X(0),
        X(0x12), X(0x00),
    };
    vm_context_t ctx;
    vm_init(&ctx, code, sizeof(code));
    return vm_execute(&ctx) == 1;
}

static int test_vm_verify_hash_bytecode(void) {
    /* 用构建期生成的 VM_BC_verify_hash 字节码测试 */
    vm_context_t ctx;
    vm_init(&ctx, VM_BC_verify_hash, VM_BC_verify_hash_size);
    /* 两个相同字符串 → 应返回 0 */
    const char *hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    vm_set_arg(&ctx, 0, (uint64_t)(uintptr_t)hash);
    vm_set_arg(&ctx, 1, (uint64_t)(uintptr_t)hash);
    uint64_t r = vm_execute(&ctx);
    if (r != 0) return 0;

    /* 不同字符串 → 应返回 1 */
    vm_init(&ctx, VM_BC_verify_hash, VM_BC_verify_hash_size);
    const char *hash2 = "0000000000000000000000000000000000000000000000000000000000000000";
    vm_set_arg(&ctx, 0, (uint64_t)(uintptr_t)hash);
    vm_set_arg(&ctx, 1, (uint64_t)(uintptr_t)hash2);
    return vm_execute(&ctx) == 1;
}

/* ===== Canary 测试 ===== */
#include "canary_guard.h"

static int test_canary_correct(void) {
    uint32_t c = CANARY_INIT;
    CANARY_UPDATE(c, 0);
    CANARY_UPDATE(c, 1);
    CANARY_UPDATE(c, 2);
    return c == canary_expected(3);
}

static int test_canary_short_circuit(void) {
    /* 模拟 hook return 0: 跳过 CANARY_UPDATE */
    uint32_t c = CANARY_INIT;
    /* 不调用 CANARY_UPDATE → canary 不匹配 */
    return c != canary_expected(3);
}

static int test_canary_wrong_count(void) {
    uint32_t c = CANARY_INIT;
    CANARY_UPDATE(c, 0);
    CANARY_UPDATE(c, 1);
    /* 只更新 2 次,期望 3 次 → 不匹配 */
    return c != canary_expected(3);
}

/* ===== 白盒 S-box 测试 ===== */
#ifdef T4_USE_WHITEBOX
#include "wb_sbox.h"

static int test_whitebox_xor_equivalence(void) {
    /* 白盒 S-box 应等价于 XOR key */
    uint8_t key[] = {0x72, 0x88, 0x61, 0xf9, 0xcf, 0x75, 0x75, 0x9a,
                     0xc6, 0x44, 0x17, 0x06, 0xd9, 0x34, 0x70, 0x72};
    int key_len = 16;
    for (int i = 0; i < 256; i++) {
        for (int s = 0; s < key_len; s++) {
            uint8_t expected = (uint8_t)(i ^ key[s]);
            uint8_t actual = WB_SBOX[s][i];
            if (expected != actual) return 0;
        }
    }
    return 1;
}
#endif

int main(void) {
    printf("=== 小城笺加固 host 单测 ===\n\n");

    printf("[VM 引擎]\n");
    TEST(vm_mov_ri);
    TEST(vm_add);
    TEST(vm_xor);
    TEST(vm_jmp);
    TEST(vm_verify_hash_bytecode);

    printf("\n[Canary 防短路]\n");
    TEST(canary_correct);
    TEST(canary_short_circuit);
    TEST(canary_wrong_count);

#ifdef T4_USE_WHITEBOX
    printf("\n[白盒 S-box]\n");
    TEST(whitebox_xor_equivalence);
#endif

    printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
