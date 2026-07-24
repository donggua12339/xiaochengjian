/**
 * test_obfstr_poly.c - 玄甲 X1 字符串多态加密 交叉验证(host 端, gcc 编译)
 *
 * 验证两件事:
 *  1. C 自洽:obf_poly_decode(obf_poly_encode(p)) == p,遍历 24 variant × 多 seed × 多明文。
 *  2. C ∘ py 互逆:对 obfstr_poly.py 产出的 test_vectors_generated.h 中每条
 *     (plain, seed, variant, cipher),C 端 obf_poly_decode(cipher) == plain。
 *     这证明 C 的 decode 与 py 的 encrypt 严格互逆(两端原语/排列/参数一致)。
 *
 * 编译: gcc -O2 -Wall -Wextra -I.. -o test_obfstr_poly test_obfstr_poly.c && ./test_obfstr_poly
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include "obfstr_poly.h"
#include "test_vectors_generated.h"

static const char *SAMPLES[] = {
    "frida", "/proc/self/maps", "", "xposed", "TracerPid:",
    "com.xcj.defender.demo", "android_dlopen_ext", "libfrida-agent.so",
};
#define NSAMP (sizeof(SAMPLES) / sizeof(SAMPLES[0]))

int main(void) {
    int failures = 0;

    /* 1. C 自洽 */
    for (int v = 0; v < 24; v++) {
        for (uint32_t seed = 1; seed < 200; seed += 7) {
            for (size_t s = 0; s < NSAMP; s++) {
                const char *p = SAMPLES[s];
                size_t n = strlen(p);
                uint8_t enc[256], dec[256];
                obf_poly_encode(enc, (const uint8_t *)p, n, seed, (uint8_t)v);
                obf_poly_decode(dec, enc, n, seed, (uint8_t)v);
                if (memcmp(dec, p, n) != 0) {
                    printf("FAIL C-self v=%d seed=%u plain=\"%s\"\n", v, seed, p);
                    failures++;
                }
                /* 密文 != 明文(非空时) */
                if (n > 0 && memcmp(enc, p, n) == 0) {
                    printf("FAIL cipher==plain v=%d seed=%u\n", v, seed);
                    failures++;
                }
            }
        }
    }
    printf("[test] C 自洽:24 variant × 多 seed × %zu plain 全往返完成\n", NSAMP);

    /* 2. C ∘ py 互逆(交叉验证) */
    for (int i = 0; i < OBF_VEC_COUNT; i++) {
        const obf_vec_t *vec = &OBF_VECS[i];
        uint8_t dec[512];
        if (vec->n > sizeof(dec)) {
            printf("FAIL vec %d too large\n", i);
            failures++;
            continue;
        }
        obf_poly_decode(dec, vec->cipher, vec->n, vec->seed, vec->variant);
        if (memcmp(dec, vec->plain, vec->n) != 0) {
            printf("FAIL cross vec %d seed=0x%X var=%u plain=\"%s\"\n",
                   i, vec->seed, vec->variant, vec->plain);
            failures++;
        }
    }
    printf("[test] C∘py 交叉验证:%d 向量完成\n", OBF_VEC_COUNT);

    if (failures == 0) {
        printf("[test] ALL PASS ✅ (X1 多态加密引擎 C↔py 互逆确认)\n");
        return 0;
    }
    printf("[test] %d FAILURES ❌\n", failures);
    return 1;
}
