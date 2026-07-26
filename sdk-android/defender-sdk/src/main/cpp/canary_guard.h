/**
 * canary_guard.h - Canary 防短路机制(路线 C 配套)
 *
 * 对抗:Frida hook 检测函数使其直接 return 0(绕过所有检测)。
 *
 * 原理:
 *   每个检测函数内部在执行各 check 时累积一个 canary 值:
 *     canary ^= CANARY_SEED ^ (check_index * CHECK_MAGIC)
 *   只有完整遍历所有 check 才能产出正确的 final canary。
 *   调用方验证 canary:不正确 → 函数被短路 → 视为检测到攻击 → kill。
 *
 * 使用方式:
 *   uint32_t canary = CANARY_INIT;
 *   int score = 0;
 *   // ... 每个 check 后:
 *   CANARY_UPDATE(canary, 0);  // check index 0
 *   // ...
 *   CANARY_UPDATE(canary, N);  // check index N
 *   // 返回前:
 *   *canary_out = canary;
 *
 *   调用方:
 *   if (canary != canary_expected(N)) { /* 被短路 * / kill(); }
 *
 * CANARY_SEED 每构建随机(由 native_cff.py 或独立脚本生成)。
 */
#ifndef CANARY_GUARD_H
#define CANARY_GUARD_H

#include <stdint.h>

/* 每构建随机种子(构建期生成,写入 cff_params.h 或独立头文件) */
#ifndef CANARY_SEED
#define CANARY_SEED 0xA5C3E1F7u  /* 默认值,正式构建时替换 */
#endif

#define CHECK_MAGIC 0x6D9B2E41u  /* 固定乘数(混淆 check 顺序) */

#define CANARY_INIT (CANARY_SEED)

#define CANARY_UPDATE(canary, idx) \
    do { (canary) ^= (CANARY_SEED ^ ((uint32_t)(idx) * CHECK_MAGIC)); } while(0)

/**
 * 计算 N 个 check 全部执行后的预期 canary 值。
 * 调用方用此验证检测函数是否被短路。
 */
static inline uint32_t canary_expected(int check_count) {
    uint32_t c = CANARY_INIT;
    for (int i = 0; i < check_count; i++) {
        c ^= (CANARY_SEED ^ ((uint32_t)i * CHECK_MAGIC));
    }
    return c;
}

#endif /* CANARY_GUARD_H */
