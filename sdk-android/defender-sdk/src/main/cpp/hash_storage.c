/**
 * hash_storage.c - 预埋合法哈希的分片存储与运行时拼接
 *
 * 详见 xcj_blue_demo_v2.1.1_prompt.md §2.4
 *
 * 原理:
 *  合法签名哈希值分段编码(32 字节 SHA-256 拆成 8 段 × 4 字节),
 *  分散存储在 SO 不同位置 + assets/ 加密配置。
 *  每段 XOR 0x5A 编码(防静态 strings 提取),运行时解码拼接。
 *
 * 对抗:
 *  - 静态分析(strings/IDA):看到的是 XOR 编码字节,非明文哈希
 *  - 单段被改:拼接后哈希不匹配,检测到篡改
 *
 * 注意:当前为骨架,正式版需 post-build 脚本计算真实哈希并写入各段。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <android/log.h>

#define TAG "DefenderHashStorage"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#define OBF_KEY 0x5A

/* ============= 预埋哈希分片(8 段 × 4 字节 = 32 字节 SHA-256) ============= */

/*
 * 占位值:全 0(post-build 脚本计算真实哈希后覆盖)。
 * 每段是 uint32(4 字节),XOR 0x5A 编码后存储。
 * 占位值 XOR 0x5A = 0x5A5A5A5A,故编码值为 0x5A5A5A5A。
 *
 * 正式版流程:
 *   1. post-build 计算 APK 受保护内容真实 SHA-256(32 字节)
 *   2. 拆成 8 段 × 4 字节
 *   3. 每段 XOR 0x5A 后写入对应 EMBEDDED_HASH_x
 *   4. 重新链接 SO(.rodata 不影响 .text,hash 不变)
 */
static const uint32_t EMBEDDED_HASH_SEG_1 __attribute__((section(".rodata"))) = 0x5A5A5A5A;
static const uint32_t EMBEDDED_HASH_SEG_2 __attribute__((section(".rodata"))) = 0x5A5A5A5A;
static const uint32_t EMBEDDED_HASH_SEG_3 __attribute__((section(".rodata"))) = 0x5A5A5A5A;
static const uint32_t EMBEDDED_HASH_SEG_4 __attribute__((section(".rodata"))) = 0x5A5A5A5A;
static const uint32_t EMBEDDED_HASH_SEG_5 __attribute__((section(".rodata"))) = 0x5A5A5A5A;
static const uint32_t EMBEDDED_HASH_SEG_6 __attribute__((section(".rodata"))) = 0x5A5A5A5A;
static const uint32_t EMBEDDED_HASH_SEG_7 __attribute__((section(".rodata"))) = 0x5A5A5A5A;
static const uint32_t EMBEDDED_HASH_SEG_8 __attribute__((section(".rodata"))) = 0x5A5A5A5A;

/* ============= 运行时拼接 ============= */

/**
 * 拼接预埋的合法哈希(8 段 XOR 解码 -> 32 字节 SHA-256)
 *
 * @param out_hash 输出:32 字节哈希
 * @return 0=成功 / -1=失败
 */
int get_embedded_hash(uint8_t out_hash[32]) {
    const uint32_t *segs[8] = {
        &EMBEDDED_HASH_SEG_1, &EMBEDDED_HASH_SEG_2, &EMBEDDED_HASH_SEG_3, &EMBEDDED_HASH_SEG_4,
        &EMBEDDED_HASH_SEG_5, &EMBEDDED_HASH_SEG_6, &EMBEDDED_HASH_SEG_7, &EMBEDDED_HASH_SEG_8,
    };

    for (int i = 0; i < 8; i++) {
        /* XOR 解码 */
        uint32_t decoded = *segs[i] ^ 0x5A5A5A5A;
        /* 写入 out_hash(小端) */
        out_hash[i * 4] = (uint8_t)(decoded & 0xff);
        out_hash[i * 4 + 1] = (uint8_t)((decoded >> 8) & 0xff);
        out_hash[i * 4 + 2] = (uint8_t)((decoded >> 16) & 0xff);
        out_hash[i * 4 + 3] = (uint8_t)((decoded >> 24) & 0xff);
    }

    /* 检测占位值(全 0):说明 post-build 未写入真实哈希 */
    int is_placeholder = 1;
    for (int i = 0; i < 32; i++) {
        if (out_hash[i] != 0) { is_placeholder = 0; break; }
    }
    if (is_placeholder) {
        LOGW("预埋哈希为占位值(全 0),post-build 未写入真实哈希");
        return -1;
    }

    return 0;
}

/* ============= 哈希比对 ============= */

/**
 * 比对计算哈希与预埋哈希
 *
 * @param computed 计算的 32 字节哈希
 * @return 0=匹配 / 1=不匹配 / -1=预埋为占位
 */
int compare_with_embedded(const uint8_t computed[32]) {
    uint8_t embedded[32];
    if (get_embedded_hash(embedded) != 0) {
        return -1;  /* 占位,跳过 */
    }
    if (memcmp(computed, embedded, 32) == 0) {
        LOGI("哈希匹配:APK 完整性校验通过");
        return 0;
    }
    LOGE("哈希不匹配:APK 被篡改");
    return 1;
}
