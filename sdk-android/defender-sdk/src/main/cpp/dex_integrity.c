/**
 * dex_integrity.c - DEX 文件 CRC/SHA256 校验(方案 B)
 *
 * 详见 xcj_blue_demo_v2.1.1_prompt.md §方案 B
 *
 * 原理(参考腾讯 libmsaoaidsec):
 *  SO 检测 DEX:Native 计算 classes.dex/classes2.dex/classes3.dex 的 CRC32/SHA256,
 *  与预埋值比对。DEX 被修改 -> CRC 不匹配 -> 检测到篡改。
 *
 * 对抗:
 *  - 修改 DEX 文件:✅ CRC 变化
 *  - MT 改 DEX 绕过校验:✅ 多 DEX 交叉校验(classes2/3 难以同时改)
 *
 * 预埋值来源:Packer 封装时遍历 APK 计算 DEX CRC,写入 defender-config.json
 * (运行时从 config 读取,避免硬编码)。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <android/log.h>

#define TAG "DefenderDexIntegrity"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

extern void defender_sha256(const unsigned char *data, size_t len, unsigned char *out);

/* ============= APK entry 读取(复用 integrity.c 的逻辑) ============= */

/**
 * 读取 APK 中指定 entry 的内容(自动解压 deflated)
 *
 * 简化版:遍历 local file header,匹配 entry 名。
 * 完整实现见 integrity.c 的 read_apk_entry。
 */
extern int read_apk_entry(const char *apk_path, const char *entry_name,
                          unsigned char **data_out, size_t *size_out);

/* ============= DEX CRC32 计算 ============= */

static uint32_t dex_crc32_table[256];
static int dex_crc32_inited = 0;

static void dex_init_crc32(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320;
            else crc >>= 1;
        }
        dex_crc32_table[i] = crc;
    }
    dex_crc32_inited = 1;
}

static uint32_t dex_compute_crc32(const uint8_t *data, size_t len) {
    if (!dex_crc32_inited) dex_init_crc32();
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc = (crc >> 8) ^ dex_crc32_table[(crc ^ data[i]) & 0xFF];
    }
    return crc ^ 0xFFFFFFFF;
}

/* ============= 多 DEX CRC 校验 ============= */

/**
 * 计算所有 DEX 文件(classes.dex / classes2.dex / classes3.dex ...)的 CRC32
 *
 * @param apk_path APK 路径
 * @param out_crcs 输出:CRC 数组(最多 16 个 DEX)
 * @param out_count 输出:DEX 数量
 * @return 0=成功 / -1=失败
 */
int compute_all_dex_crcs(const char *apk_path, uint32_t out_crcs[16], int *out_count) {
    *out_count = 0;

    for (int i = 0; i < 16; i++) {
        char dex_name[32];
        if (i == 0) {
            strcpy(dex_name, "classes.dex");
        } else {
            snprintf(dex_name, sizeof(dex_name), "classes%d.dex", i + 1);
        }

        unsigned char *dex_data = NULL;
        size_t dex_size = 0;
        if (read_apk_entry(apk_path, dex_name, &dex_data, &dex_size) != 0) {
            break;  /* 该 DEX 不存在,结束 */
        }

        uint32_t crc = dex_compute_crc32(dex_data, dex_size);
        out_crcs[i] = crc;
        (*out_count)++;
        LOGI("%s CRC32: 0x%08x (size=%zu)", dex_name, crc, dex_size);
        free(dex_data);
    }

    return *out_count > 0 ? 0 : -1;
}

/**
 * 方案 B:DEX 完整性校验
 *
 * 计算所有 DEX 的 CRC32,与预埋值(从 config 读取)比对。
 *
 * @param apk_path APK 路径
 * @param expected_crcs_json 预期 CRC JSON(如 ["classes.dex:1a2b3c4d",...],NULL 跳过)
 * @return 0=校验通过 / 1=校验失败 / -1=内部错误
 */
int dex_integrity_check(const char *apk_path, const char *expected_crcs_json) {
    LOGI("=== DEX 完整性校验(方案 B)===");

    if (!expected_crcs_json || expected_crcs_json[0] == '\0' || strcmp(expected_crcs_json, "[]") == 0) {
        LOGW("无预期 DEX CRC 表,跳过(需 Packer 封装时生成 integrityCrcTable)");
        return -1;  /* -1 = 未校验,UI 应显示"跳过"而非"通过" */
    }

    uint32_t actual_crcs[16];
    int dex_count = 0;
    if (compute_all_dex_crcs(apk_path, actual_crcs, &dex_count) != 0) {
        LOGE("计算 DEX CRC 失败");
        return -1;
    }

    /* 解析预期 CRC JSON 并比对
     * 简化:遍历 JSON 中的 "classes.dex:1a2b3c4d" 格式条目
     * 完整 JSON 解析见 integrity.c 的 lookup_expected_crc */
    int mismatch = 0;
    for (int i = 0; i < dex_count; i++) {
        char dex_name[32];
        if (i == 0) strcpy(dex_name, "classes.dex");
        else snprintf(dex_name, sizeof(dex_name), "classes%d.dex", i + 1);

        /* 在 JSON 中查找 dex_name:hash */
        char pattern[64];
        snprintf(pattern, sizeof(pattern), "%s:", dex_name);
        const char *p = strstr(expected_crcs_json, pattern);
        if (!p) {
            LOGW("%s 无预期 CRC,跳过", dex_name);
            continue;
        }
        p += strlen(pattern);

        /* 解析预期 CRC(hex) */
        char expected_hex[16] = {0};
        for (int j = 0; j < 8 && p[j]; j++) expected_hex[j] = p[j];
        uint32_t expected_crc = (uint32_t)strtoul(expected_hex, NULL, 16);

        if (actual_crcs[i] != expected_crc) {
            LOGE("%s CRC 不匹配: expected=0x%08x actual=0x%08x",
                 dex_name, expected_crc, actual_crcs[i]);
            mismatch++;
        } else {
            LOGI("%s CRC 匹配", dex_name);
        }
    }

    return mismatch > 0 ? 1 : 0;
}
