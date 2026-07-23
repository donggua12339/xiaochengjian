/**
 * signing_block_parser.c - V2 Signing Block 解析
 *
 * 详见 xcj_blue_demo_v2.1.1_prompt.md §方案 A + 附录 A
 *
 * APK Signing Block 结构(AOSP 官方文档已确认):
 *  - 位于 ZIP Central Directory 之前
 *  - 尾部 16 字节 magic:"APK Sig Block 42"
 *  - 尾部前 8 字节:块大小(uint64,与首部相同)
 *  - 首部 8 字节:块大小(uint64)
 *  - 中间:ID-value 对序列(uint64 长度前缀 + uint32 ID + 变长 value)
 *
 * v2 block ID = 0x7109871a(小端:1a 87 09 71)
 * v3 block ID = 0xf05368c0
 *
 * 参考:
 *  - AOSP source.android.com/security/apksigning/v2
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <android/log.h>

#define TAG "DefenderSigBlockParser"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* V2/V3 block ID(AOSP 官方) */
#define APK_SIG_BLOCK_V2_ID  0x7109871a
#define APK_SIG_BLOCK_V3_ID  0xf05368c0

/* APK Signing Block 尾部 magic(16 字节) */
static const char APK_SIG_BLOCK_MAGIC[16] = "APK Sig Block 42";

/* EOCD 魔数(小端:50 4b 05 06) */
#define EOCD_MAGIC 0x06054b50

/* ============= 小端读取辅助 ============= */

static uint32_t read_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t read_le64(const uint8_t *p) {
    return (uint64_t)read_le32(p) | ((uint64_t)read_le32(p + 4) << 32);
}

/* ============= EOCD 定位 ============= */

/**
 * 从 mmap 的 APK 内存中找 EOCD(End of Central Directory)
 *
 * EOCD 魔数:0x06054b50(小端:50 4b 05 06)
 * 从文件末尾向前搜索(EOCD 最小 22 字节,注释最大 65535)
 *
 * @param data APK 内存映射
 * @param size APK 大小
 * @return EOCD 偏移 / -1=未找到
 */
static long find_eocd(const uint8_t *data, size_t size) {
    if (size < 22) return -1;
    size_t search_len = size < 22 + 65535 ? size : 22 + 65535;
    size_t search_start = size - search_len;

    for (size_t i = size - 22; i >= search_start; i--) {
        if (data[i] == 0x50 && data[i + 1] == 0x4b &&
            data[i + 2] == 0x05 && data[i + 3] == 0x06) {
            return (long)i;
        }
        if (i == 0) break;
    }
    return -1;
}

/* ============= Signing Block 定位 ============= */

/**
 * 定位 APK Signing Block
 *
 * @param data APK 内存映射
 * @param size APK 大小
 * @param out_block_start 输出:签名块起始偏移
 * @param out_block_size 输出:签名块总大小(含首尾 size + magic)
 * @return 0=成功 / -1=失败(无签名块,如 V1 only)
 */
int locate_signing_block(const uint8_t *data, size_t size,
                         size_t *out_block_start, size_t *out_block_size) {
    long eocd = find_eocd(data, size);
    if (eocd < 0) {
        LOGE("找不到 EOCD");
        return -1;
    }

    /* EOCD + 16 = 中央目录偏移(uint32 LE) */
    uint32_t cd_offset = read_le32(data + eocd + 16);
    if (cd_offset < 24 || cd_offset > size) {
        LOGE("中央目录偏移异常: %u", cd_offset);
        return -1;
    }

    /* 签名块尾部在 cd_offset 前 24 字节:size(8) + magic(16) */
    size_t footer_start = cd_offset - 24;
    if (memcmp(data + footer_start + 8, APK_SIG_BLOCK_MAGIC, 16) != 0) {
        LOGW("无 APK Signing Block(可能 V1 only 签名)");
        return -1;
    }

    /* 签名块大小(footer_start 处 uint64,不含首部 size 字段) */
    uint64_t block_size = read_le64(data + footer_start);
    size_t block_total = (size_t)block_size + 24;
    size_t block_start = cd_offset - 24 - (size_t)block_size;

    if (block_start >= size) {
        LOGE("签名块起始偏移异常: %zu", block_start);
        return -1;
    }

    LOGI("Signing Block: start=%zu size=%zu cd_offset=%u eocd=%ld",
         block_start, block_total, cd_offset, eocd);
    *out_block_start = block_start;
    *out_block_size = block_total;
    return 0;
}

/* ============= V2 block 提取 ============= */

/**
 * 从 Signing Block 中找指定 ID 的 ID-value 对
 *
 * Signing Block 内部结构:
 *  [block_start + 8] .. [block_start + block_size]  ID-value 序列
 *  每个对:uint64 length + uint32 ID + value(length - 4 字节)
 *
 * @param block_start 签名块起始偏移(含首部 size)
 * @param block_size 签名块总大小
 * @param target_id 目标 ID(如 0x7109871a)
 * @param out_value_offset 输出:value 起始偏移(相对 data)
 * @param out_value_size 输出:value 大小
 * @return 0=成功 / -1=未找到
 */
int find_id_value_pair(const uint8_t *data, size_t block_start, size_t block_size,
                       uint32_t target_id,
                       size_t *out_value_offset, size_t *out_value_size) {
    /* ID-value 序列从 block_start + 8 开始,到 block_start + block_size 结束
     * (尾部 24 字节是 size + magic,不含在序列内) */
    size_t seq_start = block_start + 8;
    size_t seq_end = block_start + block_size;  /* 不含尾部 size(8)+magic(16)=24 */

    size_t pos = seq_start;
    while (pos + 12 <= seq_end) {  /* 至少 8(length) + 4(ID) */
        uint64_t pair_len = read_le64(data + pos);
        if (pair_len < 4 || pos + 8 + pair_len > seq_end) break;

        uint32_t id = read_le32(data + pos + 8);
        size_t value_size = (size_t)pair_len - 4;
        size_t value_offset = pos + 12;

        if (id == target_id) {
            LOGI("找到 ID-value 对: id=0x%08x value_offset=%zu value_size=%zu",
                 id, value_offset, value_size);
            *out_value_offset = value_offset;
            *out_value_size = value_size;
            return 0;
        }
        pos += 8 + pair_len;
    }
    return -1;
}

/**
 * 提取 V2 block(优先)或 V3 block
 *
 * @param data APK 内存映射
 * @param size APK 大小
 * @param out_v2_offset 输出:V2 block value 起始偏移
 * @param out_v2_size 输出:V2 block value 大小
 * @return 0=成功 / -1=失败
 */
int extract_v2_block(const uint8_t *data, size_t size,
                     size_t *out_v2_offset, size_t *out_v2_size) {
    size_t block_start, block_size;
    if (locate_signing_block(data, size, &block_start, &block_size) != 0) {
        return -1;
    }

    /* 优先 V2,回退 V3 */
    if (find_id_value_pair(data, block_start, block_size, APK_SIG_BLOCK_V2_ID,
                           out_v2_offset, out_v2_size) == 0) {
        LOGI("使用 V2 签名块");
        return 0;
    }
    if (find_id_value_pair(data, block_start, block_size, APK_SIG_BLOCK_V3_ID,
                           out_v2_offset, out_v2_size) == 0) {
        LOGI("使用 V3 签名块(兼容)");
        return 0;
    }

    LOGW("未找到 V2/V3 签名块");
    return -1;
}
