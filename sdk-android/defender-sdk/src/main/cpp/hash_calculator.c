/**
 * hash_calculator.c - APK 受保护内容哈希计算(方案 A 核心)
 *
 * 详见 xcj_blue_demo_v2.1.1_prompt.md §方案 A + 附录 A
 *
 * AOSP V2 签名哈希计算规则(官方文档已确认):
 *  APK 分为 4 区段:
 *    区段 1:ZIP entries 内容(偏移 0 到 Signing Block 起始)
 *    区段 2:APK Signing Block(本身不哈希,但内部 signed data 受保护)
 *    区段 3:ZIP Central Directory(Signing Block 之后到 EOCD)
 *    区段 4:ZIP EOCD(文件末尾,中央目录偏移字段替换为 Signing Block 偏移)
 *
 *  V2 保护区段 1 + 3 + 4(区段 2 的 signed data 在签名块内部,运行时不校验)
 *
 *  哈希方式(1MB 分块 Merkle 树):
 *    每区段切分为 1MB(2^20)块,最后一块可能较短
 *    每块 digest = 0xa5(1 byte) + chunk length(uint32 LE) + chunk contents
 *    顶层 digest = 0x5a(1 byte) + chunk count(uint32 LE) + 所有块 digest 拼接
 *
 *  EOCD 偏移替换:区段 4 哈希时,EOCD 的中央目录偏移字段(EOCD+16,4字节)
 *  必须替换为 Signing Block 偏移(AOSP 官方要求)。
 *
 * 参考:
 *  - AOSP source.android.com/security/apksigning/v2
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <android/log.h>

#define TAG "DefenderHashCalc"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* 1MB 分块(2^20) */
#define CHUNK_SIZE (1 << 20)

/* ============= SHA-256 实现(复用 integrity.c 的 defender_sha256) ============= */

extern void defender_sha256(const unsigned char *data, size_t len, unsigned char *out);

/* ============= 小端读取辅助 ============= */

static uint16_t hc_read_le16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t hc_read_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ============= .so 排除(解决 hash 鸡生蛋问题) ============= */

/*
 * hash_storage 在 .so 的 .data 段,post-build 写入真实 hash 后 .so 内容变化,
 * 导致 APK section 1 的 hash 也变化(鸡生蛋)。
 *
 * 解决:计算 hash 时,将 defender .so 的 ZIP 条目(local file entry + CD entry)
 * 整体置零,使 hash 与 .so 内容无关。.so 自身完整性由方案 B(self_integrity)保护。
 */

#define MAX_EXCLUDE_RANGES 8  /* 最多 4 个 ABI × 2(local + CD) */

typedef struct {
    size_t offset;  /* 在 APK 中的偏移 */
    size_t size;    /* 大小 */
} exclude_range;

/**
 * 在 Central Directory 中查找 defender .so 条目,
 * 返回需要排除的范围(local file entry + CD entry)
 */
static int find_so_exclude_ranges(const uint8_t *data, size_t size,
                                   size_t cd_offset, size_t cd_size,
                                   exclude_range *ranges, int max_ranges) {
    int count = 0;
    size_t pos = cd_offset;
    size_t cd_end = cd_offset + cd_size;

    while (pos + 46 <= cd_end && count + 2 <= max_ranges) {
        /* Central Directory entry signature: 0x02014b50 */
        if (data[pos] != 0x50 || data[pos + 1] != 0x4b ||
            data[pos + 2] != 0x01 || data[pos + 3] != 0x02)
            break;

        uint16_t fn_len  = hc_read_le16(data + pos + 28);
        uint16_t ef_len  = hc_read_le16(data + pos + 30);
        uint16_t fc_len  = hc_read_le16(data + pos + 32);
        uint32_t comp_size   = hc_read_le32(data + pos + 20);
        uint32_t local_offset = hc_read_le32(data + pos + 42);

        if (fn_len > 0 && pos + 46 + fn_len <= cd_end) {
            const char *fn = (const char *)(data + pos + 46);
            /* 匹配 lib/<abi>/libxcj_defender.so */
            int is_defender = (fn_len >= 4 && strncmp(fn, "lib/", 4) == 0);
            if (is_defender) {
                const char *so_name = "libxcj_defender.so";
                size_t so_name_len = 17;
                is_defender = 0;
                for (uint16_t j = 4; j + so_name_len <= fn_len; j++) {
                    if (strncmp(fn + j, so_name, so_name_len) == 0) {
                        is_defender = 1;
                        break;
                    }
                }
            }

            if (is_defender) {
                /* CD entry 范围 */
                size_t cd_entry_size = 46 + fn_len + ef_len + fc_len;
                ranges[count].offset = pos;
                ranges[count].size = cd_entry_size;
                count++;

                /* Local file entry 范围 */
                if (local_offset + 30 <= size && local_offset < cd_offset) {
                    uint16_t lfn_len = hc_read_le16(data + local_offset + 26);
                    uint16_t lef_len = hc_read_le16(data + local_offset + 28);
                    size_t local_entry_size = 30 + lfn_len + lef_len + comp_size;
                    ranges[count].offset = local_offset;
                    ranges[count].size = local_entry_size;
                    count++;
                }
            }
        }

        pos += 46 + fn_len + ef_len + fc_len;
    }

    return count;
}

/**
 * 将排除范围在缓冲区中置零
 */
static void apply_exclusions(uint8_t *buf, size_t buf_offset, size_t buf_size,
                              const exclude_range *ranges, int range_count) {
    for (int i = 0; i < range_count; i++) {
        size_t r_start = ranges[i].offset;
        size_t r_end = r_start + ranges[i].size;
        /* 计算与缓冲区的交集 */
        size_t b_start = buf_offset;
        size_t b_end = buf_offset + buf_size;
        if (r_start < b_end && r_end > b_start) {
            size_t z_start = (r_start > b_start ? r_start : b_start) - b_start;
            size_t z_end = (r_end < b_end ? r_end : b_end) - b_start;
            memset(buf + z_start, 0, z_end - z_start);
        }
    }
}

/* ============= 区段哈希计算 ============= */

/**
 * 计算一个区段的 1MB 分块 Merkle digest
 *
 * 每块 digest = SHA-256(0xa5 + chunk_length(LE32) + chunk_contents)
 * 区段 digest = SHA-256(0x5a + chunk_count(LE32) + 所有块 digest 拼接)
 *
 * @param data 完整 APK 内存映射
 * @param segment_offset 区段起始偏移
 * @param segment_size 区段大小
 * @param patch_offset 需要替换的 4 字节偏移(EOCD 中央目录偏移字段,-1 表示不替换)
 * @param patch_value 替换值(Signing Block 偏移)
 * @param out_digest 输出:32 字节 SHA-256
 * @return 0=成功 / -1=失败
 */
static int compute_segment_digest(const uint8_t *data,
                                  size_t segment_offset, size_t segment_size,
                                  long patch_offset, uint32_t patch_value,
                                  uint8_t out_digest[32]) {
    if (segment_size == 0) {
        /* 空区段:chunk_count=0 */
        uint8_t header[5] = {0x5a, 0x00, 0x00, 0x00, 0x00};
        defender_sha256(header, 5, out_digest);
        return 0;
    }

    /* 计算块数 */
    size_t chunk_count = (segment_size + CHUNK_SIZE - 1) / CHUNK_SIZE;
    if (chunk_count > 65535) {
        LOGE("区段块数过多: %zu", chunk_count);
        return -1;
    }

    /* 拼接所有块 digest:0x5a + chunk_count(LE32) + digests */
    size_t buf_size = 5 + chunk_count * 32;
    uint8_t *buf = (uint8_t *)malloc(buf_size);
    if (!buf) return -1;

    buf[0] = 0x5a;
    buf[1] = (uint8_t)(chunk_count & 0xff);
    buf[2] = (uint8_t)((chunk_count >> 8) & 0xff);
    buf[3] = (uint8_t)((chunk_count >> 16) & 0xff);
    buf[4] = (uint8_t)((chunk_count >> 24) & 0xff);

    /* 逐块计算 */
    size_t pos = segment_offset;
    for (size_t i = 0; i < chunk_count; i++) {
        size_t chunk_len = (pos + CHUNK_SIZE <= segment_offset + segment_size)
                               ? CHUNK_SIZE
                               : (segment_offset + segment_size - pos);

        /* 块 digest = SHA-256(0xa5 + chunk_len(LE32) + chunk_contents) */
        size_t chunk_buf_size = 5 + chunk_len;
        uint8_t *chunk_buf = (uint8_t *)malloc(chunk_buf_size);
        if (!chunk_buf) { free(buf); return -1; }

        chunk_buf[0] = 0xa5;
        chunk_buf[1] = (uint8_t)(chunk_len & 0xff);
        chunk_buf[2] = (uint8_t)((chunk_len >> 8) & 0xff);
        chunk_buf[3] = (uint8_t)((chunk_len >> 16) & 0xff);
        chunk_buf[4] = (uint8_t)((chunk_len >> 24) & 0xff);

        /* 复制块内容,处理 EOCD 偏移替换 */
        memcpy(chunk_buf + 5, data + pos, chunk_len);

        /* 如果 patch_offset 在当前块内,替换 4 字节 */
        long abs_patch = patch_offset;
        if (abs_patch >= 0 && abs_patch >= (long)pos &&
            abs_patch + 4 <= (long)(pos + chunk_len)) {
            size_t patch_in_chunk = (size_t)(abs_patch - (long)pos);
            chunk_buf[5 + patch_in_chunk] = (uint8_t)(patch_value & 0xff);
            chunk_buf[5 + patch_in_chunk + 1] = (uint8_t)((patch_value >> 8) & 0xff);
            chunk_buf[5 + patch_in_chunk + 2] = (uint8_t)((patch_value >> 16) & 0xff);
            chunk_buf[5 + patch_in_chunk + 3] = (uint8_t)((patch_value >> 24) & 0xff);
        }

        defender_sha256(chunk_buf, chunk_buf_size, buf + 5 + i * 32);
        free(chunk_buf);
        pos += chunk_len;
    }

    defender_sha256(buf, buf_size, out_digest);
    free(buf);
    return 0;
}

/* ============= APK 整体哈希(4 区段) ============= */

/**
 * 计算 APK 受保护内容的哈希(方案 A 核心)
 *
 * 哈希范围(区段 1 + 3 + 4):
 *  - 区段 1:偏移 0 到 Signing Block 起始
 *  - 区段 3:Signing Block 结束到 EOCD 起始
 *  - 区段 4:EOCD(中央目录偏移字段替换为 Signing Block 偏移)
 *
 * @param data APK 内存映射
 * @param size APK 大小
 * @param block_start Signing Block 起始偏移
 * @param block_size Signing Block 总大小
 * @param out_hash 输出:32 字节 SHA-256(区段1 || 区段3 || 区段4 的 digest 拼接后 SHA-256)
 * @return 0=成功 / -1=失败
 */
int compute_apk_protected_hash(const uint8_t *data, size_t size,
                               size_t block_start, size_t block_size,
                               uint8_t out_hash[32]) {
    /* 定位 EOCD */
    long eocd = -1;
    for (size_t i = size - 22; i > 0; i--) {
        if (data[i] == 0x50 && data[i + 1] == 0x4b &&
            data[i + 2] == 0x05 && data[i + 3] == 0x06) {
            eocd = (long)i;
            break;
        }
    }
    if (eocd < 0) {
        LOGE("计算哈希:找不到 EOCD");
        return -1;
    }

    /* 区段 1:0 到 block_start */
    size_t seg1_offset = 0;
    size_t seg1_size = block_start;

    /* 区段 3:block_start + block_size 到 eocd */
    size_t seg3_offset = block_start + block_size;
    size_t seg3_size = (size_t)eocd - seg3_offset;

    /* 区段 4:eocd 到 size */
    size_t seg4_offset = (size_t)eocd;
    size_t seg4_size = size - (size_t)eocd;

    /* EOCD 偏移替换:EOCD + 16 的 4 字节替换为 block_start */
    long patch_offset = eocd + 16;
    uint32_t patch_value = (uint32_t)block_start;

    LOGI("哈希区段: seg1=[0,%zu) seg3=[%zu,%zu) seg4=[%zu,%zu) patch@%ld=%u",
         seg1_size, seg3_offset, seg3_offset + seg3_size,
         seg4_offset, seg4_offset + seg4_size, patch_offset, patch_value);

    /* 查找 defender .so 排除范围(解决鸡生蛋问题) */
    exclude_range ranges[MAX_EXCLUDE_RANGES];
    int range_count = find_so_exclude_ranges(data, size, seg3_offset, seg3_size,
                                              ranges, MAX_EXCLUDE_RANGES);
    if (range_count > 0) {
        LOGI("排除 defender .so 条目: %d 个范围", range_count);
    }

    /* 计算三个区段的 digest */
    uint8_t digest1[32], digest3[32], digest4[32];

    /* 区段 1:复制并置零 .so local file entry */
    if (range_count > 0 && seg1_size > 0) {
        uint8_t *seg1_copy = (uint8_t *)malloc(seg1_size);
        if (!seg1_copy) { LOGE("区段 1 内存分配失败"); return -1; }
        memcpy(seg1_copy, data, seg1_size);
        apply_exclusions(seg1_copy, seg1_offset, seg1_size, ranges, range_count);
        int r = compute_segment_digest(seg1_copy, 0, seg1_size, -1, 0, digest1);
        free(seg1_copy);
        if (r != 0) { LOGE("区段 1 哈希失败"); return -1; }
    } else {
        if (compute_segment_digest(data, seg1_offset, seg1_size,
                                   -1, 0, digest1) != 0) {
            LOGE("区段 1 哈希失败");
            return -1;
        }
    }

    /* 区段 3:复制并置零 .so CD entry */
    if (range_count > 0 && seg3_size > 0) {
        uint8_t *seg3_copy = (uint8_t *)malloc(seg3_size);
        if (!seg3_copy) { LOGE("区段 3 内存分配失败"); return -1; }
        memcpy(seg3_copy, data + seg3_offset, seg3_size);
        apply_exclusions(seg3_copy, seg3_offset, seg3_size, ranges, range_count);
        int r = compute_segment_digest(seg3_copy, 0, seg3_size, -1, 0, digest3);
        free(seg3_copy);
        if (r != 0) { LOGE("区段 3 哈希失败"); return -1; }
    } else {
        if (compute_segment_digest(data, seg3_offset, seg3_size,
                                   -1, 0, digest3) != 0) {
            LOGE("区段 3 哈希失败");
            return -1;
        }
    }

    /* 区段 4:EOCD(无 .so 数据,不需排除) */
    if (compute_segment_digest(data, seg4_offset, seg4_size,
                               patch_offset, patch_value, digest4) != 0) {
        LOGE("区段 4 哈希失败");
        return -1;
    }

    /* 最终 hash = SHA-256(digest1 || digest3 || digest4) */
    uint8_t combined[96];
    memcpy(combined, digest1, 32);
    memcpy(combined + 32, digest3, 32);
    memcpy(combined + 64, digest4, 32);
    defender_sha256(combined, 96, out_hash);

    /* 转 hex 打印 */
    char hex[65];
    for (int i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", out_hash[i]);
    hex[64] = '\0';
    LOGI("APK 受保护内容 hash: %s", hex);
    return 0;
}
