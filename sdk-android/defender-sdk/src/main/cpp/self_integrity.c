/**
 * self_integrity.c - SO 自身 .text 段 CRC 校验(方案 B 核心)
 *
 * 详见 xcj_blue_demo_v2.1.1_prompt.md §2.6
 *
 * 原理:
 *  计算 SO 文件 .text 段(可执行代码)的 CRC32,与预埋值比对。
 *  若 SO 被 IDA Pro 手动修改(如改签名校验函数返回指令 mov w0,#1),
 *  .text CRC 不匹配 -> 检测到篡改。
 *
 * 对抗:
 *  - MT Level 3(IDA Pro 改 SO):✅ .text CRC 抓住
 *  - MT 教程的 ldrb w0,[var] -> mov w0,#1 修改:✅ CRC 变化
 *
 * 注意:当前为骨架,预埋 CRC 为占位值 0。
 * 正式版需 post-build 脚本计算真实 .text CRC 写入。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <dlfcn.h>
#include <android/log.h>

#define TAG "DefenderSelfIntegrity"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ============= CRC32 实现 ============= */

static uint32_t crc32_table[256];
static int crc32_inited = 0;

static void init_crc32(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320;
            else crc >>= 1;
        }
        crc32_table[i] = crc;
    }
    crc32_inited = 1;
}

static uint32_t compute_crc32(const uint8_t *data, size_t len) {
    if (!crc32_inited) init_crc32();
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ data[i]) & 0xFF];
    }
    return crc ^ 0xFFFFFFFF;
}

/* ============= 预埋 .text CRC(占位) ============= */

/* 占位值 0,post-build 脚本计算真实 .text CRC 后覆盖 */
static const uint32_t EMBEDDED_TEXT_CRC __attribute__((section(".rodata"))) = 0;

/* ============= .text 段定位 ============= */

/**
 * 用 dladdr 获取当前 SO 的 .text 段
 *
 * @param out_base 输出:.text 起始地址
 * @param out_size 输出:.text 大小
 * @return 0=成功 / -1=失败
 */
static int find_text_section(uintptr_t *out_base, size_t *out_size) {
    Dl_info info;
    if (dladdr((void *)find_text_section, &info) == 0) {
        LOGE("dladdr 失败");
        return -1;
    }

    const char *so_basename = strrchr(info.dli_fname, '/');
    so_basename = so_basename ? so_basename + 1 : info.dli_fname;

    /* 读 /proc/self/maps 找本 SO 的 r-xp 段(.text) */
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return -1;

    char buf[8192];
    char line[512];
    int line_pos = 0;
    int found = 0;

    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf) - 1)) > 0 && !found) {
        buf[n] = '\0';
        for (int i = 0; i < n && !found; i++) {
            if (buf[i] == '\n' || line_pos >= (int)sizeof(line) - 1) {
                line[line_pos] = '\0';
                /* 找 r-xp 段(可执行)且属于本 SO */
                if (strstr(line, " r-xp ") != NULL &&
                    strstr(line, so_basename) != NULL) {
                    uintptr_t start, end;
                    if (sscanf(line, "%lx-%lx", (unsigned long *)&start, (unsigned long *)&end) == 2) {
                        *out_base = start;
                        *out_size = end - start;
                        found = 1;
                    }
                }
                line_pos = 0;
            } else {
                line[line_pos++] = buf[i];
            }
        }
    }
    close(fd);
    return found ? 0 : -1;
}

/* ============= SO 自身完整性校验 ============= */

/**
 * 校验 SO 自身 .text 段 CRC(方案 B 核心)
 *
 * @return 0=校验通过 / 1=校验失败(.text 被篡改) / -1=内部错误(非致命)
 */
int self_integrity_check(void) {
    LOGI("=== SO 自身完整性校验(方案 B)===");

    uintptr_t text_base = 0;
    size_t text_size = 0;
    if (find_text_section(&text_base, &text_size) != 0) {
        LOGE("找不到 .text 段,跳过自校验(非致命)");
        return -1;
    }
    LOGI(".text 段: base=0x%lx size=%zu", (unsigned long)text_base, text_size);

    uint32_t actual_crc = compute_crc32((const uint8_t *)text_base, text_size);
    LOGI(".text 实际 CRC32: 0x%08x", actual_crc);

    /* 预埋 CRC 为占位值 0 时跳过(post-build 未写入) */
    if (EMBEDDED_TEXT_CRC == 0) {
        LOGW("预埋 CRC 为占位值 0,跳过校验(开发阶段,运行 patch_text_hash.py 写入真实 CRC)");
        return 0;
    }

    if (actual_crc == EMBEDDED_TEXT_CRC) {
        LOGI(".text CRC 校验通过");
        return 0;
    }

    LOGE(".text CRC 校验失败! 预期=0x%08x 实际=0x%08x", EMBEDDED_TEXT_CRC, actual_crc);
    LOGE(".text 被篡改(可能 IDA Pro 改返回指令)");
    return 1;
}
