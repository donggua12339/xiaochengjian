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

/* ============= 预埋 .text CRC + 偏移 + 大小(占位) ============= */

/*
 * post-build 脚本写入:.text CRC32 + .text 相对 load base 偏移 + .text 大小
 * 占位值:0x5AC05AC0 / 0x5AC05AC1 / 0x5AC05AC2(便于搜索定位)
 * 只校验纯 .text 段(排除 .plt/.rodata 等被 linker 重定位修改的段)
 */
#define TEXT_CRC_PLACEHOLDER   0x5AC05AC0
#define TEXT_OFF_PLACEHOLDER   0x5AC05AC1
#define TEXT_SIZE_PLACEHOLDER  0x5AC05AC2

static volatile uint32_t EMBEDDED_TEXT_INFO[3] __attribute__((used, section(".data"))) = {
    TEXT_CRC_PLACEHOLDER,   /* [0] .text CRC32 */
    TEXT_OFF_PLACEHOLDER,   /* [1] .text 偏移(相对 load base / r-xp 起始) */
    TEXT_SIZE_PLACEHOLDER,  /* [2] .text 大小 */
};

/* ============= .text 段定位(主线程初始化时缓存) ============= */

/* 缓存 .text 段基址与大小(由 self_integrity_init 在 JNI_OnLoad 主线程初始化) */
static uintptr_t g_text_base = 0;
static size_t g_text_size = 0;
static int g_text_inited = 0;

/* .so 加载路径检测结果(防 SRPatch/LSPatch 路径重定向) */
static int g_path_valid = -1;  /* -1=未检测 / 0=非法路径 / 1=合法路径 */
static char g_so_path[512] = {0};

/**
 * 初始化 .text 段缓存(必须在主线程 JNI_OnLoad 时调用)
 *
 * 守护线程中 dladdr 可能失败(上下文问题),故在主线程提前缓存。
 */
void self_integrity_init(void) {
    if (g_text_inited) return;

    Dl_info info;
    if (dladdr((void *)self_integrity_init, &info) == 0) {
        LOGE("self_integrity_init: dladdr 失败");
        return;
    }

    /* dli_fbase 是 .so 的加载基址( ELF 头所在地址)。
     * maps 中 .so 的第一个映射(最低地址,通常 r--p)起始 = dli_fbase。
     * .text 段(r-xp)在基址之后,找该 .so 的 r-xp 段即可。 */
    uintptr_t so_base = (uintptr_t)info.dli_fbase;
    LOGI("self_integrity_init: .so 加载基址=0x%lx", (unsigned long)so_base);

    /* 检测 .so 加载路径是否合法(防 SRPatch/LSPatch 路径重定向)
     * 正常 APK 安装在 /data/app/ 下;
     * SRPatch 从 /data/user/0/.../srpatch/base.apk 加载;
     * LSPatch 从 /data/user/0/.../cache/lspatch/origin/xxx.apk 加载 */
    if (info.dli_fname) {
        strncpy(g_so_path, info.dli_fname, sizeof(g_so_path) - 1);
        LOGI("self_integrity_init: .so 加载路径=%s", g_so_path);

        if (strncmp(g_so_path, "/data/app/", 10) == 0) {
            g_path_valid = 1;
            LOGI("self_integrity_init: .so 路径合法(/data/app/)");
        } else {
            g_path_valid = 0;
            LOGE("self_integrity_init: .so 路径异常! 非 /data/app/ 路径(疑似 SRPatch/LSPatch 重定向)");
        }
    }

    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return;

    char buf[8192];
    char line[1024];
    int line_pos = 0;
    int found = 0;
    uintptr_t text_start = 0, text_end = 0;
    int in_this_so = 0;

    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf) - 1)) > 0 && !found) {
        buf[n] = '\0';
        for (int i = 0; i < n && !found; i++) {
            if (buf[i] == '\n' || line_pos >= (int)sizeof(line) - 1) {
                line[line_pos] = '\0';

                /* 解析行:start-end perms offset ... path */
                uintptr_t start, end;
                char perms[8];
                if (sscanf(line, "%lx-%lx %7s", (unsigned long *)&start, (unsigned long *)&end, perms) == 3) {
                    /* 找到 .so 基址对应的映射(起始地址 == so_base) */
                    if (start == so_base) {
                        in_this_so = 1;
                    }

                    /* 在本 .so 的映射范围内找 r-xp 段(.text) */
                    if (in_this_so) {
                        /* 检查是否还是同一个 .so(路径含 base.apk 或 .so 名) */
                        char *path = strstr(line, "/");
                        if (path && (strstr(path, "base.apk") || strstr(path, ".so"))) {
                            if (perms[0] == 'r' && perms[2] == 'x') {
                                text_start = start;
                                text_end = end;
                                found = 1;
                            }
                        } else {
                            /* 路径变化,离开本 .so */
                            in_this_so = 0;
                        }
                    }
                }
                line_pos = 0;
            } else {
                line[line_pos++] = buf[i];
            }
        }
    }
    close(fd);

    if (found) {
        g_text_base = text_start;
        g_text_size = text_end - text_start;
        g_text_inited = 1;
        LOGI(".text 段缓存: base=0x%lx size=%zu", (unsigned long)g_text_base, g_text_size);
    } else {
        LOGE(".text 段查找失败(so_base=0x%lx)", (unsigned long)so_base);
    }
}

/* ============= SO 自身完整性校验 ============= */

/**
 * 校验 SO 自身 .text 段 CRC(方案 B 核心)
 *
 * @return 0=校验通过 / 1=校验失败(.text 被篡改) / -1=内部错误(非致命)
 */
int self_integrity_check(void) {
    LOGI("=== SO 自身完整性校验(方案 B)===");

    /* 路径合法性检测(防 SRPatch/LSPatch 路径重定向) */
    if (g_path_valid == 0) {
        LOGE(".so 从非标准路径加载: %s (SRPatch/LSPatch 重定向)", g_so_path);
        return 1;
    }

    /* 用缓存的 .text 基址(主线程初始化时缓存,避免守护线程 dladdr 失败) */
    if (!g_text_inited) {
        self_integrity_init();
    }
    if (!g_text_inited || g_text_size == 0) {
        LOGE("无 .text 段缓存,跳过自校验(非致命)");
        return -1;
    }

    /* 预埋 CRC 为占位值 = .so 未被正确初始化(可能被 MT 替换) */
    if (EMBEDDED_TEXT_INFO[0] == TEXT_CRC_PLACEHOLDER) {
        LOGE("预埋 CRC 为占位值,.so 未被正确初始化(可能被替换)");
        return 1;  /* 失败 */
    }

    /* 使用 post-build 写入的 .text 偏移和大小(只校验纯 .text,排除 .plt) */
    uint32_t text_offset = EMBEDDED_TEXT_INFO[1];
    uint32_t text_size = EMBEDDED_TEXT_INFO[2];
    uint32_t expected_crc = EMBEDDED_TEXT_INFO[0];

    if (text_offset == 0 || text_size == 0) {
        LOGW(".text 偏移/大小为 0,回退到整个 r-xp 段");
        text_offset = 0;
        text_size = (uint32_t)g_text_size;
    }

    uintptr_t check_base = g_text_base + text_offset;
    LOGI(".text 段: base=0x%lx offset=%u size=%u", (unsigned long)check_base, text_offset, text_size);

    uint32_t actual_crc = compute_crc32((const uint8_t *)check_base, text_size);
    LOGI(".text 实际 CRC32: 0x%08x (预期: 0x%08x)", actual_crc, expected_crc);

    if (actual_crc == expected_crc) {
        LOGI(".text CRC 校验通过");
        return 0;
    }

    LOGE(".text CRC 校验失败! 预期=0x%08x 实际=0x%08x", expected_crc, actual_crc);
    LOGE(".text 被篡改(可能 IDA Pro 改返回指令)");
    return 1;
}

/**
 * 获取 .so 加载路径合法性(供 JNI/UI 查询)
 * @return 1=合法(/data/app/) / 0=非法(重定向) / -1=未检测
 */
int self_integrity_path_valid(void) {
    return g_path_valid;
}

/**
 * 获取 .so 加载路径字符串
 */
const char *self_integrity_get_so_path(void) {
    return g_so_path;
}
