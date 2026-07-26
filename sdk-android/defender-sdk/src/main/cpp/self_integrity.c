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

#define DEFENDER_TAG "DefenderSelfIntegrity"
#include "defender_log.h"

/* T1 自实现 Linker(R4):xcj_loader 暴露的 defender 基址/大小查询 */
extern uintptr_t xcj_loader_get_defender_base(void);
extern size_t xcj_loader_get_defender_size(void);

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
 * T1(R4):若经 cl_dlopen_mem 加载(匿名映射),dladdr 必失败,
 * 回退到 xcj_loader_get_defender_base() 提供的基址 + ELF phdr 解析。
 */
void self_integrity_init(void) {
    if (g_text_inited) return;

    uintptr_t so_base = 0;
    int via_cl = 0;  /* 是否经自实现 Linker 加载 */

    Dl_info info;
    if (dladdr((void *)self_integrity_init, &info) != 0) {
        so_base = (uintptr_t)info.dli_fbase;

        /* 路径合法性检测 */
        if (info.dli_fname) {
            strncpy(g_so_path, info.dli_fname, sizeof(g_so_path) - 1);
            if (strncmp(g_so_path, "/data/app/", 10) == 0) {
                g_path_valid = 1;
            } else if (strstr(g_so_path, "memfd:") || strstr(g_so_path, "libxcj_payload")) {
                g_path_valid = 1;
            } else {
                g_path_valid = 0;
                LOGE("self_integrity_init: .so 路径异常(疑似 SRPatch/LSPatch 重定向)");
            }
        }
    } else {
        /* dladdr 失败 → 尝试 T1 cl 基址 */
        so_base = xcj_loader_get_defender_base();
        if (so_base != 0) {
            via_cl = 1;
            g_path_valid = 1;  /* 匿名映射 = 自研 linker 设计,合法 */
            LOGI("self_integrity_init: 经 T1 cl 加载(匿名映射)");
        } else {
            LOGE("self_integrity_init: dladdr 失败且无 cl 基址");
            return;
        }
    }

    /* 定位 .text 段 */
    if (via_cl) {
        /* 匿名映射:maps 里无路径,直接解析 ELF program headers */
        const uint8_t *base_ptr = (const uint8_t *)so_base;
        /* ELF64 header: e_phoff at offset 32, e_phentsize at 54, e_phnum at 56 */
        uint64_t phoff = *(const uint64_t *)(base_ptr + 32);
        uint16_t phentsize = *(const uint16_t *)(base_ptr + 54);
        uint16_t phnum = *(const uint16_t *)(base_ptr + 56);
        uintptr_t text_start = 0, text_end = 0;
        for (uint16_t i = 0; i < phnum; i++) {
            const uint8_t *ph = base_ptr + phoff + (uintptr_t)i * phentsize;
            uint32_t p_type = *(const uint32_t *)(ph);
            uint32_t p_flags = *(const uint32_t *)(ph + 4);
            if (p_type == 1 /* PT_LOAD */ && (p_flags & 1 /* PF_X */)) {
                uint64_t p_offset = *(const uint64_t *)(ph + 8);
                uint64_t p_vaddr = *(const uint64_t *)(ph + 16);
                uint64_t p_filesz = *(const uint64_t *)(ph + 32);
                text_start = so_base + (uintptr_t)p_vaddr;
                text_end = text_start + (uintptr_t)p_filesz;
                break;
            }
            (void)p_offset;
        }
        if (text_start && text_end > text_start) {
            g_text_base = text_start;
            g_text_size = text_end - text_start;
            g_text_inited = 1;
        }
        return;
    }

    /* 常规路径:从 maps 解析 .text 段 */
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

                uintptr_t start, end;
                char perms[8];
                if (sscanf(line, "%lx-%lx %7s", (unsigned long *)&start, (unsigned long *)&end, perms) == 3) {
                    if (start == so_base) {
                        in_this_so = 1;
                    }
                    if (in_this_so) {
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
        LOGE(".text 段查找失败");
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
        LOGE(".so 从非标准路径加载(SRPatch/LSPatch 重定向)");
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

    LOGE(".text CRC 校验失败(值不符,可能被篡改)");
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
