/**
 * integrity.c - APK 完整性校验(5 层)
 *
 * 详见 ADR 0088 §IntegrityChecker
 *
 * 5 层校验:
 *  层 1:签名证书 hash(已在 sig_verify.c D 层)
 *  层 2:DEX CRC 逐文件校验(CRC 表内嵌 .rodata)
 *  层 3:.so self-verify(已在 self_verify.c)
 *  层 4:文件列表完整性(遍历 entry,检测额外/缺失文件)
 *  层 5:服务端联动(已在 sig_verify.c C 层)
 *
 * 本文件实现层 2 + 层 4
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <pthread.h>
#include <android/log.h>

#define TAG "DefenderIntegrity"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ============= inline syscall(复用模式) ============= */

#if defined(__aarch64__)
static int ic_openat(const char *path, int flags) {
    int fd;
    __asm__ volatile(
        "mov x8, #56\n"
        "mov x0, #-100\n"
        "mov x1, %1\n"
        "mov x2, %2\n"
        "svc #0\n"
        "mov %0, x0\n"
        : "=r"(fd)
        : "r"(path), "r"(flags)
        : "x0", "x1", "x2", "x8", "memory"
    );
    return fd;
}
static ssize_t ic_read(int fd, void *buf, size_t count) {
    ssize_t ret;
    __asm__ volatile(
        "mov x8, #63\n"
        "mov x0, %1\n"
        "mov x1, %2\n"
        "mov x2, %3\n"
        "svc #0\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(fd), "r"(buf), "r"(count)
        : "x0", "x1", "x2", "x8", "memory"
    );
    return ret;
}
static int ic_close(int fd) {
    int ret;
    __asm__ volatile(
        "mov x8, #57\n"
        "mov x0, %1\n"
        "svc #0\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(fd)
        : "x0", "x8", "memory"
    );
    return ret;
}
static off_t ic_lseek(int fd, off_t offset, int whence) {
    off_t ret;
    __asm__ volatile(
        "mov x8, #62\n"
        "mov x0, %1\n"
        "mov x1, %2\n"
        "mov x2, %3\n"
        "svc #0\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(fd), "r"(offset), "r"(whence)
        : "x0", "x1", "x2", "x8", "memory"
    );
    return ret;
}
#elif defined(__arm__)
#include <sys/syscall.h>
static int ic_openat(const char *path, int flags) {
    return (int)syscall(__NR_openat, AT_FDCWD, path, flags, 0);
}
static ssize_t ic_read(int fd, void *buf, size_t count) {
    return syscall(__NR_read, fd, buf, count);
}
static int ic_close(int fd) {
    return (int)syscall(__NR_close, fd);
}
static off_t ic_lseek(int fd, off_t offset, int whence) {
    return (off_t)syscall(__NR_lseek, fd, offset, whence);
}
#else
static int ic_openat(const char *path, int flags) { return open(path, flags); }
static ssize_t ic_read(int fd, void *buf, size_t count) { return read(fd, buf, count); }
static int ic_close(int fd) { return close(fd); }
static off_t ic_lseek(int fd, off_t offset, int whence) { return lseek(fd, offset, whence); }
#endif

/* ============= CRC32 实现 ============= */

static unsigned int crc32_table[256];
static pthread_once_t crc32_table_once = PTHREAD_ONCE_INIT;

static void init_crc32_table(void) {
    for (unsigned int i = 0; i < 256; i++) {
        unsigned int crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        crc32_table[i] = crc;
    }
}

static unsigned int compute_crc32(const unsigned char *data, size_t len) {
    pthread_once(&crc32_table_once, init_crc32_table);
    unsigned int crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ data[i]) & 0xFF];
    }
    return crc ^ 0xFFFFFFFF;
}

/* ============= H5 修复:ZIP Central Directory 遍历 ============= */

/* ZIP entry 信息(从 Central Directory File Header 解析) */
typedef struct {
    char name[256];
    unsigned int crc32;
    unsigned int comp_size;
    unsigned int uncomp_size;
    unsigned int local_offset;
} zip_entry_t;

/* 遍历回调:返回 0 继续,非 0 中止(并作为 zip_foreach_entry 返回值) */
typedef int (*zip_entry_cb)(const zip_entry_t *entry, void *ctx);

/**
 * 遍历 APK 的 Central Directory,对每个 entry 调用回调
 *
 * @return 0=遍历完成 / 非 0=回调中止或解析失败
 */
static int zip_foreach_entry(const char *apk_path, zip_entry_cb cb, void *ctx) {
    int fd = ic_openat(apk_path, 0);
    if (fd < 0) return -1;

    off_t file_size = ic_lseek(fd, 0, SEEK_END);
    if (file_size < 22) {
        ic_close(fd);
        return -1;
    }

    /* 找 EOCD(signature 0x06054b50,字节序 50 4b 05 06) */
    off_t search_len = file_size < 22 + 65535 ? file_size : 22 + 65535;
    off_t search_start = file_size - search_len;
    static unsigned char buf[22 + 65535];
    ic_lseek(fd, search_start, SEEK_SET);
    ssize_t rd = ic_read(fd, buf, (size_t)search_len);
    if (rd < 22) {
        ic_close(fd);
        return -1;
    }

    off_t eocd = -1;
    for (ssize_t i = rd - 22; i >= 0; i--) {
        if (buf[i] == 0x50 && buf[i + 1] == 0x4b &&
            buf[i + 2] == 0x05 && buf[i + 3] == 0x06) {
            eocd = search_start + i;
            break;
        }
    }
    if (eocd < 0) {
        ic_close(fd);
        return -1;
    }

    /* EOCD:total entries(10-11),CD offset(16-19) */
    unsigned char eocd_buf[22];
    ic_lseek(fd, eocd, SEEK_SET);
    if (ic_read(fd, eocd_buf, 22) != 22) {
        ic_close(fd);
        return -1;
    }
    unsigned int total_entries = (unsigned int)eocd_buf[10] | ((unsigned int)eocd_buf[11] << 8);
    unsigned int cd_offset = (unsigned int)eocd_buf[16] | ((unsigned int)eocd_buf[17] << 8) |
                             ((unsigned int)eocd_buf[18] << 16) | ((unsigned int)eocd_buf[19] << 24);

    /* 遍历 Central Directory File Header(signature 0x02014b50) */
    ic_lseek(fd, cd_offset, SEEK_SET);
    for (unsigned int i = 0; i < total_entries; i++) {
        unsigned char h[46];
        if (ic_read(fd, h, 46) != 46) break;
        if (h[0] != 0x50 || h[1] != 0x4b || h[2] != 0x01 || h[3] != 0x02) break;

        zip_entry_t entry;
        entry.crc32 = (unsigned int)h[16] | ((unsigned int)h[17] << 8) |
                      ((unsigned int)h[18] << 16) | ((unsigned int)h[19] << 24);
        entry.comp_size = (unsigned int)h[20] | ((unsigned int)h[21] << 8) |
                          ((unsigned int)h[22] << 16) | ((unsigned int)h[23] << 24);
        entry.uncomp_size = (unsigned int)h[24] | ((unsigned int)h[25] << 8) |
                            ((unsigned int)h[26] << 16) | ((unsigned int)h[27] << 24);
        unsigned int name_len = (unsigned int)h[28] | ((unsigned int)h[29] << 8);
        unsigned int extra_len = (unsigned int)h[30] | ((unsigned int)h[31] << 8);
        unsigned int comment_len = (unsigned int)h[32] | ((unsigned int)h[33] << 8);
        entry.local_offset = (unsigned int)h[42] | ((unsigned int)h[43] << 8) |
                             ((unsigned int)h[44] << 16) | ((unsigned int)h[45] << 24);

        if (name_len >= sizeof(entry.name)) name_len = sizeof(entry.name) - 1;
        if (ic_read(fd, entry.name, name_len) != (ssize_t)name_len) break;
        entry.name[name_len] = '\0';

        /* 跳过 extra + comment */
        ic_lseek(fd, (off_t)(extra_len + comment_len), SEEK_CUR);

        int ret = cb(&entry, ctx);
        if (ret != 0) {
            ic_close(fd);
            return ret;
        }
    }

    ic_close(fd);
    return 0;
}

/* ============= 层 2:DEX CRC 逐文件校验 ============= */

/**
 * 预期 CRC 表(编译时生成,写入 .rodata)
 *
 * 格式:每项 "entry名:CRC32十六进制"(如 "classes.dex:1a2b3c4d")
 * 占位:空表(开发阶段,Packer 封装时生成)
 */
static const char *EXPECTED_CRC_ENTRIES[] __attribute__((section(".rodata"))) = {
    NULL  /* 占位 */
};

/* 层 2 回调上下文 */
typedef struct {
    int checked;     /* 已校验的 .dex 数 */
    int mismatch;    /* 不匹配数 */
} crc_ctx_t;

/* 在预期表中查 entry 的 CRC,返回 1=找到且匹配 / 0=找到但不匹配 / -1=未找到 */
static int lookup_expected_crc(const char *name, unsigned int crc) {
    char crc_str[9];
    snprintf(crc_str, sizeof(crc_str), "%08x", crc);
    for (int i = 0; EXPECTED_CRC_ENTRIES[i] != NULL; i++) {
        const char *colon = strchr(EXPECTED_CRC_ENTRIES[i], ':');
        if (!colon) continue;
        size_t name_len = (size_t)(colon - EXPECTED_CRC_ENTRIES[i]);
        if (strlen(name) == name_len && strncmp(name, EXPECTED_CRC_ENTRIES[i], name_len) == 0) {
            return strcasecmp(colon + 1, crc_str) == 0 ? 1 : 0;
        }
    }
    return -1;
}

static int crc_check_cb(const zip_entry_t *entry, void *ctx) {
    crc_ctx_t *c = (crc_ctx_t *)ctx;
    size_t len = strlen(entry->name);
    /* 只校验 .dex 文件 */
    if (len >= 4 && strcasecmp(entry->name + len - 4, ".dex") == 0) {
        int r = lookup_expected_crc(entry->name, entry->crc32);
        if (r == 0) {
            LOGE("层 2 CRC 不匹配: %s", entry->name);
            c->mismatch++;
        } else if (r == 1) {
            c->checked++;
        }
        /* r == -1:预期表无此项,跳过 */
    }
    return 0;
}

/**
 * 层 2:DEX CRC 逐文件校验
 *
 * H5 修复:遍历 APK Central Directory,对每个 .dex 用 ZIP 记录的 CRC32
 * 与 .rodata 预期 CRC 表比对。预期表为空时跳过(开发阶段)。
 *
 * @return 0=校验通过 / 1=校验失败 / -1=内部错误
 */
int integrity_check_crc(const char *apk_path) {
    LOGI("=== 层 2:DEX CRC 校验 ===");

    if (EXPECTED_CRC_ENTRIES[0] == NULL) {
        LOGW("层 2 预期 CRC 表为空,跳过(开发阶段,Packer 封装时生成)");
        return 0;
    }

    crc_ctx_t ctx = {0, 0};
    int r = zip_foreach_entry(apk_path, crc_check_cb, &ctx);
    if (r < 0) {
        LOGE("层 2 ZIP 解析失败");
        return -1;
    }

    LOGI("层 2 校验完成: checked=%d mismatch=%d", ctx.checked, ctx.mismatch);
    return ctx.mismatch > 0 ? 1 : 0;
}

/* ============= 层 4:文件列表完整性 ============= */

/**
 * 文件类型分类(决定 kill/warn)
 */
typedef enum {
    FILE_TYPE_KILL,      /* .so / .dex -> kill */
    FILE_TYPE_WARN,      /* .jar / 其他 -> warn */
    FILE_TYPE_IGNORE,    /* META-INF -> 忽略 */
} file_response_t;

static file_response_t classify_extra_file(const char *name) {
    /* 签名文件:忽略 */
    if (strncmp(name, "META-INF/", 9) == 0) {
        return FILE_TYPE_IGNORE;
    }

    /* 可执行代码:kill */
    size_t len = strlen(name);
    if (len >= 4 && strcasecmp(name + len - 4, ".so") == 0) {
        return FILE_TYPE_KILL;
    }
    if (len >= 4 && strcasecmp(name + len - 4, ".dex") == 0) {
        return FILE_TYPE_KILL;
    }

    /* .jar:warn(可含 dex,但可能是资源包) */
    if (len >= 4 && strcasecmp(name + len - 4, ".jar") == 0) {
        return FILE_TYPE_WARN;
    }

    /* 其他:warn */
    return FILE_TYPE_WARN;
}

/**
 * 预期文件列表(编译时生成,写入 .rodata)
 *
 * 格式:每项一个 entry 名(如 "classes.dex", "lib/arm64-v8a/libxxx.so")
 * 占位:空(开发阶段,Packer 封装时生成)
 */
static const char *EXPECTED_FILE_LIST[] __attribute__((section(".rodata"))) = {
    NULL  /* 占位 */
};

static int in_expected_file_list(const char *name) {
    for (int i = 0; EXPECTED_FILE_LIST[i] != NULL; i++) {
        if (strcmp(EXPECTED_FILE_LIST[i], name) == 0) return 1;
    }
    return 0;
}

/* 层 4 回调上下文 */
typedef struct {
    int has_kill;
    int has_warn;
} filelist_ctx_t;

static int filelist_check_cb(const zip_entry_t *entry, void *ctx) {
    filelist_ctx_t *c = (filelist_ctx_t *)ctx;
    if (in_expected_file_list(entry->name)) return 0;  /* 在预期列表,OK */

    /* 额外文件,按类型分类 */
    file_response_t resp = classify_extra_file(entry->name);
    if (resp == FILE_TYPE_KILL) {
        LOGE("层 4 额外可执行文件: %s", entry->name);
        c->has_kill = 1;
    } else if (resp == FILE_TYPE_WARN) {
        LOGW("层 4 额外文件: %s", entry->name);
        c->has_warn = 1;
    }
    /* FILE_TYPE_IGNORE(META-INF 签名文件):忽略 */
    return 0;
}

/**
 * 层 4:文件列表完整性
 *
 * H5 修复:遍历 APK Central Directory,检测不在预期列表的额外文件,
 * 按类型分类(.so/.dex -> kill,.jar/其他 -> warn,META-INF -> 忽略)。
 * 预期列表为空时跳过(开发阶段)。
 *
 * @return 0=安全 / 1=kill(额外 .so/.dex)/ 2=warn(额外资源)/ -1=内部错误
 */
int integrity_check_file_list(const char *apk_path) {
    LOGI("=== 层 4:文件列表完整性 ===");

    if (EXPECTED_FILE_LIST[0] == NULL) {
        LOGW("层 4 预期文件列表为空,跳过(开发阶段,Packer 封装时生成)");
        return 0;
    }

    filelist_ctx_t ctx = {0, 0};
    int r = zip_foreach_entry(apk_path, filelist_check_cb, &ctx);
    if (r < 0) {
        LOGE("层 4 ZIP 解析失败");
        return -1;
    }

    if (ctx.has_kill) return 1;  /* kill */
    if (ctx.has_warn) return 2;  /* warn */
    return 0;
}

/* ============= 组合校验(层 2 + 层 4) ============= */

/**
 * 完整性校验(层 2 + 层 4)
 *
 * 层 1(签名证书 hash)+ 层 3(.so self-verify)+ 层 5(服务端)由其他模块处理
 *
 * @param apk_path APK 文件路径
 * @return 0=安全 / 1=kill / 2=warn / -1=内部错误
 */
int integrity_check(const char *apk_path) {
    LOGI("=== IntegrityChecker(层 2 + 层 4)===");

    /* 层 2:CRC */
    int crc_result = integrity_check_crc(apk_path);
    if (crc_result == 1) {
        LOGE("层 2 CRC 校验失败");
        return 1;  /* kill */
    }

    /* 层 4:文件列表 */
    int list_result = integrity_check_file_list(apk_path);
    if (list_result == 1) {
        LOGE("层 4 检测到额外 .so/.dex");
        return 1;  /* kill */
    }
    if (list_result == 2) {
        LOGW("层 4 检测到额外资源/配置");
        return 2;  /* warn */
    }

    LOGI("IntegrityChecker 通过(层 2 + 层 4)");
    return 0;
}
