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
#else
static int ic_openat(const char *path, int flags) { return open(path, flags); }
static ssize_t ic_read(int fd, void *buf, size_t count) { return read(fd, buf, count); }
static int ic_close(int fd) { return close(fd); }
#endif

/* ============= CRC32 实现 ============= */

static unsigned int crc32_table[256];
static int crc32_table_init = 0;

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
    crc32_table_init = 1;
}

static unsigned int compute_crc32(const unsigned char *data, size_t len) {
    if (!crc32_table_init) init_crc32_table();
    unsigned int crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ data[i]) & 0xFF];
    }
    return crc ^ 0xFFFFFFFF;
}

/* ============= 层 2:DEX CRC 逐文件校验 ============= */

/**
 * 预期 CRC 表(编译时生成,写入 .rodata)
 *
 * 占位:空表(开发阶段)
 * 正式版:Packer 封装时遍历 APK 所有 entry,计算 CRC32,生成表
 */
static const char *EXPECTED_CRC_ENTRIES[] __attribute__((section(".rodata"))) = {
    NULL  /* 占位 */
};

/**
 * 层 2:DEX CRC 逐文件校验
 *
 * 遍历 APK 内所有 .dex 文件,计算 CRC32,与预期比对
 *
 * 简化版:计算 classes.dex 的 CRC
 * 正式版:解析 ZIP 结构,遍历所有 entry
 *
 * @param apk_path APK 文件路径
 * @return 0=校验通过 / 1=校验失败 / -1=内部错误
 */
int integrity_check_crc(const char *apk_path) {
    LOGI("=== 层 2:DEX CRC 校验 ===");

    /* 简化版:计算整个 APK 文件的 CRC32 作为占位 */
    int fd = ic_openat(apk_path, 0);
    if (fd < 0) {
        LOGE("打开 APK 失败");
        return -1;
    }

    unsigned char buf[8192];
    unsigned int crc = 0xFFFFFFFF;
    ssize_t n;
    if (!crc32_table_init) init_crc32_table();

    while ((n = ic_read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            crc = (crc >> 8) ^ crc32_table[(crc ^ buf[i]) & 0xFF];
        }
    }
    ic_close(fd);
    crc ^= 0xFFFFFFFF;

    LOGI("APK CRC32: 0x%08x", crc);

    /* 占位:不做比对(正式版与 EXPECTED_CRC_ENTRIES 比对) */
    LOGW("CRC 校验占位(正式版与 .rodata 预期 CRC 比对)");
    return 0;
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
 * 占位:空(开发阶段)
 * 正式版:Packer 封装时遍历 APK 所有 entry,生成文件列表
 */
static const char *EXPECTED_FILE_LIST[] __attribute__((section(".rodata"))) = {
    NULL  /* 占位 */
};

/**
 * 层 4:文件列表完整性
 *
 * 遍历 APK entry,检测:
 *  - 额外文件(不在预期列表)-> 按类型 kill/warn
 *  - 缺失文件(在预期列表但 APK 没有)-> kill
 *
 * 简化版:仅统计 entry 数量
 * 正式版:解析 ZIP 结构,逐 entry 比对
 *
 * @param apk_path APK 文件路径
 * @return 0=安全 / 1=kill(额外 .so/.dex)/ 2=warn(额外资源)/ -1=内部错误
 */
int integrity_check_file_list(const char *apk_path) {
    LOGI("=== 层 4:文件列表完整性 ===");

    /* 简化版:APK 存在即通过 */
    int fd = ic_openat(apk_path, 0);
    if (fd < 0) {
        LOGE("打开 APK 失败");
        return -1;
    }
    ic_close(fd);

    LOGW("文件列表校验占位(正式版解析 ZIP 遍历 entry)");
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
