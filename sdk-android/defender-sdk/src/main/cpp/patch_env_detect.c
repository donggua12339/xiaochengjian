/**
 * patch_env_detect.c - 通用签名绕过环境检测(Native 层)
 *
 * 不依赖特定工具名称,检测绕过行为的通用特征:
 *
 *  1. maps 真实性验证:
 *     - 扫描 /proc/self/maps 中所有 .apk 映射
 *     - 正常 APK 映射路径必须以 /data/app/ 开头
 *     - /data/data/ 或 /data/user/ 下的 .apk 映射 = 异常
 *
 *  2. dl_iterate_phdr 交叉验证:
 *     - 遍历 linker 内部已加载模块列表(不读 maps 文件)
 *     - 检查是否有 /data/data/ 下的 .apk 或可疑 .so
 *     - 与 maps 结果交叉对比
 *
 *  3. /proc/self/fd 扫描:
 *     - 用 readlinkat 检查每个 fd 指向的真实路径
 *     - 找 base.apk 的真实路径
 *     - 与 maps/packageCodePath 对比
 *
 * 对抗 SRPatch Lv.4 SVC Hook:
 *  - dl_iterate_phdr 读 linker 内部数据,不经过 syscall
 *  - /proc/self/fd readlinkat 是不同 syscall,SRPatch 可能未 hook
 *  - 即使 maps 被篡改,dl_iterate_phdr 和 fd 扫描提供独立验证
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <link.h>
#include <android/log.h>

#define TAG "DefenderPatchEnv"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ============= inline syscall(复用 mmap_reader.c 的模式) ============= */

#if defined(__aarch64__)
static int pe_openat(const char *path, int flags) {
    int fd;
    __asm__ volatile(
        "mov x8, #56\n mov x0, #-100\n mov x1, %1\n mov x2, %2\n svc #0\n mov %0, x0\n"
        : "=r"(fd) : "r"(path), "r"(flags)
        : "x0", "x1", "x2", "x8", "memory"
    );
    return fd;
}
static ssize_t pe_read(int fd, void *buf, size_t count) {
    ssize_t ret;
    __asm__ volatile(
        "mov x8, #63\n mov x0, %1\n mov x1, %2\n mov x2, %3\n svc #0\n mov %0, x0\n"
        : "=r"(ret) : "r"(fd), "r"(buf), "r"(count)
        : "x0", "x1", "x2", "x8", "memory"
    );
    return ret;
}
static int pe_close(int fd) {
    int ret;
    __asm__ volatile(
        "mov x8, #57\n mov x0, %1\n svc #0\n mov %0, x0\n"
        : "=r"(ret) : "r"(fd)
        : "x0", "x8", "memory"
    );
    return ret;
}
/* readlinkat: __NR_readlinkat=78 */
static ssize_t pe_readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz) {
    ssize_t ret;
    __asm__ volatile(
        "mov x8, #78\n mov x0, %1\n mov x1, %2\n mov x2, %3\n mov x3, %4\n svc #0\n mov %0, x0\n"
        : "=r"(ret) : "r"(dirfd), "r"(path), "r"(buf), "r"(bufsiz)
        : "x0", "x1", "x2", "x3", "x8", "memory"
    );
    return ret;
}
/* getdents64: __NR_getdents64=61 */
struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    uint16_t d_reclen;
    unsigned char d_type;
    char d_name[];
};
static int pe_getdents64(int fd, void *buf, size_t count) {
    int ret;
    __asm__ volatile(
        "mov x8, #61\n mov x0, %1\n mov x1, %2\n mov x2, %3\n svc #0\n mov %0, x0\n"
        : "=r"(ret) : "r"(fd), "r"(buf), "r"(count)
        : "x0", "x1", "x2", "x8", "memory"
    );
    return ret;
}
#else
static int pe_openat(const char *path, int flags) { return open(path, flags); }
static ssize_t pe_read(int fd, void *buf, size_t count) { return read(fd, buf, count); }
static int pe_close(int fd) { return close(fd); }
static ssize_t pe_readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz) {
    return readlinkat(dirfd, path, buf, bufsiz);
}
struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    uint16_t d_reclen;
    unsigned char d_type;
    char d_name[];
};
static int pe_getdents64(int fd, void *buf, size_t count) {
    return syscall(61, fd, buf, count);
}
#endif

/* ============= 检测结果 ============= */

typedef struct {
    int maps_apk_anomaly;       /* maps 中有非 /data/app/ 的 .apk 映射 */
    int dl_apk_anomaly;         /* dl_iterate_phdr 中有非标准路径 .apk */
    int fd_apk_anomaly;         /* /proc/self/fd 中 base.apk 不在 /data/app/ */
    int suspicious_so_count;    /* 可疑 .so 数量 */
    char maps_apk_path[512];    /* maps 中的 .apk 路径 */
    char fd_apk_path[512];      /* fd 扫描中的 base.apk 路径 */
    char suspicious_so[4][256]; /* 可疑 .so 路径(最多 4 个) */
    int score;                  /* 风险分数 */
} patch_env_result_t;

static patch_env_result_t g_result;

/* ============= 辅助:判断路径是否在应用私有目录 ============= */

/**
 * 判断路径是否在应用私有数据目录(/data/data/<pkg>/ 或 /data/user/0/<pkg>/)
 * 绕过工具只能在应用私有目录创建文件,系统组件不会在此目录操作。
 * 因此只需正向匹配私有目录,无需维护系统路径排除列表。
 */
static int is_in_app_private_dir(const char *path) {
    return (strstr(path, "/data/data/") != NULL ||
            strstr(path, "/data/user/") != NULL);
}

/** 去除路径末尾的换行/空格 */
static void trim_path(char *path) {
    char *end = path + strlen(path) - 1;
    /* 去掉末尾空白 + ART 匿名映射的 ] 后缀
     * 格式: [anon:dalvik-classes.dex extracted in memory from /data/app/.../base.apk] */
    while (end >= path && (*end == '\n' || *end == '\r' || *end == ' ' || *end == ']'))
        *end-- = '\0';
}

/* ============= 1. maps 扫描 ============= */

static void scan_maps_for_apk(void) {
    int fd = pe_openat("/proc/self/maps", 0);
    if (fd < 0) return;

    char buf[8192];
    char line[1024];
    int line_pos = 0;
    ssize_t n;

    while ((n = pe_read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        for (int i = 0; i < n; i++) {
            if (buf[i] == '\n' || line_pos >= (int)sizeof(line) - 1) {
                line[line_pos] = '\0';

                /* 搜索 .apk 映射 */
                if (strstr(line, ".apk")) {
                    char *path_start = strrchr(line, ' ');
                    if (path_start) path_start++;
                    else path_start = line;
                    trim_path(path_start);

                    if (strncmp(path_start, "/data/app/", 10) == 0) {
                        /* 正常安装路径,记录用于交叉验证 */
                        if (g_result.maps_apk_path[0] == '\0') {
                            strncpy(g_result.maps_apk_path, path_start,
                                    sizeof(g_result.maps_apk_path) - 1);
                        }
                    } else if (is_in_app_private_dir(path_start)) {
                        /* 应用私有目录下的 .apk = 绕过工具副本(SRPatch/LSPatch) */
                        g_result.maps_apk_anomaly = 1;
                        strncpy(g_result.maps_apk_path, path_start,
                                sizeof(g_result.maps_apk_path) - 1);
                        LOGE("maps 异常 .apk 映射(私有目录): %s", path_start);
                        g_result.score += 30;
                    }
                    /* 其他路径(/system/ /product/ /dalvik-cache/ 等)不标记 */
                }

                /* 搜索可疑 .so: 仅在应用私有目录下 */
                if (strstr(line, ".so") && is_in_app_private_dir(line)) {
                    if (!strstr(line, "/code_cache/") && !strstr(line, "/oat/")) {
                        char *path_start = strrchr(line, ' ');
                        if (path_start) {
                            path_start++;
                            trim_path(path_start);
                            if (g_result.suspicious_so_count < 4) {
                                strncpy(g_result.suspicious_so[g_result.suspicious_so_count],
                                        path_start, 255);
                                g_result.suspicious_so_count++;
                            }
                        }
                    }
                }

                line_pos = 0;
            } else {
                line[line_pos++] = buf[i];
            }
        }
    }
    pe_close(fd);

    if (g_result.suspicious_so_count > 0) {
        LOGE("maps 中发现 %d 个可疑 .so(应用私有目录):", g_result.suspicious_so_count);
        for (int i = 0; i < g_result.suspicious_so_count; i++) {
            LOGE("  %s", g_result.suspicious_so[i]);
        }
        g_result.score += 20 * g_result.suspicious_so_count;
    }
}

/* ============= 2. dl_iterate_phdr 交叉验证 ============= */

static int dl_callback(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    (void)data;

    if (!info->dlpi_name || info->dlpi_name[0] == '\0') return 0;

    const char *name = info->dlpi_name;

    /* 只检测应用私有目录下的 .apk(正向匹配,无需排除列表) */
    if (strstr(name, ".apk") && is_in_app_private_dir(name)) {
        LOGE("dl_iterate_phdr 异常 .apk(私有目录): %s", name);
        g_result.dl_apk_anomaly = 1;
        g_result.score += 30;
    }

    return 0;
}

static void scan_dl_iterate(void) {
    dl_iterate_phdr(dl_callback, NULL);
}

/* ============= 3. /proc/self/fd 扫描 ============= */

static void scan_proc_fd(void) {
    int dir_fd = pe_openat("/proc/self/fd", 0);
    if (dir_fd < 0) return;

    char buf[4096];
    int nread;

    while ((nread = pe_getdents64(dir_fd, buf, sizeof(buf))) > 0) {
        char *pos = buf;
        while (pos < buf + nread) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)pos;

            /* 跳过 . 和 .. */
            if (d->d_name[0] != '.') {
                /* readlinkat 获取 fd 指向的真实路径 */
                char link_path[512];
                ssize_t len = pe_readlinkat(dir_fd, d->d_name, link_path, sizeof(link_path) - 1);
                if (len > 0) {
                    link_path[len] = '\0';

                    /* 检查是否指向 base.apk */
                    if (strstr(link_path, "base.apk")) {
                        strncpy(g_result.fd_apk_path, link_path,
                                sizeof(g_result.fd_apk_path) - 1);

                        /* 检查是否在 /data/app/ 下 */
                        if (strncmp(link_path, "/data/app/", 10) != 0) {
                            LOGE("/proc/self/fd 中 base.apk 路径异常: %s", link_path);
                            g_result.fd_apk_anomaly = 1;
                            g_result.score += 25;
                        } else {
                            LOGI("/proc/self/fd 中 base.apk 路径正常: %s", link_path);
                        }
                    }
                }
            }

            pos += d->d_reclen;
        }
    }
    pe_close(dir_fd);
}

/* ============= 综合检测入口 ============= */

/**
 * 运行通用绕过环境检测
 * @return 风险分数(0=安全, ≥40=疑似被绕过)
 */
int patch_env_detect(void) {
    memset(&g_result, 0, sizeof(g_result));

    LOGI("=== 通用绕过环境检测(Native 层)===");

    /* 1. maps 扫描 */
    scan_maps_for_apk();

    /* 2. dl_iterate_phdr 交叉验证 */
    scan_dl_iterate();

    /* 3. /proc/self/fd 扫描 */
    scan_proc_fd();

    /* 4. 交叉验证: maps 路径 vs fd 路径 */
    if (g_result.maps_apk_path[0] && g_result.fd_apk_path[0]) {
        if (strcmp(g_result.maps_apk_path, g_result.fd_apk_path) != 0) {
            /* 去掉 maps 路径中可能的 !/ 后缀再比较 */
            char maps_clean[512];
            strncpy(maps_clean, g_result.maps_apk_path, sizeof(maps_clean) - 1);
            char *bang = strstr(maps_clean, "!/");
            if (bang) *bang = '\0';

            if (strcmp(maps_clean, g_result.fd_apk_path) != 0) {
                LOGE("路径不一致! maps=%s vs fd=%s", maps_clean, g_result.fd_apk_path);
                g_result.score += 20;
            }
        }
    }

    LOGI("检测结果: score=%d maps_anomaly=%d dl_anomaly=%d fd_anomaly=%d suspicious_so=%d",
         g_result.score, g_result.maps_apk_anomaly, g_result.dl_apk_anomaly,
         g_result.fd_apk_anomaly, g_result.suspicious_so_count);

    return g_result.score;
}

/**
 * 获取检测结果详情(JSON 字符串,供 JNI 层使用)
 */
int patch_env_get_result(char *buf, size_t buf_size) {
    return snprintf(buf, buf_size,
        "{\"nativeScore\":%d,"
        "\"mapsApkAnomaly\":%d,"
        "\"dlApkAnomaly\":%d,"
        "\"fdApkAnomaly\":%d,"
        "\"suspiciousSoCount\":%d,"
        "\"mapsApkPath\":\"%s\","
        "\"fdApkPath\":\"%s\"}",
        g_result.score,
        g_result.maps_apk_anomaly,
        g_result.dl_apk_anomaly,
        g_result.fd_apk_anomaly,
        g_result.suspicious_so_count,
        g_result.maps_apk_path,
        g_result.fd_apk_path);
}
