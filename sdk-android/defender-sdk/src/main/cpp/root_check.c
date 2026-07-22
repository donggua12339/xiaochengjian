/**
 * root_check.c - Root 检测(Native 层)
 *
 * 详见 ADR 0088 §RootDetector
 *
 * 检测范围:
 *  - 用户态:su 路径 + Magisk 目录 + ro.secure + SELinux + mounts
 *  - BL 锁:verifiedbootstate + flash.locked + veritymode
 *  - 内核级:KernelSU + APatch + 内核版本 + 内核模块 + sepolicy patch
 *  - Zygisk/Shamiko:maps 扫描
 *
 * 参考:2025-2026 最新检测技术
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <android/log.h>

#define TAG "DefenderRootCheck"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ============= inline syscall 封装 ============= */

#if defined(__aarch64__)
static int rc_openat(const char *path, int flags) {
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

static ssize_t rc_read(int fd, void *buf, size_t count) {
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

static int rc_close(int fd) {
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

static int rc_access(const char *path, int mode) {
    int ret;
    __asm__ volatile(
        "mov x8, #48\n"      /* __NR_faccessat */
        "mov x0, #-100\n"    /* AT_FDCWD */
        "mov x1, %1\n"
        "mov x2, %2\n"
        "svc #0\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(path), "r"(mode)
        : "x0", "x1", "x2", "x8", "memory"
    );
    return ret;
}

#elif defined(__arm__)
#include <sys/syscall.h>
static int rc_openat(const char *path, int flags) {
    return (int)syscall(__NR_openat, AT_FDCWD, path, flags, 0);
}
static ssize_t rc_read(int fd, void *buf, size_t count) {
    return syscall(__NR_read, fd, buf, count);
}
static int rc_close(int fd) {
    return (int)syscall(__NR_close, fd);
}
static int rc_access(const char *path, int mode) {
    return (int)syscall(__NR_faccessat, AT_FDCWD, path, mode, 0);
}

#else
static int rc_openat(const char *path, int flags) { return open(path, flags); }
static ssize_t rc_read(int fd, void *buf, size_t count) { return read(fd, buf, count); }
static int rc_close(int fd) { return close(fd); }
static int rc_access(const char *path, int mode) { return access(path, mode); }
#endif

/* ============= 辅助:读文件内容 ============= */

static int read_file(const char *path, char *buf, size_t bufsize) {
    int fd = rc_openat(path, 0);
    if (fd < 0) return -1;
    ssize_t n = rc_read(fd, buf, bufsize - 1);
    rc_close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    return 0;
}

/* ============= 用户态 Root 检测 ============= */

/**
 * 检查 su 二进制(8 个常见路径)
 */
static int check_su_paths(void) {
    const char *paths[] = {
        "/system/xbin/su", "/system/bin/su", "/sbin/su",
        "/data/local/xbin/su", "/data/local/bin/su",
        "/system/sd/xbin/su", "/system/bin/failsafe/su",
        "/data/adb/magisk/su",
    };
    for (int i = 0; i < 8; i++) {
        if (rc_access(paths[i], 0) == 0) {  /* F_OK=0 */
            LOGE("检测到 su: %s", paths[i]);
            return 1;
        }
    }
    return 0;
}

/**
 * 检查 Magisk 目录
 */
static int check_magisk_paths(void) {
    const char *paths[] = {
        "/sbin/.magisk", "/data/adb/magisk",
        "/data/adb/modules", "/cache/.disable_magisk",
    };
    for (int i = 0; i < 4; i++) {
        if (rc_access(paths[i], 0) == 0) {
            LOGE("检测到 Magisk: %s", paths[i]);
            return 1;
        }
    }
    return 0;
}

/**
 * 检查 ro.secure 属性
 */
static int check_ro_secure(void) {
    char value[32] = {0};
    __system_property_get("ro.secure", value);
    if (strcmp(value, "0") == 0) {
        LOGE("ro.secure=0(不安全)");
        return 1;
    }
    return 0;
}

/**
 * 检查 SELinux 状态(Permissive = 可能 root)
 */
static int check_selinux(void) {
    char buf[8] = {0};
    if (read_file("/sys/fs/selinux/enforce", buf, sizeof(buf)) != 0) {
        return 0;  /* SELinux 不存在,不算 root */
    }
    if (buf[0] == '0') {
        LOGE("SELinux Permissive(可能 root)");
        return 1;
    }
    return 0;
}

/**
 * 检查系统分区是否可写(root 常 remount)
 */
static int check_mounts(void) {
    char buf[16384] = {0};
    if (read_file("/proc/self/mounts", buf, sizeof(buf)) != 0) {
        return 0;
    }
    /* 找 /system 或 /system_root 的 rw 挂载(正常应为 ro)
     * 部分设备 /system 是符号链接到 /system_root,两种都检测 */
    char *p = strstr(buf, " /system ");
    if (!p) p = strstr(buf, " /system_root ");
    if (p) {
        char *end = strchr(p, '\n');
        if (end) *end = '\0';
        if (strstr(p, " rw,") != NULL || strstr(p, " rw ") != NULL) {
            LOGE("/system 可写(root remount)");
            return 1;
        }
    }
    return 0;
}

/* ============= BL 锁检测 ============= */

/**
 * 检查 verifiedbootstate(green=锁定 / orange=解锁 / red=不可信)
 */
static int check_verified_boot(void) {
    char buf[32] = {0};
    __system_property_get("ro.boot.verifiedbootstate", buf);
    if (strcmp(buf, "orange") == 0 || strcmp(buf, "red") == 0) {
        LOGE("BL 解锁: verifiedbootstate=%s", buf);
        return 1;
    }
    return 0;
}

/**
 * 检查 flash.locked(1=锁定 / 0=解锁)
 */
static int check_flash_locked(void) {
    char buf[32] = {0};
    __system_property_get("ro.boot.flash.locked", buf);
    if (strcmp(buf, "0") == 0) {
        LOGE("BL 解锁: flash.locked=0");
        return 1;
    }
    return 0;
}

/**
 * 检查 veritymode(disabled = verity 关闭)
 */
static int check_verity(void) {
    char buf[32] = {0};
    __system_property_get("ro.boot.veritymode", buf);
    if (strcmp(buf, "disabled") == 0) {
        LOGE("BL 解锁: veritymode=disabled");
        return 1;
    }
    return 0;
}

/* ============= 内核级 Root 检测(KernelSU / APatch) ============= */

/**
 * 检查 KernelSU
 */
static int check_kernelsu(void) {
    /* KSU 的 /proc 接口 */
    if (rc_access("/proc/kernelsu", 0) == 0) {
        LOGE("检测到 KernelSU: /proc/kernelsu");
        return 1;
    }
    /* KSU 工作目录 */
    if (rc_access("/data/adb/ksu", 0) == 0) {
        LOGE("检测到 KernelSU: /data/adb/ksu");
        return 1;
    }
    /* KSU 设备节点 */
    if (rc_access("/dev/.ksu", 0) == 0) {
        LOGE("检测到 KernelSU: /dev/.ksu");
        return 1;
    }
    return 0;
}

/**
 * 检查 APatch
 */
static int check_apatch(void) {
    if (rc_access("/data/adb/ap", 0) == 0) {
        LOGE("检测到 APatch: /data/adb/ap");
        return 1;
    }
    if (rc_access("/data/adb/apd", 0) == 0) {
        LOGE("检测到 APatch: /data/adb/apd");
        return 1;
    }
    if (rc_access("/sys/module/apatch", 0) == 0) {
        LOGE("检测到 APatch: /sys/module/apatch");
        return 1;
    }
    return 0;
}

/**
 * 检查 /proc/version 里的内核 root 痕迹
 */
static int check_kernel_version(void) {
    char buf[512] = {0};
    if (read_file("/proc/version", buf, sizeof(buf)) != 0) {
        return 0;
    }
    if (strstr(buf, "KernelSU") || strstr(buf, "APatch") ||
        strstr(buf, "MAGIC") || strstr(buf, "kernelsu")) {
        LOGE("内核版本含 root 痕迹: %s", buf);
        return 1;
    }
    return 0;
}

/**
 * 扫 /sys/module/ 找异常内核模块
 */
static int check_kernel_modules(void) {
    DIR *d = opendir("/sys/module/");
    if (!d) return 0;

    const char *suspicious[] = {
        "kernelsu", "ksu", "apatch", "apd",
        "magisk", "supersu", "superuser",
    };
    int detected = 0;
    struct dirent *ent;

    while ((ent = readdir(d)) != NULL) {
        for (int i = 0; i < 7; i++) {
            if (strcmp(ent->d_name, suspicious[i]) == 0) {
                LOGE("检测到异常内核模块: %s", ent->d_name);
                detected = 1;
                break;
            }
        }
        if (detected) break;
    }

    closedir(d);
    return detected;
}

/* ============= Zygisk/Shamiko 检测 ============= */

/**
 * 扫 /proc/self/maps 找 zygisk/magisk/riru 特征
 */
static int check_zygisk_maps(void) {
    char buf[8192];
    int fd = rc_openat("/proc/self/maps", 0);
    if (fd < 0) return 0;

    const char *keywords[] = {
        "zygisk", "magisk", "riru",
        "zygisk_core", "zygisk_next",
    };
    int detected = 0;

    ssize_t n;
    while ((n = rc_read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        for (int i = 0; i < 5; i++) {
            if (strstr(buf, keywords[i]) != NULL) {
                LOGE("maps 检测到 Zygisk/Magisk: %s", keywords[i]);
                detected = 1;
                break;
            }
        }
        if (detected) break;
    }

    rc_close(fd);
    return detected;
}

/**
 * 检测 overlayfs 挂载(APatch/Shamiko 用 overlayfs 隐藏)
 */
static int check_overlayfs(void) {
    char buf[16384] = {0};
    if (read_file("/proc/self/mounts", buf, sizeof(buf)) != 0) {
        return 0;
    }
    /* Android 12+ 用 overlayfs 做灰度更新,直接匹配 "overlay" 会误报。
     * 只检测 /system 或 /vendor 的 overlay(正常灰度更新不涉及,
     * APatch/Shamiko 用 overlay 隐藏 /system 修改) */
    if (strstr(buf, "overlay") != NULL) {
        char *line = strtok(buf, "\n");
        while (line) {
            if (strstr(line, "overlay") != NULL &&
                (strstr(line, " /system ") != NULL || strstr(line, " /vendor ") != NULL)) {
                LOGE("检测到 /system 或 /vendor 的 overlayfs 挂载(可能 APatch/Shamiko)");
                return 1;
            }
            line = strtok(NULL, "\n");
        }
        LOGW("检测到非 /system overlay,忽略(可能 Android 12+ 灰度更新)");
    }
    return 0;
}

/* ============= 组合检测 ============= */

/**
 * Root 检测(全组合)
 *
 * @return 0=未检测到 root / 1=检测到 root
 */
int root_check(void) {
    LOGI("=== Root 检测 ===");

    /* 用户态 */
    if (check_su_paths()) return 1;
    if (check_magisk_paths()) return 1;
    if (check_ro_secure()) return 1;
    if (check_selinux()) return 1;
    if (check_mounts()) return 1;

    /* BL 锁 */
    if (check_verified_boot()) return 1;
    if (check_flash_locked()) return 1;
    if (check_verity()) return 1;

    /* 内核级 */
    if (check_kernelsu()) return 1;
    if (check_apatch()) return 1;
    if (check_kernel_version()) return 1;
    if (check_kernel_modules()) return 1;

    /* Zygisk/Shamiko */
    if (check_zygisk_maps()) return 1;
    if (check_overlayfs()) return 1;

    LOGI("Root 检测通过(未检测到 root)");
    return 0;
}
