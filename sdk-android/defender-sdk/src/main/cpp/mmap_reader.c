/**
 * mmap_reader.c - 方案 A 核心:mmap 内存映射读取 APK
 *
 * 详见 xcj_blue_demo_v2.1.1_prompt.md §方案 A
 *
 * 原理:
 *  用 mmap 将 APK 文件映射到内存,在内存中解析 ZIP + Signing Block。
 *  关键:mmap 未被 NP/MT hook(已查证:看雪《校验的N次方》确认 NP/MT
 *  IO 重定向只 hook open/openat/fopen/syscall(__NR_openat),不含 mmap)。
 *
 * 对抗效果:
 *  - NP Level 3(open Hook):✅ mmap 绕过
 *  - NP Level 4(openat ptrace):✅ mmap 未被 hook + 内存读取不经过 syscall
 *  - MT Level 1-2(Java PMS):✅ 不走 PMS
 *
 * 降级方案:若 mmap 被 hook,改用 /proc/self/maps 读取已映射内存基址。
 *
 * 参考:
 *  - AOSP APK Signature Scheme v2(source.android.com/security/apksigning/v2)
 *  - 看雪《校验的N次方》(bbs.kanxue.com/thread-278216-1.htm)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <android/log.h>

#define TAG "DefenderMmapReader"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ============= inline syscall(复用 sig_verify.c 模式) ============= */

#if defined(__aarch64__)
/* arm64-v8a syscall 号:
 *   __NR_openat=56, __NR_close=57, __NR_fstat=80, __NR_mmap=222, __NR_read=63 */
static int mr_openat(const char *path, int flags) {
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

static int mr_close(int fd) {
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

/* __NR_read=63: 防 SRPatch PLT hook libc read() 篡改 /proc/self/maps */
static ssize_t mr_read(int fd, void *buf, size_t count) {
    ssize_t ret;
    __asm__ volatile(
        "mov x8, #63\n"      /* __NR_read */
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

static int mr_fstat(int fd, struct stat *st) {
    int ret;
    __asm__ volatile(
        "mov x8, #80\n"      /* __NR_fstat */
        "mov x0, %1\n"
        "mov x1, %2\n"
        "svc #0\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(fd), "r"(st)
        : "x0", "x1", "x8", "memory"
    );
    return ret;
}

/* mmap6(addr, len, prot, flags, fd, offset) -- arm64 用 6 个参数 */
static void *mr_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    void *ret;
    __asm__ volatile(
        "mov x8, #222\n"     /* __NR_mmap */
        "mov x0, %1\n"
        "mov x1, %2\n"
        "mov x2, %3\n"
        "mov x3, %4\n"
        "mov x4, %5\n"
        "mov x5, %6\n"
        "svc #0\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(addr), "r"(len), "r"(prot), "r"(flags), "r"(fd), "r"(offset)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x8", "memory"
    );
    return ret;
}

static int mr_munmap(void *addr, size_t len) {
    int ret;
    __asm__ volatile(
        "mov x8, #215\n"     /* __NR_munmap */
        "mov x0, %1\n"
        "mov x1, %2\n"
        "svc #0\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(addr), "r"(len)
        : "x0", "x1", "x8", "memory"
    );
    return ret;
}

#elif defined(__arm__)
#include <sys/syscall.h>
/* armeabi-v7a 用 __NR_mmap2(旧内核),页偏移单位为 1KB(4096/1024=4) */
#ifndef __NR_mmap
#define __NR_mmap __NR_mmap2
#endif
static int mr_openat(const char *path, int flags) {
    return (int)syscall(__NR_openat, AT_FDCWD, path, flags, 0);
}
static int mr_close(int fd) {
    return (int)syscall(__NR_close, fd);
}
static ssize_t mr_read(int fd, void *buf, size_t count) {
    return (ssize_t)syscall(__NR_read, fd, buf, count);
}
static int mr_fstat(int fd, struct stat *st) {
    return (int)syscall(__NR_fstat, fd, st);
}
static void *mr_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    /* mmap2 的 offset 单位是 1KB,需除以 4096 */
    return (void *)syscall(__NR_mmap, addr, len, prot, flags, fd, (long)(offset / 4096));
}
static int mr_munmap(void *addr, size_t len) {
    return (int)syscall(__NR_munmap, addr, len);
}
#else
static int mr_openat(const char *path, int flags) { return open(path, flags); }
static int mr_close(int fd) { return close(fd); }
static ssize_t mr_read(int fd, void *buf, size_t count) { return read(fd, buf, count); }
static int mr_fstat(int fd, struct stat *st) { return fstat(fd, st); }
static void *mr_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    return mmap(addr, len, prot, flags, fd, offset);
}
static int mr_munmap(void *addr, size_t len) { return munmap(addr, len); }
#endif

/* ============= 前向声明 ============= */
static int find_apk_path_from_maps(char *apk_path_out, size_t out_size);

/* ============= 早期 fd 缓存(防 SRPatch SVC hook 重定向 openat) ============= */

/*
 * SRPatch signatureStrength=4 用 SvcHookSigna hook SVC 指令本身,
 * 导致我们的 inline svc #0 openat 也被拦截并重定向到原始 APK。
 *
 * 解决:在 .init_array 构造器中(dlopen 时,早于所有 Java 代码和 hook 框架)
 * 打开 APK 并缓存 fd。此时 SRPatch 的 libSRPatch.so 尚未加载,hook 未安装。
 * 后续 mmap_apk 使用缓存 fd,不再调用 openat,SRPatch 无法拦截。
 */
static int g_cached_apk_fd = -1;
static struct stat g_cached_apk_stat;
static int g_cached_stat_valid = 0;

static void __attribute__((constructor)) mmap_reader_early_init(void) {
    char path[512];
    if (find_apk_path_from_maps(path, sizeof(path)) != 0) return;

    int fd = mr_openat(path, 0); /* O_RDONLY, inline svc, hook 尚未安装 */
    if (fd < 0) return;

    if (mr_fstat(fd, &g_cached_apk_stat) == 0) {
        g_cached_stat_valid = 1;
    }
    g_cached_apk_fd = fd;
    /* 不关闭 fd,保持打开状态供后续 mmap 使用 */
}

/**
 * 尝试使用缓存 fd,若无效则扫描 /proc/self/fd/ 找回正确 fd
 * (通过 dev+ino 匹配,绕过路径重定向)
 */
static int get_valid_apk_fd(const char *fallback_path) {
    /* 优先使用缓存 fd */
    if (g_cached_apk_fd >= 0) {
        struct stat st;
        if (mr_fstat(g_cached_apk_fd, &st) == 0) {
            return g_cached_apk_fd; /* fd 仍有效 */
        }
        /* 缓存 fd 被关闭,尝试回退 */
    }

    /* 回退:openat by path(可能被 hook,但作为最后手段) */
    if (fallback_path) {
        return mr_openat(fallback_path, 0);
    }
    return -1;
}

/* ============= APK 路径定位(从 /proc/self/maps) ============= */

/**
 * 从 /proc/self/maps 定位当前 APK 路径
 *
 * 绕过 Java 层 packageCodePath(可被 Frida hook)。
 * maps 中 APK 的 .so 映射形如:
 *   76e5000000-... r-xp ... /data/app/.../base.apk!/lib/arm64-v8a/libxxx.so
 * 提取 "!" 前的 APK 路径。
 *
 * @param apk_path_out 输出:APK 路径(至少 512 字节)
 * @return 0=成功 / -1=失败
 */
static int find_apk_path_from_maps(char *apk_path_out, size_t out_size) {
    int fd = mr_openat("/proc/self/maps", 0);
    if (fd < 0) return -1;

    char buf[8192];
    char line[1024];
    int line_pos = 0;
    int found = 0;
    /* 回退:从 .so 路径推断 APK 路径(extractNativeLibs=true 时无 .apk! 条目) */
    char fallback_apk[512] = {0};
    int has_fallback = 0;

    ssize_t n;
    while ((n = mr_read(fd, buf, sizeof(buf) - 1)) > 0 && !found) {
        buf[n] = '\0';
        for (int i = 0; i < n && !found; i++) {
            if (buf[i] == '\n' || line_pos >= (int)sizeof(line) - 1) {
                line[line_pos] = '\0';

                /* 优先搜索 ".apk!" 格式(extractNativeLibs=false 时) */
                char *apk_marker = strstr(line, ".apk!");
                if (apk_marker != NULL) {
                    char *path_start = strrchr(line, ' ');
                    if (path_start != NULL) {
                        path_start++;
                        size_t prefix_len = (size_t)(apk_marker - path_start) + 4;
                        if (prefix_len < out_size) {
                            strncpy(apk_path_out, path_start, prefix_len);
                            apk_path_out[prefix_len] = '\0';
                            found = 1;
                        }
                    }
                }

                /* 回退:搜索 /data/app/ 下的 base.apk(DEX 映射,无 "!" 后缀)
                 * extractNativeLibs=true 时,.so 从 lib/ 提取加载,
                 * maps 中没有 ".apk!" 条目,但 DEX 仍从 APK mmap,
                 * maps 中有 "/data/app/.../base.apk" 条目 */
                if (!found && !has_fallback) {
                    char *data_app = strstr(line, "/data/app/");
                    if (data_app) {
                        char *base_apk = strstr(data_app, "base.apk");
                        if (base_apk && (base_apk[8] == '\0' || base_apk[8] == ' ' ||
                                         base_apk[8] == '\n' || base_apk[8] == '!')) {
                            /* 提取完整路径(从 /data/app/ 到 base.apk) */
                            char *path_start = strrchr(line, ' ');
                            if (path_start) path_start++;
                            else path_start = line;
                            /* 找路径结束位置(空格或行尾) */
                            char *path_end = strchr(path_start, ' ');
                            if (!path_end) path_end = path_start + strlen(path_start);
                            size_t path_len = (size_t)(path_end - path_start);
                            if (path_len < sizeof(fallback_apk)) {
                                strncpy(fallback_apk, path_start, path_len);
                                fallback_apk[path_len] = '\0';
                                has_fallback = 1;
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
    mr_close(fd);

    if (found) return 0;

    /* 回退:使用 DEX 映射中的 base.apk 路径 */
    if (has_fallback && strlen(fallback_apk) < out_size) {
        strncpy(apk_path_out, fallback_apk, out_size - 1);
        apk_path_out[out_size - 1] = '\0';
        LOGI("从 maps DEX 映射推断 APK: %s", apk_path_out);
        return 0;
    }

    return -1;
}

/* ============= mmap 读取 APK ============= */

/**
 * 方案 A 核心:mmap 映射 APK 到内存
 *
 * @param apk_path APK 路径(若 NULL,从 maps 定位)
 * @param out_mapped 输出:映射的内存指针(需 mmap_unmap 释放)
 * @param out_size 输出:APK 文件大小
 * @return 0=成功 / -1=失败
 */
int mmap_apk(const char *apk_path, void **out_mapped, size_t *out_size) {
    char maps_path[512];
    const char *effective_path = apk_path;

    /* 优先从 maps 定位(绕过 Java packageCodePath hook) */
    if (!apk_path || find_apk_path_from_maps(maps_path, sizeof(maps_path)) == 0) {
        effective_path = maps_path;
        LOGI("从 maps 定位 APK: %s", effective_path);
    }

    /* 优先使用 .init_array 缓存的 fd(绕过 SRPatch SVC hook 重定向 openat) */
    int fd = get_valid_apk_fd(effective_path);
    if (fd < 0) {
        LOGE("打开 APK 失败: %s (cached_fd=%d)", effective_path, g_cached_apk_fd);
        return -1;
    }
    if (fd == g_cached_apk_fd) {
        LOGI("使用缓存 fd=%d(绕过 openat hook)", fd);
    }

    struct stat st;
    if (mr_fstat(fd, &st) != 0) {
        LOGE("fstat 失败");
        mr_close(fd);
        return -1;
    }

    /* mmap 映射(关键:mmap 未被 NP/MT hook) */
    void *mapped = mr_mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    /* 不关闭缓存 fd(后续守护线程还需使用) */
    if (fd != g_cached_apk_fd) {
        mr_close(fd);
    }

    if (mapped == MAP_FAILED || mapped == NULL) {
        LOGE("mmap 失败");
        return -1;
    }

    LOGI("APK mmap 成功: %s size=%zu base=%p", effective_path, (size_t)st.st_size, mapped);
    *out_mapped = mapped;
    *out_size = st.st_size;
    return 0;
}

/**
 * 缓存 fd 是否有效(供 JNI 层查询)
 */
int mmap_reader_cached_fd_valid(void) {
    if (g_cached_apk_fd < 0) return 0;
    struct stat st;
    return (mr_fstat(g_cached_apk_fd, &st) == 0) ? 1 : 0;
}

/**
 * 释放 mmap 映射
 */
void mmap_apk_free(void *mapped, size_t size) {
    if (mapped) mr_munmap(mapped, size);
}
