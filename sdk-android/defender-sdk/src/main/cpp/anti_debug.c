/**
 * anti_debug.c - 反调试检测(Native 层)
 *
 * 详见 ADR 0088 §AntiDebug
 *
 * 检测方式:
 *  - B:读 /proc/self/status 的 TracerPid(非 0 = 被调试)
 *  - C:读 /proc/self/wchan(含 "ptrace_stop" = 被调试)
 *  - F:inline syscall(绕过 libc hook)
 *
 * 检测频率:启动时 1 次 + 关键节点(activate/validate 前)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>

#define TAG "DefenderAntiDebug"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ============= inline syscall 封装(复用 sig_verify.c 的逻辑) ============= */

#if defined(__aarch64__)
static int ad_openat(const char *path, int flags) {
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

static ssize_t ad_read(int fd, void *buf, size_t count) {
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

static int ad_close(int fd) {
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
/* M1 说明:armeabi-v7a 的 inline syscall 需要 R7 存 syscall 号,但 R7 被 ABI 保留为
 * 帧指针(frame pointer),直接用 inline asm 会破坏栈帧。此处用 libc syscall() 替代,
 * 代价是可被 libc hook 绕过。权衡:armeabi-v7a 设备占比已很低,且核心检测在 arm64-v8a
 * (inline asm 不可 hook),故 v7a 用 syscall() 是可接受的折中。 */
#include <sys/syscall.h>
static int ad_openat(const char *path, int flags) {
    return (int)syscall(__NR_openat, AT_FDCWD, path, flags, 0);
}
static ssize_t ad_read(int fd, void *buf, size_t count) {
    return syscall(__NR_read, fd, buf, count);
}
static int ad_close(int fd) {
    return (int)syscall(__NR_close, fd);
}

#else
static int ad_openat(const char *path, int flags) { return open(path, flags); }
static ssize_t ad_read(int fd, void *buf, size_t count) { return read(fd, buf, count); }
static int ad_close(int fd) { return close(fd); }
#endif

/* ============= B:TracerPid 检测 ============= */

/**
 * 读 /proc/self/status,解析 TracerPid
 *
 * TracerPid 非 0 = 被调试器附加(gdb/lldb/Frida attach)
 *
 * @return 0=未被调试 / 1=被调试 / -1=读取失败
 */
static int check_tracer_pid(void) {
    int fd = ad_openat("/proc/self/status", 0);  /* O_RDONLY */
    if (fd < 0) {
        LOGE("open /proc/self/status 失败");
        return -1;
    }

    char buf[4096];
    ssize_t n = ad_read(fd, buf, sizeof(buf) - 1);
    ad_close(fd);

    if (n <= 0) {
        LOGE("read /proc/self/status 失败");
        return -1;
    }
    buf[n] = '\0';

    /* 找 TracerPid 行 */
    const char *p = strstr(buf, "TracerPid:");
    if (!p) {
        LOGW("TracerPid 字段未找到");
        return -1;
    }

    /* 解析数字 */
    int tracer_pid = atoi(p + 10);  /* "TracerPid:" 后面是空格+数字 */
    LOGI("TracerPid: %d", tracer_pid);

    return tracer_pid != 0 ? 1 : 0;
}

/* ============= C:wchan 检测 ============= */

/**
 * 读 /proc/self/wchan,检查是否含 "ptrace_stop"
 *
 * 被调试时 wchan 含 "ptrace_stop"
 *
 * @return 0=未被调试 / 1=被调试 / -1=读取失败
 */
static int check_wchan(void) {
    int fd = ad_openat("/proc/self/wchan", 0);
    if (fd < 0) {
        /* wchan 在某些设备上不可读,不算被调试 */
        LOGW("open /proc/self/wchan 失败(非致命)");
        return 0;
    }

    char buf[256] = {0};
    ssize_t n = ad_read(fd, buf, sizeof(buf) - 1);
    ad_close(fd);

    if (n <= 0) {
        return 0;
    }
    buf[n] = '\0';

    LOGI("wchan: %s", buf);

    /* 检查是否含 ptrace_stop */
    if (strstr(buf, "ptrace_stop") != NULL) {
        return 1;
    }

    return 0;
}

/* ============= 组合检测 ============= */

/**
 * 反调试检测(B + C + F 组合)
 *
 * @return 0=未被调试 / 1=被调试
 */
int anti_debug_check(void) {
    LOGI("=== 反调试检测 ===");

    /* B:TracerPid */
    int b = check_tracer_pid();
    if (b == 1) {
        LOGE("检测到调试器(TracerPid 非 0)");
        return 1;
    }

    /* C:wchan */
    int c = check_wchan();
    if (c == 1) {
        LOGE("检测到调试器(wchan=ptrace_stop)");
        return 1;
    }

    LOGI("反调试检测通过(未被调试)");
    return 0;
}
