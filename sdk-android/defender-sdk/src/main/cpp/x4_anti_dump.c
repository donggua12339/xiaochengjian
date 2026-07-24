/**
 * x4_anti_dump.c - X4-4 L3 反内存 Dump 实现(ADR 0093)
 *
 * 全部用 svc 直读 /proc + 自实现字符串 + OBF 关键词。
 * inotify 对 procfs 部分内核不可靠(调研标注),作预警层:失败静默,成功则
 * 设 flag;check 时读 flag 作为附加信号,不单独判定。
 */
#include "x4_anti_dump.h"
#include "x4_svc.h"
#include "x4_str.h"
#include "obfstr_poly.h"
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/inotify.h>
#include <poll.h>

/* ============= 基线(init 时记录) ============= */

static int g_memfd_baseline = -1;       /* init 时 memfd 数 */
static int g_anon_dalvik_baseline = -1; /* init 时 anon:dalvik 段数 */
static volatile int g_inotify_triggered = 0;
static int g_inotify_ok = 0;

/* ============= 辅助:扫 maps ============= */

/* 读 /proc/self/maps 到 buf,返回读取字节数。buf 须 caller 提供(>=128KB)。 */
static ssize_t read_maps(char *buf, size_t bufsz) {
    int fd = x4_svc_openat(AT_FDCWD, OBF("/proc/self/maps"), O_RDONLY, 0);
    if (fd < 0) return -1;
    ssize_t n = x4_svc_read(fd, buf, bufsz - 1);
    x4_svc_close(fd);
    if (n > 0) buf[n] = 0;
    return n;
}

/* ============= 1. rwx 段 ============= */

int x4_check_rwx_segments(void) {
    static char buf[131072];
    ssize_t n = read_maps(buf, sizeof(buf));
    if (n <= 0) return 0;
    int count = 0;
    char *line = buf;
    while (line && *line) {
        char *nl = line;
        while (*nl && *nl != '\n') nl++;
        if (*nl) { *nl = 0; nl++; } else { nl = 0; }
        /* 解析 perms:line 中第二个字段(start-end perms ...) */
        char *p = line;
        while (*p && *p != ' ') p++;   /* 跳过 addr range */
        while (*p == ' ') p++;
        if (p[0] == 'r' && p[1] == 'w' && p[2] == 'x') count++;
        line = nl;
    }
    return count;
}

/* ============= 2. anon:dalvik 段 ============= */

static int count_anon_dalvik(void) {
    static char buf[131072];
    ssize_t n = read_maps(buf, sizeof(buf));
    if (n <= 0) return 0;
    int count = 0;
    char *line = buf;
    while (line && *line) {
        char *nl = x4_strstr(line, "\n");
        if (nl) { *nl = 0; nl++; } else { nl = 0; }
        if (x4_strstr(line, OBF("anon:dalvik-"))) count++;
        line = nl;
    }
    return count;
}

int x4_check_anon_dalvik(void) {
    if (g_anon_dalvik_baseline < 0) return 0;
    int cur = count_anon_dalvik();
    int diff = cur - g_anon_dalvik_baseline;
    return (diff > 0) ? diff : 0;
}

/* ============= 3. memfd 数量 ============= */

static int count_memfd(void) {
    /* 遍历 /proc/self/fd/,readlink 找 "memfd:" */
    int dfd = x4_svc_openat(AT_FDCWD, OBF("/proc/self/fd"), O_RDONLY | O_DIRECTORY, 0);
    if (dfd < 0) return -1;
    /* 用 getdents64 遍历 */
    char dbuf[4096];
    int count = 0;
    ssize_t nr;
    while ((nr = x4_svc_getdents64(dfd, dbuf, sizeof(dbuf))) > 0) {
        int pos = 0;
        while (pos < nr) {
            /* linux_dirent64: d_ino(8) + d_off(8) + d_reclen(2) + d_type(1) + d_name(...) */
            unsigned short reclen;
            __builtin_memcpy(&reclen, dbuf + pos + 16, 2);
            char *name = dbuf + pos + 19;
            if (name[0] != '.' || name[1]) {  /* 跳过 . 和 .. */
                /* readlink /proc/self/fd/<name> */
                char linkpath[64];
                int lp = 0;
                const char *prefix = "/proc/self/fd/";
                while (*prefix) linkpath[lp++] = *prefix++;
                const char *nm = name;
                while (*nm) linkpath[lp++] = *nm++;
                linkpath[lp] = 0;
                char target[128];
                ssize_t tl = x4_svc_readlinkat(AT_FDCWD, linkpath, target, sizeof(target) - 1);
                if (tl > 0) {
                    target[tl] = 0;
                    if (x4_strstr(target, OBF("memfd:"))) count++;
                }
            }
            pos += reclen;
        }
    }
    x4_svc_close(dfd);
    return count;
}

int x4_check_memfd_count(void) {
    if (g_memfd_baseline < 0) return 0;
    int cur = count_memfd();
    if (cur < 0) return 0;
    int diff = cur - g_memfd_baseline;
    return (diff > 0) ? diff : 0;
}

/* ============= 4. inotify 监控 /proc/self/mem(预警层) ============= */

static void *inotify_thread(void *arg) {
    (void)arg;
    int ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (ifd < 0) return 0;  /* 部分内核不支持,静默退出 */
    char path[64];
    /* 构建 /proc/self/mem */
    const char *p = OBF("/proc/self/mem");
    int i = 0;
    while (*p) path[i++] = *p++;
    path[i] = 0;
    int wd = inotify_add_watch(ifd, path, IN_OPEN | IN_ACCESS);
    if (wd < 0) {
        /* procfs inotify 不可靠,静默 */
        x4_svc_close(ifd);
        return 0;
    }
    g_inotify_ok = 1;
    /* 阻塞等事件(最多 30s 超时,循环检查 running flag) */
    struct pollfd pfd = { .fd = ifd, .events = POLLIN };
    while (1) {
        int ret = poll(&pfd, 1, 30000);
        if (ret > 0) {
            char evbuf[256];
            ssize_t en = read(ifd, evbuf, sizeof(evbuf));
            if (en > 0) {
                g_inotify_triggered = 1;
                break;  /* 触发一次即够,不循环(防自身 svc read maps 误触发) */
            }
        }
        if (ret == 0) break;  /* 30s 超时退出(inotify 仅预警,不常驻) */
    }
    x4_svc_close(ifd);
    return 0;
}

int x4_check_inotify_triggered(void) {
    return g_inotify_triggered;
}

/* ============= init ============= */

void x4_anti_dump_init(void) {
    g_anon_dalvik_baseline = count_anon_dalvik();
    g_memfd_baseline = count_memfd();
    if (g_memfd_baseline < 0) g_memfd_baseline = 0;
    /* 启动 inotify 监控线程(detach,不阻塞) */
    pthread_t t;
    if (pthread_create(&t, 0, inotify_thread, 0) == 0) {
        pthread_detach(t);
    }
}

/* ============= L3 综合 ============= */

int x4_anti_dump_check(void) {
    int score = 0;
    int rwx = x4_check_rwx_segments();
    if (rwx > 0) score += rwx;
    int dalvik = x4_check_anon_dalvik();
    if (dalvik > 0) score += dalvik;
    int memfd = x4_check_memfd_count();
    if (memfd > 0) score += memfd;
    if (g_inotify_triggered) score++;
    return score;
}
