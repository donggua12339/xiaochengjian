/**
 * x4_anti_inject.c - X4-1 L1 反注入实现(ADR 0093)
 *
 * 三类检测,均下沉到 svc + 自实现字符串 + OBF 关键词:
 *  1. dl_iterate_phdr 枚举 SO(底层,抗 maps 重命名)匹配注入框架特征;
 *  2. /proc/self/maps 可执行段路径关键词扫描;
 *  3. ptrace(TracerPid + wchan=ptrace_stop)。
 *
 * 关键词用 OBF()(构建期 obfstr_poly.py 加密),静态不可见。
 * 检测保守,干净设备应全 0(避免误报);CREATOR/mPM/Application 检测在 Java 侧
 * (X4InjectionDetector.kt),native 与 Java 结果交叉绑定(后续接入)。
 */
#include "x4_anti_inject.h"
#include "x4_svc.h"
#include "x4_str.h"
#include "obfstr_poly.h"
#include <link.h>
#include <fcntl.h>
#include <stdint.h>

/* ============= 1. dl_iterate_phdr 枚举注入 SO ============= */

struct so_ctx { int suspicious; };

static int phdr_cb(struct dl_phdr_info *info, size_t sz, void *data) {
    (void)sz;
    struct so_ctx *ctx = (struct so_ctx *)data;
    const char *name = info->dlpi_name;
    if (!name || !*name) return 0;   /* 主程序无 dlpi_name */
    if (x4_strstr(name, OBF("frida"))    || x4_strstr(name, OBF("gadget"))    ||
        x4_strstr(name, OBF("gum-js"))   || x4_strstr(name, OBF("zygisk"))    ||
        x4_strstr(name, OBF("riru"))     || x4_strstr(name, OBF("linjector")) ||
        x4_strstr(name, OBF("substrate"))|| x4_strstr(name, OBF("xposed"))    ||
        x4_strstr(name, OBF("sandhook"))) {
        ctx->suspicious++;
    }
    return 0;
}

int x4_detect_injected_so(void) {
    struct so_ctx ctx;
    ctx.suspicious = 0;
    dl_iterate_phdr(phdr_cb, &ctx);
    return ctx.suspicious;
}

/* ============= 2. /proc/self/maps 可执行段关键词扫描 ============= */

/* 判断一行 maps 是否为"路径含注入特征的可执行段" */
static int exec_line_suspicious(const char *line) {
    const char *p = line;
    while (*p && *p != ' ') p++;        /* 跳过地址范围 */
    while (*p == ' ') p++;
    if (p[0] == 0 || p[1] == 0 || p[2] == 0) return 0;
    if (p[2] != 'x') return 0;          /* 仅看可执行段(r-xp/rwxp) */
    /* 定位 pathname:跳过 perms 后的 offset/dev/inode 三个字段 */
    const char *path = p + 4;
    for (int f = 0; f < 3 && *path; f++) {
        while (*path == ' ') path++;
        while (*path && *path != ' ') path++;
    }
    while (*path == ' ') path++;
    if (!*path) return 0;               /* 匿名段不在此处判定(交由 L3 白名单) */
    if (x4_strstr(path, OBF("frida"))    || x4_strstr(path, OBF("gadget"))   ||
        x4_strstr(path, OBF("linjector"))|| x4_strstr(path, OBF("zygisk"))  ||
        x4_strstr(path, OBF("riru"))     || x4_strstr(path, OBF("substrate"))||
        x4_strstr(path, OBF("xposed"))   || x4_strstr(path, OBF("sandhook"))) {
        return 1;
    }
    return 0;
}

int x4_detect_exec_segments(void) {
    int fd = x4_svc_openat(AT_FDCWD, OBF("/proc/self/maps"), O_RDONLY, 0);
    if (fd < 0) return -1;
    static char buf[65536];
    ssize_t n = x4_svc_read(fd, buf, sizeof(buf) - 1);
    x4_svc_close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;

    int suspicious = 0;
    char *line = buf;
    while (line && *line) {
        char *nl = line;
        while (*nl && *nl != '\n') nl++;
        if (*nl == '\n') { *nl = 0; nl++; }
        if (exec_line_suspicious(line)) suspicious++;
        line = (*nl) ? nl : 0;
    }
    return suspicious;
}

/* ============= 3. ptrace 检测(TracerPid + wchan) ============= */

int x4_detect_ptrace(void) {
    /* TracerPid */
    int fd = x4_svc_openat(AT_FDCWD, OBF("/proc/self/status"), O_RDONLY, 0);
    if (fd >= 0) {
        static char sbuf[4096];
        ssize_t n = x4_svc_read(fd, sbuf, sizeof(sbuf) - 1);
        x4_svc_close(fd);
        if (n > 0) {
            sbuf[n] = 0;
            char *tp = x4_strstr(sbuf, OBF("TracerPid:"));
            if (tp) {
                tp += 10;   /* strlen("TracerPid:") */
                while (*tp == ' ' || *tp == '\t') tp++;
                int pid = 0;
                while (*tp >= '0' && *tp <= '9') { pid = pid * 10 + (*tp - '0'); tp++; }
                if (pid != 0) return 1;
            }
        }
    }
    /* wchan == ptrace_stop(比 TracerPid 更隐蔽的调试指纹) */
    fd = x4_svc_openat(AT_FDCWD, OBF("/proc/self/wchan"), O_RDONLY, 0);
    if (fd >= 0) {
        char w[64];
        ssize_t wn = x4_svc_read(fd, w, sizeof(w) - 1);
        x4_svc_close(fd);
        if (wn > 0) {
            w[wn] = 0;
            if (x4_strstr(w, OBF("ptrace_stop"))) return 1;
        }
    }
    return 0;
}

/* ============= L1 综合 ============= */

int x4_anti_inject_check(void) {
    int score = 0;
    int so = x4_detect_injected_so();
    int exec = x4_detect_exec_segments();
    int ptr = x4_detect_ptrace();
    if (so > 0) score += so;
    if (exec > 0) score += exec;
    if (ptr > 0) score += ptr;
    return score;
}
