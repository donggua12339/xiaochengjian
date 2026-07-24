/**
 * x4_anti_debug.c - X4-3 L2 反调试实现(ADR 0093)
 *
 * 全部用 svc 直读 /proc + 自实现字符串比较,关键词 OBF 运行时解密。
 */
#include "x4_anti_debug.h"
#include "x4_svc.h"
#include "x4_str.h"
#include "obfstr_poly.h"
#include <fcntl.h>
#include <stdint.h>
#include <time.h>

/* ============= 1. /proc/self/stat state 字段 ============= */

int x4_check_stat_state(void) {
    int fd = x4_svc_openat(AT_FDCWD, OBF("/proc/self/stat"), O_RDONLY, 0);
    if (fd < 0) return 0;
    char buf[512];
    ssize_t n = x4_svc_read(fd, buf, sizeof(buf) - 1);
    x4_svc_close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    /* comm 可能含空格和括号,从最后一个 ')' 后取 state */
    char *rp = buf;
    while (*rp && *rp != ')') rp++;
    if (!*rp) return 0;
    rp++; /* 跳过 ')' */
    while (*rp == ' ') rp++;
    char state = *rp;
    /* 'T' = traced/stopped, 't' = tracing stop */
    if (state == 'T' || state == 't') return 1;
    return 0;
}

/* ============= 2. 时间差检测 ============= */

/* 被测代码:简单循环(正常 <1ms,单步暂停 >>100ms) */
static volatile int g_sink = 0;
static void timed_work(void) {
    int s = 0;
    for (int i = 0; i < 1000; i++) s += i;
    g_sink = s;
}

int x4_check_time_delta(void) {
    int slow_count = 0;
    for (int trial = 0; trial < 3; trial++) {
        struct timespec t1, t2;
        x4_svc_clock_gettime(CLOCK_MONOTONIC, &t1);
        timed_work();
        x4_svc_clock_gettime(CLOCK_MONOTONIC, &t2);
        long delta_ms = (t2.tv_sec - t1.tv_sec) * 1000 +
                        (t2.tv_nsec - t1.tv_nsec) / 1000000;
        if (delta_ms > 200) slow_count++;  /* 正常设备 3 次不可能都超 200ms */
    }
    return (slow_count >= 2) ? 1 : 0;
}

/* ============= 3. 断点指令扫描(ARM64 BRK) ============= */

/* ARM64 BRK #imm16: insn = 0xD4200000 | (imm16 << 5)
 * 小端 byte[2]==0x20 && byte[3]==0xD4 且 4 字节对齐 → 唯一匹配 BRK */
static int scan_brk(const void *func, size_t bytes) {
    const uint8_t *p = (const uint8_t *)func;
    for (size_t i = 0; i + 3 < bytes; i += 4) {
        if (p[i + 2] == 0x20 && p[i + 3] == 0xD4) return 1;
    }
    return 0;
}

extern int x4_check_stat_state(void);
extern int x4_check_time_delta(void);

int x4_check_breakpoints(void) {
    int found = 0;
    void *targets[] = {
        (void *)x4_check_stat_state,
        (void *)x4_check_time_delta,
        (void *)x4_check_breakpoints,
    };
    int n = (int)(sizeof(targets) / sizeof(targets[0]));
    for (int i = 0; i < n; i++) {
        if (scan_brk(targets[i], 32)) found++;
    }
    return found;
}

/* ============= 4. Frida 端口检测 ============= */

int x4_check_frida_port(void) {
    int fd = x4_svc_openat(AT_FDCWD, OBF("/proc/net/tcp"), O_RDONLY, 0);
    if (fd < 0) return 0;
    char buf[8192];
    ssize_t n = x4_svc_read(fd, buf, sizeof(buf) - 1);
    x4_svc_close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    /* 27042 = 0x69A2; /proc/net/tcp 端口为大写 hex,部分内核小写 */
    if (x4_strstr(buf, OBF(":69A2")) || x4_strstr(buf, OBF(":69a2"))) return 1;
    /* 27043 = 0x69A3(frida 第二个端口) */
    if (x4_strstr(buf, OBF(":69A3")) || x4_strstr(buf, OBF(":69a3"))) return 1;
    return 0;
}

/* ============= L2 综合 ============= */

int x4_anti_debug_check(void) {
    int score = 0;
    if (x4_check_stat_state()) score++;
    if (x4_check_time_delta()) score++;
    int bp = x4_check_breakpoints();
    if (bp > 0) score += bp;
    if (x4_check_frida_port()) score++;
    return score;
}
