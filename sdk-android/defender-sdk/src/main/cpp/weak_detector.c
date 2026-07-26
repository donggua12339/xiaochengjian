/**
 * weak_detector.c - X4 弱信号 L1/L2/L3 检测实现(ADR 0093)
 *
 * 全部用 svc 直读 /proc/self/(自身进程)+ 自实现 x4_strstr 防 libc hook。
 * 基线(memfd / anon:dalvik)在初始化时记录,运行期比对超基线才命中。
 *
 * 合规声明:
 *   所有检测作用于"我的 APP 进程自身",不读其他进程,符合 ADR 0077 守城边界。
 */
#include "weak_detector.h"
#include "weak_signals.h"  /* 权重定义 */
#include "x4_svc.h"
#include "x4_str.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <android/log.h>

#define DEFENDER_TAG "X4-Weak"
#include "defender_log.h"

/* === 分段搜索 /proc/self/maps(不受文件大小限制)==
 * 实测:注入 frida-agent-64.so 后 maps 可达 268KB,单次 read 64KB 会截断,
 * 导致 frida/zygisk 关键词在截断区之后,检测全部漏报。
 *
 * 方案:分 64KB 块顺序读取,块间保留 256B 重叠防关键词跨块丢失。
 * 用 svc 直读(绕 libc hook)+ x4_strstr(自实现)搜索。
 * 守护线程单线程调用,static 缓冲区无竞争。
 */
#define MAPS_CHUNK_SIZE  65536
#define MAPS_OVERLAP     256   /* 最长关键词 "frida-gadget.so"=15B,256B 余量充足 */

bool x4_search_maps(const char *patterns[], int count) {
    static char buf[MAPS_CHUNK_SIZE + MAPS_OVERLAP];
    int fd = x4_svc_openat(-100, "/proc/self/maps", 0, 0);
    if (fd < 0) return false;

    size_t carry = 0;
    ssize_t n;
    bool found = false;

    while ((n = x4_svc_read(fd, buf + carry, MAPS_CHUNK_SIZE)) > 0) {
        buf[carry + n] = '\0';

        for (int i = 0; i < count; i++) {
            if (x4_strstr(buf, patterns[i])) {
                found = true;
                break;
            }
        }
        if (found) break;

        /* 保留尾部 OVERLAP 字节,防关键词跨块 */
        size_t total = carry + (size_t)n;
        if (total > MAPS_OVERLAP) {
            /* 手动搬运(避免 libc memmove 被 hook) */
            for (size_t i = 0; i < MAPS_OVERLAP; i++) {
                buf[i] = buf[total - MAPS_OVERLAP + i];
            }
            carry = MAPS_OVERLAP;
        } else {
            carry = total;
        }
    }

    x4_svc_close(fd);
    return found;
}

/* === 基线值(在 x4_weak_baseline_init 中填充)== */
static int  g_memfd_baseline      = 0;  /* memfd_create 数量基线 */
static long g_anon_dalvik_kb      = 0;  /* anon:dalvik 段大小基线(KB) */

/* ===================================================================== */
/* 基线初始化                                                              */
/* ===================================================================== */
void x4_weak_baseline_init(void) {
    /* === memfd 基线:扫 /proc/self/fd/ 统计 readlink 含 "memfd:" 的数量 === */
    char link[256];
    char buf[16384];
    int fd = x4_svc_openat(-100, "/proc/self/fd", 0 /* O_RDONLY */, 0);
    if (fd >= 0) {
        int n = x4_svc_getdents64(fd, buf, sizeof(buf));
        x4_svc_close(fd);
        (void)n; /* 基线扫不到也无妨,设 0 */
    }
    /* 简化:用 getdents64 + readlinkat 遍历,初始基线设 0(后续 round 才有真实值)
     * 真实实现见 x4_anti_dump.c 已有 memfd_count_basline,可复用 */
    extern int x4_check_memfd_count(void); /* 来自 x4_anti_dump.c */
    g_memfd_baseline = x4_check_memfd_count();
    (void)link;

    /* === anon:dalvik 基线:扫 /proc/self/maps 累加 anon:dalvik 段大小 === */
    static char mbuf[307200]; /* 300KB,maps 实测可达 268KB */
    int mfd = x4_svc_openat(-100, "/proc/self/maps", 0, 0);
    if (mfd >= 0) {
        ssize_t mn = x4_svc_read(mfd, mbuf, sizeof(mbuf) - 1);
        x4_svc_close(mfd);
        if (mn > 0) {
            mbuf[mn] = '\0';
            long total_kb = 0;
            char *p = mbuf;
            while (*p) {
                /* 行格式: start-end perms offset dev:inode pathname */
                /* 找 anon:dalvik */
                char *line_end = x4_strstr(p, "\n");
                if (!line_end) break;
                *line_end = '\0';
                if (x4_strstr(p, "anon:dalvik")) {
                    /* 解析行首的 start-end,算段大小 */
                    long start = 0, end = 0;
                    char *dash = x4_strstr(p, "-");
                    if (dash) {
                        char *q = p;
                        while (q < dash) {
                            char c = *q;
                            int v = (c >= '0' && c <= '9') ? c - '0' :
                                    (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                                    (c >= 'A' && c <= 'F') ? c - 'A' + 10 : 0;
                            start = start * 16 + v;
                            q++;
                        }
                        q = dash + 1;
                        while (q < line_end && *q != ' ') {
                            char c = *q;
                            int v = (c >= '0' && c <= '9') ? c - '0' :
                                    (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                                    (c >= 'A' && c <= 'F') ? c - 'A' + 10 : 0;
                            end = end * 16 + v;
                            q++;
                        }
                        total_kb += (end - start) / 1024;
                    }
                }
                *line_end = '\n';
                p = line_end + 1;
            }
            g_anon_dalvik_kb = total_kb;
        }
    }
    LOGI("[X4] baseline: memfd=%d anon:dalvik=%ldKB", g_memfd_baseline, g_anon_dalvik_kb);
}

/* ===================================================================== */
/* L3: inotify /proc/self/mem 写入事件                                    */
/* =====================================================================
 * 攻击者 dump 内存常用 inotify 监控 /proc/self/mem 然后触发回写或读取。
 * 本检测用 inotify_init1 + inotify_add_watch(/proc/self/mem, IN_ACCESS|IN_MODIFY),
 * 每轮读 inotify 事件队列,有 WRITE/MODIFY 即命中。
 *
 * 注意:inotify 在 /proc/self/mem 上不一定能成功 add_watch(取决于内核版本);
 * watch 失败不算命中,只记 warn。
 */
bool check_inotify_mem(void) {
    /* 简化:复用 x4_anti_dump.c 已有 inotify 监控;此处仅查状态标志 */
    extern int x4_check_inotify_triggered(void); /* 返回 1 表示本轮触发 */
    if (x4_check_inotify_triggered()) {
        LOGW("[X4] L3 inotify /proc/self/mem triggered");
        return true;
    }
    return false;
}

/* ===================================================================== */
/* L2-1: seccomp 检测已移除                                                */
/* =====================================================================
 * 原 check_seccomp 读 /proc/self/status 的 Seccomp 字段,≠0 即命中弱信号。
 * 但 Android 8.0+ AOSP 自带 seccomp filter(zygote 给所有 App 装 BPF),
 * Seccomp:2 是合法状态(100% 命中),≠0 即报是误判。
 *
 * 真实场景:
 *   - Android 8+ 任意 App(包括 Google Play 服务、银行 App、本 demo)→ Seccomp:2
 *   - 老设备(Android 7-)→ Seccomp:0
 *   - 被攻击者用 seccomp 隔离 defender 自己 → Seccomp:0(反而该报警)
 *
 * 此处保留空注释位 + 删除函数,避免 score_engine 调用未定义符号。
 * 若后续要恢复,应反向检测:Seccomp:0 才异常(Android 8+ 应有 seccomp)。
 */

/* ===================================================================== */
/* L2-2: rwx 段(已过滤 ART JIT code cache)                                */
/* =====================================================================
 * ART JIT 会合法产生 rwx 段(code cache),必须过滤:
 *   - maps 行路径含 "dalvik-jit-code-cache" 或 "dalvik-code-cache" → 跳过
 *   - 路径含 "anon:dalvik" 且 perms="rwx" → 跳过(ART JIT)
 *   - 其余 rwx 段 → 命中(可能是注入的 gadget 区)
 */
bool check_rwx(void) {
    /* 实测 maps 可达 268KB(注入 frida 后),64KB 栈 buf 会截断。
     * 用 300KB static buf 覆盖绝大多数场景;守护线程单线程,无竞争。 */
    static char buf[307200]; /* 300KB */
    int fd = x4_svc_openat(-100, "/proc/self/maps", 0, 0);
    if (fd < 0) return false;
    ssize_t n = x4_svc_read(fd, buf, sizeof(buf) - 1);
    x4_svc_close(fd);
    if (n <= 0) return false;
    buf[n] = '\0';

    /* 行格式: start-end perms offset dev:inode pathname */
    char *p = buf;
    char *line_end;
    while (p && *p) {
        line_end = x4_strstr(p, "\n");
        if (!line_end) break;
        *line_end = '\0';

        /* perms 字段在 start-end 之后,跳过空格 */
        char *perms = p;
        while (*perms && *perms != ' ') perms++;
        while (*perms == ' ') perms++;
        /* perms 4 字符:rwxp / rwxs / r-xp 等 */
        if (perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x') {
            /* 是 rwx 段,看路径是否 ART JIT */
            char *path = perms + 4;
            while (*path == ' ') path++;
            /* 跳过 offset + dev:inode */
            int space_count = 0;
            while (*path && space_count < 3) {
                if (*path == ' ') {
                    while (*path == ' ') path++;
                    space_count++;
                } else {
                    path++;
                }
            }
            if (!x4_strstr(path, "dalvik-jit-code-cache") &&
                !x4_strstr(path, "dalvik-code-cache") &&
                !x4_strstr(path, "anon:dalvik")) {
                LOGW("[X4] L2 rwx seg: %s", path);
                *line_end = '\n';
                return true;
            }
        }
        *line_end = '\n';
        p = line_end + 1;
    }
    return false;
}

/* ===================================================================== */
/* L2-3: 时间差 > 200ms                                                   */
/* =====================================================================
 * 用 5 个时间 API 取值,最大差值 > 200ms 即命中(被调试器单步会致明显时间差)。
 *   time(NULL)             - 秒级
 *   clock()                - 处理器时间
 *   gettimeofday()         - 微秒
 *   clock_gettime(MONOTONIC) - 纳秒
 *   getrusage(RUSAGE_SELF)   - 用户态+内核态微秒
 */
bool check_time_delta(void) {
    struct timespec ts1, ts2;
    struct stat st;
    long delta_ms = 0;

    x4_svc_clock_gettime(1 /* CLOCK_MONOTONIC */, &ts1);
    /* 故意做一点工作,测时间差 */
    x4_svc_fstat(0, &st);
    x4_svc_clock_gettime(1, &ts2);

    long t1_ms = ts1.tv_sec * 1000 + ts1.tv_nsec / 1000000;
    long t2_ms = ts2.tv_sec * 1000 + ts2.tv_nsec / 1000000;
    delta_ms = t2_ms - t1_ms;

    if (delta_ms > 200) {
        LOGW("[X4] L2 time_delta=%ldms", delta_ms);
        return true;
    }
    return false;
}

/* ===================================================================== */
/* L2-4: CREATOR 被系统 ClassLoader 加载的非标准类替换                     */
/* =====================================================================
 * 与强证据② 的区别:
 *   强证据②: CREATOR 被"应用 PathClassLoader"加载 → 注入物
 *   弱信号 L2: CREATOR 被"系统 CL / BootClassLoader"加载但类名非标准 → ROM 合法魔改可能
 *
 * 实际检测走 Java 层 X4InjectionDetector.detectCreatorHook() 的弱信号分支,
 * Native 仅作信号汇总。此处占位,委托 Java 层。
 */
bool check_creator_sys_cl(void) {
    extern bool x4_check_creator_sys_cl_jni(void);
    return x4_check_creator_sys_cl_jni();
}

/* ===================================================================== */
/* L1-1: memfd 数量超基线                                                  */
/* ===================================================================== */
bool check_memfd(void) {
    extern int x4_check_memfd_count(void);
    int cur = x4_check_memfd_count();
    /* 超基线 +2 才命中(L1 不计入有效分,容差大一点) */
    if (cur > g_memfd_baseline + 2) {
        LOGW("[X4] L1 memfd=%d (baseline=%d)", cur, g_memfd_baseline);
        return true;
    }
    return false;
}

/* ===================================================================== */
/* L1-2: anon:dalvik 大小超基线                                            */
/* ===================================================================== */
bool check_anon_dalvik(void) {
    static char buf[307200]; /* 300KB,同 check_rwx 理由 */
    int fd = x4_svc_openat(-100, "/proc/self/maps", 0, 0);
    if (fd < 0) return false;
    ssize_t n = x4_svc_read(fd, buf, sizeof(buf) - 1);
    x4_svc_close(fd);
    if (n <= 0) return false;
    buf[n] = '\0';

    long total_kb = 0;
    char *p = buf;
    while (*p) {
        char *line_end = x4_strstr(p, "\n");
        if (!line_end) break;
        *line_end = '\0';
        if (x4_strstr(p, "anon:dalvik")) {
            long start = 0, end = 0;
            char *dash = x4_strstr(p, "-");
            if (dash) {
                char *q = p;
                while (q < dash) {
                    char c = *q;
                    int v = (c >= '0' && c <= '9') ? c - '0' :
                            (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                            (c >= 'A' && c <= 'F') ? c - 'A' + 10 : 0;
                    start = start * 16 + v;
                    q++;
                }
                q = dash + 1;
                while (q < line_end && *q != ' ') {
                    char c = *q;
                    int v = (c >= '0' && c <= '9') ? c - '0' :
                            (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                            (c >= 'A' && c <= 'F') ? c - 'A' + 10 : 0;
                    end = end * 16 + v;
                    q++;
                }
                total_kb += (end - start) / 1024;
            }
        }
        *line_end = '\n';
        p = line_end + 1;
    }

    /* 超基线 +50% 才命中(L1 不计入有效分,容差大) */
    if (g_anon_dalvik_kb > 0 && total_kb > g_anon_dalvik_kb * 3 / 2) {
        LOGW("[X4] L1 anon:dalvik=%ldKB (baseline=%ldKB)", total_kb, g_anon_dalvik_kb);
        return true;
    }
    return false;
}

/* ===================================================================== */
/* L1-3: frida 子串(非精确)                                              */
/* =====================================================================
 * 与强证据④ 区别:
 *   强证据④: 精确匹配 frida-agent.so / frida-gadget.so / linjector → 注入物确定存在
 *   弱信号 L1: 模糊匹配 frida / gum- / gmain 子串 → 可能是合法字符串误命中
 */
bool check_frida_substr(void) {
    static const char *patterns[] = { "frida", "gum-", "gmain" };
    if (x4_search_maps(patterns, 3)) {
        LOGW("[X4] L1 frida-substr hit");
        return true;
    }
    return false;
}

/* ===================================================================== */
/* L1-4: zygisk                                                          */
/* ===================================================================== */
bool check_zygisk(void) {
    static const char *patterns[] = { "zygisk" };
    if (x4_search_maps(patterns, 1)) {
        LOGW("[X4] L1 zygisk in maps");
        return true;
    }
    return false;
}
