/**
 * strong_evidence.c - X4 强证据 5 条检测实现(ADR 0093)
 *
 * 设计哲学(Q2 锁定):
 *   强证据 = 不可抵赖的物理事实,无视阈值,即时 kill(dry-run 除外)。
 *   所有检测用 svc 直读 /proc(绕过 libc hook),字符串用 x4_strstr(自实现)。
 *
 * 5 条强证据逐条说明:
 *   ① 签名 hash:复用 sig_verify_check_b(),APK 内容 hash 比对白名单
 *   ② CREATOR ClassLoader:JNI 获取 CREATOR.getClass().getClassLoader(),
 *      若 == app PathClassLoader → 命中(注入物必然在 app CL)
 *   ③ 23946 LISTEN:/proc/net/tcp + tcp6 搜 5D8A + 状态 0A
 *   ④ frida-agent maps:/proc/self/maps 精确匹配 frida-agent.so/gadget/linjector
 *   ⑤ state=T ∧ TracerPid≠0:双条件同时满足(防系统瞬态误报)
 *
 * 开关机制(Q5.6):
 *   strong_enabled[5] 默认全 true,远程 config 只能关不能开。
 *   检查时先看开关,关闭的条目跳过(既不进强通道也不进弱通道)。
 *
 * 合规声明:
 *   所有检测作用于"我的 APP 进程自身",不读其他进程数据,符合 ADR 0077 守城边界。
 */

#include "strong_evidence.h"
#include "weak_detector.h"  /* x4_search_maps() */
#include "x4_svc.h"
#include "x4_str.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>
#include <jni.h>

#define DEFENDER_TAG "X4-Strong"
#include "defender_log.h"

/* === 强证据开关(默认全 true,config_loader 可远程关单条)== */
bool strong_enabled[STRONG_EVIDENCE_COUNT] = {
    true, true, true, true, true
};

/* === 复用现有 sig_verify.c 的 B 层校验(内容 hash)==
 * extern 声明,避免循环 include;sig_verify.c 已用 svc 直读 APK,满足抗 hook 要求。
 * 返回 0 = 校验通过(无篡改),非 0 = 失败(篡改/异常)。
 * check_signature_hash 返回 true 表示"命中强证据"(即 hash 不匹配)。
 */
extern int sig_verify_check_b(const char *apk_path, const char *expected_hash);

/* === 全局 APK 路径和预期 hash,由 x4_core 初始化 == */
extern char g_x4_apk_path[1024];
extern char g_x4_expected_hash[65];

/* ===================================================================== */
/* ① 签名 hash 不匹配                                                     */
/* ===================================================================== */
bool check_signature_hash(void) {
    if (g_x4_apk_path[0] == '\0' || g_x4_expected_hash[0] == '\0') {
        /* 未初始化,无法校验,不命中(避免误杀) */
        return false;
    }
    int ret = sig_verify_check_b(g_x4_apk_path, g_x4_expected_hash);
    /* sig_verify_check_b 返回 0 = 通过;非 0 = 篡改 → 命中强证据 */
    if (ret != 0) {
        LOGW("[X4] strong① signature hash mismatch (ret=%d)", ret);
        return true;
    }
    return false;
}

/* ===================================================================== */
/* ② CREATOR/mPM 被应用 PathClassLoader 代理                              */
/* =====================================================================
 * 通过 JNI 获取 PackageInfo.CREATOR 静态字段,检查其 Class.getClassLoader():
 *   - app PathClassLoader 加载 → 命中(注入物必然在 app CL)
 *   - BootClassLoader / 系统 CL 加载 → 不命中(走弱信号 CREATOR-sysCL)
 *
 * 此处仅声明,实际实现见 strong_evidence_classloader.c(需要 JNIEnv*,
 * 单独文件以便 x4_core 选择性调用)。
 */
bool check_creator_classloader(void) {
    /* 委托给 X4InjectionDetector.kt 的 Java 层检测,Native 仅作信号汇总。
     * 原因:Java 层已实现完整双检测(CREATOR ClassLoader + 类名),见 ADR 0093 §3.4。
     * X4-1 真机验证 score=0,故此处通过 JNI 调用 Java 静态方法。
     * 具体实现见 strong_evidence_classloader.c。 */
    extern bool x4_check_creator_classloader_jni(void);
    return x4_check_creator_classloader_jni();
}

/* ===================================================================== */
/* ③ 调试端口 23946 LISTEN                                                 */
/* =====================================================================
 * 23946 = 0x5D8A(读 /proc/net/tcp 时端口字段为 4 位 hex)。
 * LISTEN 状态 = 0A( tenth field,TCP状态枚举)。
 */
bool check_port_23946(void) {
    static const char *paths[] = { "/proc/net/tcp", "/proc/net/tcp6" };
    char buf[8192];
    int hit = 0;

    for (int i = 0; i < 2; i++) {
        int fd = x4_svc_openat(-100 /* AT_FDCWD */, paths[i], 0 /* O_RDONLY */, 0);
        if (fd < 0) continue;
        ssize_t n = x4_svc_read(fd, buf, sizeof(buf) - 1);
        x4_svc_close(fd);
        if (n <= 0) continue;
        buf[n] = '\0';

        /* /proc/net/tcp 格式:每行
         *   sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmtm uid timeout inode
         * local_address: 0100007F:5D8A  (IP:PORT_hex)
         * 我们要找 ":5D8A" + 状态 "0A" */
        char *p = buf;
        /* 跳过第一行表头 */
        char *nl = x4_strstr(p, "\n");
        if (nl) p = nl + 1;

        while (p && *p) {
            /* 找 :5D8A */
            char *port = x4_strstr(p, ":5D8A");
            if (!port) {
                /* 也试小写 */
                port = x4_strstr(p, ":5d8a");
            }
            if (port && port - p < 100) {
                /* 在同一行找状态字段 0A(LISTEN)
                 * 格式:... :5D8A 01 02 03 04 05 06 07 0A ...
                 * 简化:从 port 往后找 " 0A " 或行尾 " 0A\n" */
                char *line_end = x4_strstr(port, "\n");
                if (!line_end) line_end = p + x4_strlen(p);
                /* 在 port 到 line_end 之间找状态 0A */
                char *q = port;
                while (q < line_end - 3) {
                    if (q[0] == ' ' && q[1] == '0' && q[2] == 'A' && (q[3] == ' ' || q[3] == '\n')) {
                        LOGW("[X4] strong③ port 23946 LISTEN in %s", paths[i]);
                        hit = 1;
                        break;
                    }
                    q++;
                }
                if (hit) break;
            }
            p = x4_strstr(p, "\n");
            if (p) p++;
            else break;
        }
        if (hit) break;
    }
    return hit ? true : false;
}

/* ===================================================================== */
/* ④ maps 含 frida-agent / frida-gadget / linjector                       */
/* =====================================================================
 * 修复(2026-07-25 Tier1 对抗测试发现):
 *   原模式 "frida-agent.so" 不匹配 "frida-agent-64.so"(中间有 -64),
 *   导致 Frida 注入后强证据④ 漏报。改为 "frida-agent" 覆盖所有变体:
 *   frida-agent.so / frida-agent-64.so / frida-agent-32.so。
 *
 *   同时:原 64KB 栈 buf 在 maps > 64KB 时截断(实测注入后 268KB),
 *   改用 x4_search_maps() 分段读取,不受文件大小限制。
 */
bool check_frida_agent_maps(void) {
    static const char *patterns[] = {
        "frida-agent",     /* 匹配 frida-agent.so / frida-agent-64.so / frida-agent-32.so */
        "frida-gadget",    /* 匹配 frida-gadget.so / frida-gadget-64.so */
        "linjector",
    };
    if (x4_search_maps(patterns, 3)) {
        LOGW("[X4] strong④ frida/linjector in maps");
        return true;
    }
    return false;
}

/* ===================================================================== */
/* ⑤ state=T ∧ TracerPid≠0(双条件)                                       */
/* =====================================================================
 * 双条件(Q3.3.a 锁定):
 *   state == 'T'  AND  TracerPid != 0  → 命中强证据
 *   仅 state=T 但 TracerPid=0 → 不命中(可能是系统瞬态 stop,如 ANR/OOM)
 *   仅 TracerPid≠0 但 state≠T → 不命中(走弱信号路径)
 */
bool check_state_and_tracer(void) {
    char buf[1024];
    int  state_T = 0;
    int  tracer_pid = 0;

    /* 读 /proc/self/stat —— 第 3 字段是 state */
    int fd = x4_svc_openat(-100, "/proc/self/stat", 0, 0);
    if (fd >= 0) {
        ssize_t n = x4_svc_read(fd, buf, sizeof(buf) - 1);
        x4_svc_close(fd);
        if (n > 0) {
            buf[n] = '\0';
            /* stat 格式: pid (comm) state ...
             * comm 可能含空格但被括号包围,所以跳过第一个 "(...)" 后取下一字符 */
            char *lp = x4_strstr(buf, "(");
            char *rp = x4_strstr(buf, ")");
            if (lp && rp && rp > lp) {
                char state_ch = rp[1]; /* 紧跟 ')' 后的字符就是 state */
                if (state_ch == 'T' || state_ch == 't') {
                    state_T = 1;
                }
            }
        }
    }

    /* 读 /proc/self/status —— 找 TracerPid: */
    fd = x4_svc_openat(-100, "/proc/self/status", 0, 0);
    if (fd >= 0) {
        ssize_t n = x4_svc_read(fd, buf, sizeof(buf) - 1);
        x4_svc_close(fd);
        if (n > 0) {
            buf[n] = '\0';
            char *tp = x4_strstr(buf, "TracerPid:");
            if (tp) {
                /* 跳过 "TracerPid:" 和空白,取整数 */
                char *q = tp + 10; /* "TracerPid:" 长度 10 */
                while (*q == ' ' || *q == '\t') q++;
                while (*q >= '0' && *q <= '9') {
                    tracer_pid = tracer_pid * 10 + (*q - '0');
                    q++;
                }
            }
        }
    }

    if (state_T && tracer_pid != 0) {
        LOGW("[X4] strong⑤ state=T AND TracerPid=%d", tracer_pid);
        return true;
    }
    return false;
}

/* ===================================================================== */
/* 总入口:遍历 5 条强证据                                                */
/* ===================================================================== */
bool check_all_strong_evidence(void) {
    /* 开关机制(Q5.6):远程 config 只能关不能开 */
    if (strong_enabled[STRONG_SIG_HASH]            && check_signature_hash())        return true;
    if (strong_enabled[STRONG_CREATOR_CLASSLOADER] && check_creator_classloader())  return true;
    if (strong_enabled[STRONG_PORT_23946]          && check_port_23946())           return true;
    if (strong_enabled[STRONG_FRIDA_AGENT_MAPS]    && check_frida_agent_maps())     return true;
    if (strong_enabled[STRONG_STATE_TRACER]        && check_state_and_tracer())     return true;
    return false;
}
