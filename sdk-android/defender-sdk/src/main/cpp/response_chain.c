/**
 * response_chain.c - X4 三通道响应链实现(ADR 0093)
 *
 * 优先级链(从高到低,Q4.2 锁定):
 *   dry-run=true             → 全部只 log [X4-DRY-RUN]
 *   dry-run=false + 强证据命中 → kill(无视 onViolation)
 *   dry-run=false + 无强证据 + 有效分≥kill → 按 onViolation 响应
 *   dry-run=false + 无强证据 + 有效分≥warn → warn
 *   dry-run=false + 存在感≥PRESENCE_ALERT → log+上报
 *
 * 关键不变量(Q4.2 锁定):
 *   - onViolation 仅控制"有效分通道",不影响"强证据通道"
 *   - 即使 onViolation=none,强证据仍然 kill
 *   - 唯一能旁路强证据的开关是 dry-run=true
 *
 * trigger_kill(Q1 锁定):
 *   - 随机延迟 3-15s(防当触发点定位)
 *   - 上报 telemetry
 *   - SIGABRT 自毁
 */
#include "response_chain.h"
#include "score_weights.h"
#include "weak_signals.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <android/log.h>

#define DEFENDER_TAG "X4-Response"
#include "defender_log.h"

/* === 外部依赖 == */
extern bool x4_dry_run_is_enabled(void);              /* dry_run.c */
extern x4_on_violation_t x4_config_get_on_violation(void); /* config_loader.c */

/* === telemetry 上报接口(供本模块调用)== */
extern void x4_telemetry_log_round(bool strong_hit, int round_score,
                                   int total_score, int presence, int last_max);
extern void x4_telemetry_report_kill(const char *reason);
extern void x4_telemetry_report_warn(const char *reason);
extern void x4_telemetry_report_presence(int presence);

/* === toast 接口(走 JNI 调 Java,占位) == */
extern void x4_ui_show_toast(const char *msg);

/* ===================================================================== */
/* 响应链评估入口                                                          */
/* ===================================================================== */
void x4_response_evaluate(bool strong_hit, int score, int presence) {
    /**
     * X4 响应优先级链(从高到低):
     *
     * 1. dry-run=true(任意来源)→ 全部只 log [X4-DRY-RUN]
     * 2. 强证据命中 → kill(无视 onViolation)
     * 3. 有效分 ≥ killThreshold → 按 onViolation 响应
     * 4. 有效分 ≥ warnThreshold → warn
     * 5. 存在感 ≥ PRESENCE_ALERT → log + 上报
     * 6. 以上都不命中 → 只 log 原始数据
     *
     * dry-run 优先级 > onViolation 优先级 > 强证据
     * onViolation 仅控制有效分通道,不影响强证据通道
     * 即使 onViolation=none,强证据仍然 kill
     * 唯一能旁路强证据的是 dry-run=true
     */

    /* === 第一优先级:dry-run 总闸 === */
    if (x4_dry_run_is_enabled()) {
        LOGI("[X4-DRY-RUN] strong=%d score=%d presence=%d", strong_hit, score, presence);
        /* dry-run 期全量上报(Q5.4) */
        x4_telemetry_log_round(strong_hit, 0, score, presence, 0);
        return;  /* 全部短路 */
    }

    /* === 第二优先级:强证据(无视 onViolation)== */
    if (strong_hit) {
        x4_trigger_kill("strong_evidence");
        return;
    }

    /* === 第三优先级:有效分超 kill === */
    if (score >= X4_KILL_THRESHOLD_FINAL) {
        x4_on_violation_t v = x4_config_get_on_violation();
        if (v == X4_ON_VIOLATION_KILL) {
            x4_trigger_kill("score_overflow_kill");
        } else if (v == X4_ON_VIOLATION_WARN) {
            x4_trigger_warn("score_overflow_warn");
        }
        /* ON_VIOLATION_NONE → 只 log */
        LOGW("[X4] score=%d ≥ kill=%d but onViolation=none", score, X4_KILL_THRESHOLD_FINAL);
        return;
    }

    /* === 第四优先级:有效分超 warn === */
    if (score >= X4_WARN_THRESHOLD_FINAL) {
        x4_on_violation_t v = x4_config_get_on_violation();
        if (v != X4_ON_VIOLATION_NONE) {
            x4_trigger_warn("score_threshold_warn");
        } else {
            LOGW("[X4] score=%d ≥ warn=%d but onViolation=none", score, X4_WARN_THRESHOLD_FINAL);
        }
        return;
    }

    /* === 第五优先级:存在感 === */
    if (presence >= PRESENCE_ALERT) {
        LOGW("[X4] sustained probing: presence=%d ≥ %d", presence, PRESENCE_ALERT);
        x4_telemetry_report_presence(presence);
        return;
    }

    /* === 第六优先级:无任何触发,只 log === */
    LOGI("[X4] round clean: score=%d presence=%d", score, presence);
}

/* ===================================================================== */
/* trigger_kill:随机延迟 + 上报 + SIGABRT(Q1 锁定)                       */
/* ===================================================================== */
void x4_trigger_kill(const char *reason) {
    LOGE("[X4] KILL triggered: %s", reason);

    /* 上报(在自毁前发) */
    x4_telemetry_report_kill(reason);

    /* 随机延迟 3-15s(防当触发点定位,调研 看雪1 结论) */
    static int seeded = 0;
    if (!seeded) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        srand((unsigned int)(ts.tv_nsec ^ ts.tv_sec));
        seeded = 1;
    }
    int delay = 3 + (rand() % 13);  /* 3..15 */
    LOGI("[X4] kill delay=%ds", delay);
    sleep(delay);

    /* 自毁 */
    raise(SIGABRT);

    /* 兜底:SIGABRT 被 catch 时直接 _exit */
    _exit(137);
}

/* ===================================================================== */
/* trigger_warn:toast + 上报                                              */
/* ===================================================================== */
void x4_trigger_warn(const char *reason) {
    LOGW("[X4] WARN triggered: %s", reason);
    x4_ui_show_toast("检测到安全风险");
    x4_telemetry_report_warn(reason);
}
