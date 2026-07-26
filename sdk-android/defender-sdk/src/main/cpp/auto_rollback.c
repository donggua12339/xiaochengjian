/**
 * auto_rollback.c - X4 客户端自动回滚实现(ADR 0093, Q5.5)
 *
 * 三个触发条件 + 紧急回滚:
 *   1. model_kill_count_5min > 50  → onViolation = warn
 *   2. strong_hit && score==0     → 本 session 降级 warn
 *   3. device_kill_count >= 3     → 降级 1 小时
 *   4. (紧急)                       → dry-run 强制 true(兜底)
 *
 * 回滚写入 config(is_mdm/strong_switches 不动,只动 on_violation/dry_run)
 */
#include "auto_rollback.h"
#include "config_loader.h"
#include "dry_run.h"
#include "score_engine.h"

#include <time.h>
#include <string.h>
#include <android/log.h>

#define DEFENDER_TAG "X4-Rollback"
#include "defender_log.h"

/* === 计数器(持久化由 Java 层 SharedPreferences 处理,Native 仅记内存)== */
static int   g_model_kill_count_5min = 0;
static long  g_model_kill_window_start = 0;  /* 5 分钟窗口起点 */
static int   g_device_kill_count = 0;
static long  g_device_kill_window_start = 0; /* 1 小时窗口起点 */
static bool  g_session_downgraded = false;   /* 本 session 已降级 */

/* ===================================================================== */
/* 条件1:同型号 5 分钟内 kill > 50                                        */
/* ===================================================================== */
static bool check_model_kill_spike(void) {
    long now = (long)time(NULL);
    if (g_model_kill_window_start == 0) {
        g_model_kill_window_start = now;
    }
    /* 5 分钟 = 300 秒窗口 */
    if (now - g_model_kill_window_start > 300) {
        g_model_kill_count_5min = 0;
        g_model_kill_window_start = now;
    }
    /* 调用方负责在 kill 时 +1 */
    return g_model_kill_count_5min > 50;
}

/* ===================================================================== */
/* 条件2:孤立强证据(强证据命中 + 有效分 == 0)                            */
/* ===================================================================== */
static bool check_lone_strong_evidence(bool strong_hit, int score) {
    /* 强证据命中但有效分为 0 → 可能是边界误报(如某 ROM CREATOR 合法替换) */
    return strong_hit && (score == 0);
}

/* ===================================================================== */
/* 条件3:同设备连续 3 次 kill 后仍重开                                    */
/* ===================================================================== */
static bool check_repeat_victim(void) {
    long now = (long)time(NULL);
    if (g_device_kill_window_start == 0) {
        g_device_kill_window_start = now;
    }
    /* 1 小时 = 3600 秒窗口 */
    if (now - g_device_kill_window_start > 3600) {
        g_device_kill_count = 0;
        g_device_kill_window_start = now;
    }
    return g_device_kill_count >= 3;
}

/* ===================================================================== */
/* 降级入口                                                                */
/* ===================================================================== */
static void downgrade_on_violation_to_warn(const char *reason) {
    if (g_x4_config.on_violation != X4_ON_VIOLATION_WARN) {
        g_x4_config.on_violation = X4_ON_VIOLATION_WARN;
        LOGW("[X4] AUTO DOWNGRADE: onViolation → warn (%s)", reason);
    }
}

static void downgrade_session_to_warn(const char *reason) {
    if (!g_session_downgraded) {
        g_session_downgraded = true;
        downgrade_on_violation_to_warn(reason);
    }
}

/* ===================================================================== */
/* 主入口:每轮调一次                                                      */
/* ===================================================================== */
void x4_auto_rollback_check(void) {
    /* 拉本轮快照 */
    bool strong_hit = x4_engine_is_strong_hit_last_round();
    int  score      = x4_engine_get_score();

    /* 条件1:型号 kill spike */
    if (check_model_kill_spike()) {
        downgrade_on_violation_to_warn("auto_rollback: model_kill_spike");
    }
    /* 条件2:孤立强证据 */
    if (check_lone_strong_evidence(strong_hit, score)) {
        downgrade_session_to_warn("auto_rollback: lone_strong_evidence");
    }
    /* 条件3:repeat victim */
    if (check_repeat_victim()) {
        downgrade_on_violation_to_warn("auto_rollback: repeat_victim");
    }
}

void x4_auto_rollback_note_round(bool strong_hit, int score) {
    /* 供 score_engine 每轮调,把快照传进来 */
    (void)strong_hit;
    (void)score;
    /* 实际逻辑在 x4_auto_rollback_check 里通过 x4_engine_get_* 拉取,
     * 这里保留接口供未来"主动通知"场景。 */
}

/* ===================================================================== */
/* 紧急回滚(兜底)== */
void x4_auto_rollback_emergency(void) {
    x4_dry_run_set_override(true);
    LOGW("[X4] AUTO ROLLBACK EMERGENCY: dry-run forced on");
}

/* ===================================================================== */
/* kill 计数(由 response_chain.trigger_kill 调)== */
extern void x4_rollback_note_kill(void);
void x4_rollback_note_kill(void) {
    g_model_kill_count_5min++;
    g_device_kill_count++;
}
