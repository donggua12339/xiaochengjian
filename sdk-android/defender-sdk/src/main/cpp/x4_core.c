/**
 * x4_core.c - X4 主入口:初始化 + 守护线程调度(ADR 0093)
 *
 * 初始化顺序(执行纪律 §4 第 2 条):
 *   1. load_config        (读 5 字段 config + strongEvidenceSwitches)
 *   2. dry_run_init       (四级优先级 + 决策链日志)
 *   3. detect_mdm         (自动探测,填充 softExempt 通道)
 *   4. weak_baseline_init (memfd / anon:dalvik 基线)
 *   5. daemon_start       (每 3-15s 随机间隔触发 x4_round_check)
 *
 * 每轮调度:
 *   check_auto_rollback → exempt 检查 → score_engine_round
 *
 * 合规声明:
 *   所有检测作用于"我的 APP 进程自身",不读其他进程,符合 ADR 0077 守城边界。
 */
#include "config_loader.h"
#include "dry_run.h"
#include "score_engine.h"
#include "weak_detector.h"
#include "auto_rollback.h"
#include "x4_daemon.h"

#include <stdlib.h>
#include <string.h>
#include <android/log.h>

#define DEFENDER_TAG "X4-Core"
#include "defender_log.h"

/* === 全局:APK 路径 + 预期 hash(供 strong_evidence ① 用)==
 * 由 Java 层 DefenderInitProvider 在 attachBaseContext 时通过 JNI 填充。
 */
char g_x4_apk_path[1024] = {0};
char g_x4_expected_hash[65] = {0};

/* === 本 APP 包名(供 exempt 检查) == */
static char g_self_pkg[256] = {0};

/* ===================================================================== */
/* 每轮 check 调度                                                        */
/* ===================================================================== */
static void x4_round_check(void) {
    /* 1. 自动回滚检查(Q5.5) */
    x4_auto_rollback_check();

    /* 2. exempt 检查 */
    if (x4_config_is_hard_exempt(g_self_pkg)) {
        return;  /* hardExempt 命中:全部旁路(含强证据) */
    }
    if (x4_config_is_soft_exempt(g_self_pkg)) {
        x4_engine_reset_soft();  /* softExempt 命中:清零弱通道,强证据仍 kill */
    }

    /* 3. 总开关 */
    if (!x4_config_is_enabled()) {
        return;
    }

    /* 4. 执行检测 + 响应(score_engine 内部调 response_chain) */
    x4_engine_round();

    /* 5. 把本轮快照通知 auto_rollback(供孤立强证据判定) */
    x4_auto_rollback_note_round(x4_engine_is_strong_hit_last_round(),
                                 x4_engine_get_score());
}

/* ===================================================================== */
/* 初始化                                                                  */
/* ===================================================================== */
void x4_init(const char *config_path, const char *self_pkg,
             const char *apk_path, const char *expected_hash) {
    LOGI("[X4] init start");

    /* 1. 加载 config */
    x4_config_load(config_path);

    /* 2. dry-run 初始化(打印决策链) */
    x4_dry_run_init();

    /* 3. 记 self_pkg + APK 路径 + 预期 hash */
    if (self_pkg) {
        strncpy(g_self_pkg, self_pkg, sizeof(g_self_pkg) - 1);
    }
    if (apk_path) {
        strncpy(g_x4_apk_path, apk_path, sizeof(g_x4_apk_path) - 1);
    }
    if (expected_hash) {
        strncpy(g_x4_expected_hash, expected_hash, sizeof(g_x4_expected_hash) - 1);
    }

    /* 4. 弱信号基线(memfd / anon:dalvik) */
    x4_weak_baseline_init();

    /* 5. 守护线程注册 + 启动 */
    x4_daemon_register((x4_check_fn)x4_round_check, NULL);
    x4_daemon_set_interval(3, 15);  /* 3-15s 随机间隔 */
    x4_daemon_start();

    LOGI("[X4] init done, daemon started");
}

/* ===================================================================== */
/* 紧急停止(供 auto_rollback emergency 调)                              */
/* ===================================================================== */
void x4_emergency_stop(void) {
    x4_auto_rollback_emergency();
}
