/**
 * telemetry.c - X4 安全状态快照上报实现(ADR 0093)
 *
 * 日志结构(仅设备安全状态,无用户/业务字段,Q5.4 锁定):
 *   - timestamp_ms         - 时间戳
 *   - device_model_hash    - 哈希后的设备型号(防指纹)
 *   - android_major_ver    - 仅大版本
 *   - is_mdm               - 是否 MDM 设备
 *   - strong_hits          - 5bit 位图(命中哪几条强证据)
 *   - weak_hits            - 9bit 位图(命中哪几条弱信号)
 *   - score                - 有效分累计
 *   - presence_count       - 存在感计数
 *   - dry_run_decision     - dry-run 决策(编码)
 *   - response_action      - 响应动作 kill/warn/log
 *
 * 上报策略:
 *   dry-run 期:全量上报(每轮一次,用于灰度 S1/S2 收集)
 *   enforce 后:仅 warn/kill 触发时上报
 */
#include "telemetry.h"
#include "score_weights.h"
#include "weak_signals.h"
#include "config_loader.h"
#include "dry_run.h"
#include "score_engine.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <android/log.h>

#define DEFENDER_TAG "X4-Telemetry"
#include "defender_log.h"

/* === 上报通道(走 JNI 到 Java 网络层,占位) == */
extern void x4_telemetry_send(const char *json);  /* 真机实现见后续 PR */

/* === 设备信息查询(走 JNI,占位) == */
static uint16_t hash_device_model(void) {
    /* 占位:实际取 Build.MODEL 后哈希,这里返回 0 */
    return 0;
}

static uint8_t get_android_major(void) {
    /* 占位:实际取 Build.VERSION.SDK_INT,这里返回 0 */
    return 0;
}

/* === 把本轮结果编码成 JSON 发送(host 仅 log)== */
static void send_telemetry(bool strong_hit, int round_score, int total_score,
                           int presence, int last_max, x4_response_action_t action) {
    char buf[512];
    int n = snprintf(buf, sizeof(buf),
        "{\"ts\":%lld,\"dm\":%u,\"av\":%u,\"mdm\":%d,"
        "\"strong\":%d,\"rscore\":%d,\"score\":%d,\"pres\":%d,"
        "\"lmax\":%d,\"dry\":%d,\"act\":%d}",
        (long long)time(NULL) * 1000,
        hash_device_model(),
        get_android_major(),
        g_x4_config.is_mdm ? 1 : 0,
        strong_hit ? 1 : 0,
        round_score, total_score, presence,
        last_max,
        x4_dry_run_is_enabled() ? 1 : 0,
        (int)action);
    (void)n;
    LOGI("[X4-TEL] %s", buf);
    x4_telemetry_send(buf);  /* 真机走 JNI 上报 */
}

/* ===================================================================== */
/* 每轮上报(dry-run 期全量,Q5.4)                                       */
/* ===================================================================== */
void x4_telemetry_log_round(bool strong_hit, int round_score,
                            int total_score, int presence, int last_max) {
    /* dry-run 期:全量上报 */
    if (x4_dry_run_is_enabled()) {
        send_telemetry(strong_hit, round_score, total_score, presence, last_max,
                       X4_RESPONSE_LOG);
        return;
    }
    /* enforce 后:无触发也记一条(便于分析),但不主动上报 */
    /* 实际 warn/kill 时由 report_warn/report_kill 单独上报 */
}

/* ===================================================================== */
/* kill/warn/presence 上报                                                */
/* ===================================================================== */
void x4_telemetry_report_kill(const char *reason) {
    send_telemetry(true /* strong_hit 暂置 true,实际由调用方传 */,
                   0, x4_engine_get_score(), x4_engine_get_presence(),
                   x4_engine_get_last_max_round_hit(),
                   X4_RESPONSE_KILL);
    (void)reason;
}

void x4_telemetry_report_warn(const char *reason) {
    send_telemetry(false, x4_engine_get_round_score_last(),
                   x4_engine_get_score(), x4_engine_get_presence(),
                   x4_engine_get_last_max_round_hit(),
                   X4_RESPONSE_WARN);
    (void)reason;
}

void x4_telemetry_report_presence(int presence) {
    send_telemetry(false, 0, x4_engine_get_score(), presence,
                   x4_engine_get_last_max_round_hit(),
                   X4_RESPONSE_LOG);
}
