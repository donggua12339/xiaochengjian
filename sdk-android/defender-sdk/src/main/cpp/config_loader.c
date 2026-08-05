/**
 * config_loader.c - X4 配置加载实现(ADR 0093)
 *
 * 简化 JSON 解析:本项目主 config 在 Java 层 DefenderConfig.kt 解析,
 * Native 通过 JNI 拿到字段。本文件提供 host fallback + 强证据开关的
 * 单向写入逻辑(Q5.6)。
 *
 * 合规声明:
 *   不解析用户业务字段;config 仅含 X4 检测配置。
 */
#include "config_loader.h"

#include <android/log.h>
#include <jni.h>
#include <stdlib.h>
#include <string.h>

#include "score_weights.h"

#define DEFENDER_TAG "X4-Config"
#include "defender_log.h"

/* === 全局配置实例 == */
x4_config_t g_x4_config = {
    .enabled = true,
    .on_violation = X4_ON_VIOLATION_KILL,
    .dry_run = false,
    .is_mdm = false,
    .soft_exempt_count = 0,
    .hard_exempt_count = 0,
    .strong_switches = {true, true, true, true, true, true, true},
};

/* === 外部 strong_enabled(来自 strong_evidence.c) == */
extern bool strong_enabled[STRONG_EVIDENCE_COUNT];

/* ===================================================================== */
/* 查询接口                                                                */
/* ===================================================================== */
bool x4_config_is_enabled(void)
{
    return g_x4_config.enabled;
}
x4_on_violation_t x4_config_get_on_violation(void)
{
    return g_x4_config.on_violation;
}

bool x4_config_is_hard_exempt(const char *pkg)
{
    if (!pkg)
        return false;
    for (int i = 0; i < g_x4_config.hard_exempt_count; i++) {
        if (strncmp(g_x4_config.hard_exempt[i], pkg, X4_PACKAGE_NAME_MAX) == 0) {
            return true;
        }
    }
    return false;
}

bool x4_config_is_soft_exempt(const char *pkg)
{
    if (!pkg)
        return false;
    /* MDM 自动探测 → softExempt 通道(Q4.4 锁定) */
    if (g_x4_config.is_mdm)
        return true;
    for (int i = 0; i < g_x4_config.soft_exempt_count; i++) {
        if (strncmp(g_x4_config.soft_exempt[i], pkg, X4_PACKAGE_NAME_MAX) == 0) {
            return true;
        }
    }
    return false;
}

/* ===================================================================== */
/* 强证据开关:单向写入(Q5.6 锁定)                                       */
/* =====================================================================
 * 远程 config 只能从 true → false(关闭某条)
 * 不能从 false → true(防 MITM 重置已关闭的开关)
 */
void x4_config_apply_strong_switch(const bool remote_vals[STRONG_EVIDENCE_COUNT])
{
    for (int i = 0; i < STRONG_EVIDENCE_COUNT; i++) {
        if (remote_vals[i] == false) {
            /* 允许远程关闭 */
            if (strong_enabled[i] != false) {
                strong_enabled[i] = false;
                g_x4_config.strong_switches[i] = false;
                LOGW("[X4] strong evidence %d DISABLED by remote config", i);
            }
        }
        /* remote_val == true → 忽略(保持本地状态,防 MITM 重置) */
    }
}

/* ===================================================================== */
/* MDM 自动探测                                                            */
/* =====================================================================
 * 通过 DevicePolicyManager API 探测(Native 走 JNI)。
 * MDM 命中 → softExempt 通道自动填充(Q4.4 锁定)。
 * 占位:实际 JNI 调用见 x4_config_mdm.c,host 返回 false。
 */
bool x4_config_detect_mdm(void)
{
    extern bool x4_config_detect_mdm_jni(void);
    bool hit = x4_config_detect_mdm_jni();
    g_x4_config.is_mdm = hit;
    if (hit) {
        LOGI("[X4] MDM device detected, softExempt auto-filled");
    }
    return hit;
}

/* ===================================================================== */
/* 加载入口:host fallback = 默认值;Android 走 JNI 拉字段                 */
/* ===================================================================== */
void x4_config_load(const char *json_path)
{
    (void) json_path; /* host 测试不读文件,用默认值 */

    /* Android 真机:通过 JNI 调 Java 层 DefenderConfig.parseX4Config() */
    extern void x4_config_load_from_jni(void);
    x4_config_load_from_jni();

    /* 加载完检测 MDM */
    x4_config_detect_mdm();

    LOGI("[X4] config loaded: enabled=%d onViolation=%d dryRun=%d isMDM=%d", g_x4_config.enabled,
         g_x4_config.on_violation, g_x4_config.dry_run, g_x4_config.is_mdm);
}
