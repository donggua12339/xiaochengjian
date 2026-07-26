/**
 * config_loader.h - X4 配置加载(ADR 0093)
 *
 * 5 字段 config(Q4.3 锁定):
 *   enabled / onViolation / dryRun / softExempt / hardExempt
 *   + strongEvidenceSwitches(Q5.6:运行时禁用开关,只能关不能开)
 *
 * softExempt vs hardExempt(Q4.3 锁定):
 *   softExempt 命中 → 清零有效分 + 存在感,强证据仍 kill
 *   hardExempt 命中 → 清零所有通道(含强证据),加载时弹二次确认
 *
 * 字段权限(Q4.1/Q5.6 锁定):
 *   运行时可配:enabled / onViolation / dryRun / softExempt / hardExempt / strongEvidenceSwitches
 *   构建期可配(宏覆盖):killThreshold / warnThreshold
 *   完全硬编码:decayFactor / floorNoiseFactor / zeroRounds / presenceAlert / 权重表
 *
 * strongEvidenceSwitches 单向(Q5.6 锁定):
 *   远程 config 只能从 true → false(关闭某条)
 *   不能从 false → true(防 MITM 重置已关闭的开关)
 */
#ifndef X4_CONFIG_LOADER_H
#define X4_CONFIG_LOADER_H

#include <stdbool.h>
#include "response_chain.h"  /* x4_on_violation_t */
#include "score_weights.h"   /* STRONG_EVIDENCE_COUNT */

#define X4_EXEMPT_MAX  16
#define X4_PACKAGE_NAME_MAX 256

typedef struct {
    bool   enabled;
    x4_on_violation_t on_violation;
    bool   dry_run;
    bool   is_mdm;  /* MDM 自动探测填充,config 文件不写 */

    /* 软/硬豁免包名列表 */
    int    soft_exempt_count;
    char   soft_exempt[X4_EXEMPT_MAX][X4_PACKAGE_NAME_MAX];
    int    hard_exempt_count;
    char   hard_exempt[X4_EXEMPT_MAX][X4_PACKAGE_NAME_MAX];

    /* 强证据开关(默认全 true,远程只能关单条) */
    bool   strong_switches[STRONG_EVIDENCE_COUNT];
} x4_config_t;

extern x4_config_t g_x4_config;

/* === 加载入口:x4_core 调用 == */
void x4_config_load(const char *json_path);

/* === 查询接口 == */
bool                  x4_config_is_enabled(void);
x4_on_violation_t     x4_config_get_on_violation(void);
bool                  x4_config_is_hard_exempt(const char *pkg);
bool                  x4_config_is_soft_exempt(const char *pkg);

/* === 强证据开关查询(供 strong_evidence.c 用)== */
extern bool strong_enabled[STRONG_EVIDENCE_COUNT];

/* === MDM 自动探测(Q4.4 + 设计 §MDM)== */
bool x4_config_detect_mdm(void);

#endif /* X4_CONFIG_LOADER_H */
