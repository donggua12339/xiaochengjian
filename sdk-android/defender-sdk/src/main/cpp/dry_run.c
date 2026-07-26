/**
 * dry_run.c - X4 dry-run 四级优先级链实现(ADR 0093)
 *
 * 优先级链(从高到低):
 *   1. dry_run_override       - 代码显式(测试)
 *   2. config 文件
 *   3. Gradle BuildType 默认
 *   4. 硬编码 fallback=false
 *
 * 启动打印决策链,方便排查。
 */
#include "dry_run.h"
#include "config_loader.h"  /* g_x4_config.dry_run */

#include <android/log.h>

#define DEFENDER_TAG "X4-DryRun"
#include "defender_log.h"

/* === Gradle BuildType 默认:由 -DBUILD_TYPE_DEBUG 决定 == */
#ifdef BUILD_TYPE_DEBUG
#define GRADLE_DEFAULT_DRY_RUN true
#else
#define GRADLE_DEFAULT_DRY_RUN false
#endif

/* === 硬编码 fallback(理论上不会用到)== */
#define HARDCODED_FALLBACK false

/* === 静态状态 == */
static bool dry_run_override = false;  /* 优先级 1:代码显式 */
static bool dry_run_initialized = false;

/* ===================================================================== */
/* 计算最终 dry-run 值                                                     */
/* ===================================================================== */
bool x4_dry_run_is_enabled(void) {
    /* 优先级 1:代码 override */
    if (dry_run_override) return true;

    /* 优先级 2:config 文件(由 config_loader 加载到 g_x4_config.dry_run) */
    if (g_x4_config.dry_run) return true;

    /* 优先级 3:Gradle 默认 */
    return GRADLE_DEFAULT_DRY_RUN;

    /* 优先级 4:硬编码 fallback(理论不可达,因为 Gradle 默认已锁定 true/false) */
}

/* ===================================================================== */
/* 代码显式 override(最高优先级)== */
void x4_dry_run_set_override(bool val) {
    dry_run_override = val;
    LOGI("[X4] dry-run override set to %d", val);
}

/* ===================================================================== */
/* 打印决策链(启动时 + config 变更时)== */
void x4_dry_run_log_decision(void) {
    bool final = x4_dry_run_is_enabled();
    LOGI("[X4] dry-run decision: override=%d config=%d default=%d fallback=%d final=%d",
         dry_run_override,
         g_x4_config.dry_run,
         GRADLE_DEFAULT_DRY_RUN,
         HARDCODED_FALLBACK,
         final);
}

/* ===================================================================== */
/* 初始化(在 x4_init 调一次)== */
void x4_dry_run_init(void) {
    if (dry_run_initialized) return;
    dry_run_initialized = true;
    x4_dry_run_log_decision();
    (void)HARDCODED_FALLBACK;  /* 占位防 unused warning */
}
