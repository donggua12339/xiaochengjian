/**
 * dry_run.h - X4 dry-run 四级优先级链(ADR 0093)
 *
 * 优先级链(Q4.4 锁定,从高到低):
 *   1. 代码显式 set_dry_run_override(true) - 最高(测试/紧急旁路用)
 *   2. config 文件 x4Detect.dryRun
 *   3. Gradle BuildType 默认(debug=true, release=false)
 *   4. 硬编码 fallback=false(理论上不会用到)
 *
 * 决策链日志(Q4.4 锁定):
 *   启动时打印 [X4] dry-run decision: override=%d config=%d default=%d final=%d
 *   方便排查"为什么我的 dry-run 没生效"——不用远程猜 config。
 *
 * dry-run 语义(Q1 锁定):
 *   dry-run=true 时所有响应动作(kill/warn/toast/上报)全部短路
 *   只 log 带 [X4-DRY-RUN] 前缀
 *   dry-run 优先级 > onViolation > 强证据
 */
#ifndef X4_DRY_RUN_H
#define X4_DRY_RUN_H

#include <stdbool.h>

/* === 主接口 == */
bool x4_dry_run_is_enabled(void);

/* === 初始化(在 x4_init 调一次)== */
void x4_dry_run_init(void);

/* === 打印决策链(启动时 + config 变更时)== */
void x4_dry_run_log_decision(void);

/* === 代码显式 override(最高优先级,测试用)== */
void x4_dry_run_set_override(bool val);

#endif /* X4_DRY_RUN_H */
