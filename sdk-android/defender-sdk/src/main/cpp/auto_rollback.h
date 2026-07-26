/**
 * auto_rollback.h - X4 客户端自动回滚(ADR 0093, Q5.5)
 *
 * 三个自动触发条件(Q5.5 锁定):
 *   条件1: 同型号 5 分钟内 kill > 50 次 → 降级 onViolation = warn
 *   条件2: 强证据命中但有效分 == 0(孤立强证据,可能边界误报)→ 本 session 降级
 *   条件3: 同设备连续 3 次被 kill 后仍重开 → 降级 1 小时
 *
 * 回滚机制(Q5.5 锁定):
 *   主: onViolation 降级 kill → warn(止血快,保留告警能力)
 *   兜底: dry-run 紧急回滚(连真实攻击也旁路,极端情况)
 *
 * 合规声明:
 *   不读其他进程;仅本 APP 自身的 kill 计数。
 */
#ifndef X4_AUTO_ROLLBACK_H
#define X4_AUTO_ROLLBACK_H

#include <stdbool.h>

/* === 主入口:x4_core 每轮调一次 == */
void x4_auto_rollback_check(void);

/* === 强证据本轮命中标记(score_engine 调)==
 * 供"孤立强证据"检测使用:本轮是否命中强证据 + 本轮有效分是否为 0
 */
void x4_auto_rollback_note_round(bool strong_hit, int score);

/* === 紧急 dry-run 回滚(条件4,兜底)== */
void x4_auto_rollback_emergency(void);

#endif /* X4_AUTO_ROLLBACK_H */
