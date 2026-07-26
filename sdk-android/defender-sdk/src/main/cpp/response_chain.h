/**
 * response_chain.h - X4 三通道响应链(ADR 0093)
 *
 * 优先级链(从高到低,Q4.2 锁定):
 *   1. dry-run=true(任意来源)→ 全部只 log [X4-DRY-RUN]
 *   2. 强证据命中 → kill(无视 onViolation)
 *   3. 有效分 ≥ killThreshold → 按 onViolation 响应
 *   4. 有效分 ≥ warnThreshold → warn
 *   5. 存在感 ≥ PRESENCE_ALERT → log+上报
 *   6. 以上都不命中 → 只 log 原始数据
 *
 * 关键不变量(Q4.2 锁定):
 *   - onViolation 仅控制"有效分通道",不影响"强证据通道"
 *   - 即使 onViolation=none,强证据仍然 kill
 *   - 唯一能旁路强证据的开关是 dry-run=true
 *   - dry-run 优先级 > onViolation 优先级 > 强证据
 */
#ifndef X4_RESPONSE_CHAIN_H
#define X4_RESPONSE_CHAIN_H

#include <stdbool.h>

/* onViolation 枚举(Q4.2 锁定) */
typedef enum {
    X4_ON_VIOLATION_KILL = 0,
    X4_ON_VIOLATION_WARN = 1,
    X4_ON_VIOLATION_NONE = 2,
} x4_on_violation_t;

/* === 响应链评估入口:score_engine 每轮调一次 == */
void x4_response_evaluate(bool strong_hit, int score, int presence);

/* === trigger 函数(供 auto_rollback 降级时复用)== */
void x4_trigger_kill(const char *reason);
void x4_trigger_warn(const char *reason);

#endif /* X4_RESPONSE_CHAIN_H */
