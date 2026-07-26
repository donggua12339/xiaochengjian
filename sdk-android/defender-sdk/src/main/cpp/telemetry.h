/**
 * telemetry.h - X4 安全状态快照上报(ADR 0093)
 *
 * 字段全部是位图/哈希/枚举,无用户业务数据(Q5.4 锁定)。
 * 符合 ADR 0077 隐私合规边界。
 *
 * 上报策略(Q5.4 锁定):
 *   dry-run 期:全量上报(每轮一次)
 *   enforce 后:仅 warn/kill 触发时上报
 */
#ifndef X4_TELEMETRY_H
#define X4_TELEMETRY_H

#include <stdint.h>
#include <stdbool.h>

/* 响应动作枚举(供 telemetry 编码) */
typedef enum {
    X4_RESPONSE_LOG = 0,
    X4_RESPONSE_WARN = 1,
    X4_RESPONSE_KILL = 2,
} x4_response_action_t;

/* === 主接口 == */
void x4_telemetry_log_round(bool strong_hit, int round_score,
                            int total_score, int presence, int last_max);
void x4_telemetry_report_kill(const char *reason);
void x4_telemetry_report_warn(const char *reason);
void x4_telemetry_report_presence(int presence);

#endif /* X4_TELEMETRY_H */
