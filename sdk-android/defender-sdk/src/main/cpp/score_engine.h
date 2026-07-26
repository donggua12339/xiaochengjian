/**
 * score_engine.h - X4 衰减累计引擎(ADR 0093)
 *
 * 设计哲学(Q3 锁定):
 *   三通道独立:
 *     有效分通道(L2+L3 衰减累计)→ 决定 warn/kill
 *     存在感通道(L1+L2+L3 命中计数)→ 决定探测告警
 *     强证据通道(check_all_strong_evidence 返回)→ 即时 kill(本引擎只透传)
 *
 * 衰减动力学(Q3.3.d 锁定):
 *   衰减系数 0.7
 *   命中:score = round_score + score × 0.7;重置 no_hit_rounds
 *   无命中:score = score × 0.7;no_hit_rounds++
 *   no_hit_rounds ≥ N(5) 后底噪按 0.7 衰减 3 轮归零(防参数探测)
 *
 * 底噪(Q3.3.f 锁定):
 *   floor_noise = last_max_round_hit × 0.3
 *   last_max_round_hit:最近一次有命中轮的最高单次分,永不下降
 *
 * 三通道响应:
 *   强证据 → 即时 kill(dry-run 除外)
 *   有效分 ≥ killThreshold(70) → 按 onViolation 响应
 *   有效分 ≥ warnThreshold(40) → warn
 *   存在感 ≥ PRESENCE_ALERT(10) → log+上报
 */
#ifndef X4_SCORE_ENGINE_H
#define X4_SCORE_ENGINE_H

#include <stdbool.h>

/* === 全局状态查询接口(供 telemetry / config_loader 用)== */
int  x4_engine_get_score(void);
int  x4_engine_get_presence(void);
int  x4_engine_get_last_max_round_hit(void);
int  x4_engine_get_no_hit_rounds(void);
bool x4_engine_is_strong_hit_last_round(void);
int  x4_engine_get_round_score_last(void);

/* === 主轮检入口:x4_core 守护线程每轮调一次 == */
void x4_engine_round(void);

/* === 软豁免时清零弱通道(强证据通道仍 kill)== */
void x4_engine_reset_soft(void);

#endif /* X4_SCORE_ENGINE_H */
