/**
 * score_engine.c - X4 衰减累计引擎实现(ADR 0093)
 *
 * 设计哲学(Q3 锁定):
 *   三通道独立运行,响应等级绝不混淆。
 *
 * 衰减动力学(Q3.1/Q3.3.d 锁定):
 *   衰减系数 0.7(用整数运算 7/10 避免浮点误差累积)
 *   命中:score = round_score + score × 0.7;重置 no_hit_rounds
 *   无命中:score = score × 0.7;no_hit_rounds++
 *   no_hit_rounds ≥ N(5) 后,底噪也按 0.7 衰减,3 轮归零(防参数探测)
 *
 * 底噪(Q3.3.f 锁定):
 *   floor_noise = last_max_round_hit × 0.3
 *   last_max_round_hit:最近一次有命中轮的最高单次分,永不下降
 *
 *   "永不下降"的语义:
 *     - 轮3 命中 inotify(50)+seccomp(40),last_max_round_hit=50
 *     - 轮4 无命中,last_max_round_hit 仍为 50(不更新)
 *     - 轮5 命中 rwx(40),last_max_round_hit 仍为 50(取 max,不降)
 *     - 这是"攻击者曾达到的最高攻击强度"的记忆
 *
 * 通道归属(Q3.3.e 锁定):
 *   L3/L2 命中 → 计入 round_score(有效分)+ presence_count(存在感)
 *   L1 命中    → 只计入 presence_count,不加 round_score
 */
#include "score_engine.h"
#include "score_weights.h"
#include "weak_signals.h"
#include "strong_evidence.h"
#include "weak_detector.h"

#include <android/log.h>

#define DEFENDER_TAG "X4-Engine"
#include "defender_log.h"

/* ===================================================================== */
/* 全局状态(Q3 完整定稿)                                                */
/* ===================================================================== */

/**
 * X4 衰减底噪的基准值来源。
 *
 * 语义:最近一次"有命中"的那一轮中,单次命中分的最高值。
 * 例如:轮3命中 inotify(50)+seccomp(40),则 last_max_round_hit=50。
 *      轮4无命中,last_max_round_hit 仍为 50(不更新)。
 *      轮5命中 rwx(40),last_max_round_hit 仍为 50(取 max,不降)。
 *
 * 用途:底噪 = last_max_round_hit × 0.3
 *      攻击者停手后,底噪在 N=5 轮无命中后按 0.7 衰减 3 轮归零。
 *
 * 关键不变量:
 *   - 仅在 round_has_hit=true 时更新(取本轮 max)
 *   - 永不从 50 降到 40(即使后续轮命中更低,保持历史最高)
 *   - 这是"攻击者曾达到的最高攻击强度"的记忆
 */
static int g_last_max_round_hit = 0;

static int g_score = 0;             /* 有效分累计(L2+L3 衰减) */
static int g_presence_count = 0;    /* 存在感计数(L1+L2+L3 命中数累加,无衰减) */
static int g_no_hit_rounds = 0;     /* 连续无命中轮数 */
static int g_floor_decay_counter = 0; /* N 轮后底噪衰减计数器(0..3) */
static int g_round_score_last = 0;  /* 上一轮 round_score,供 telemetry */
static bool g_strong_hit_last = false; /* 上一轮强证据命中 */

/* === 全局状态查询接口 == */
int  x4_engine_get_score(void)               { return g_score; }
int  x4_engine_get_presence(void)            { return g_presence_count; }
int  x4_engine_get_last_max_round_hit(void)  { return g_last_max_round_hit; }
int  x4_engine_get_no_hit_rounds(void)       { return g_no_hit_rounds; }
bool x4_engine_is_strong_hit_last_round(void){ return g_strong_hit_last; }
int  x4_engine_get_round_score_last(void)    { return g_round_score_last; }

/* === 软豁免清零弱通道 == */
void x4_engine_reset_soft(void) {
    g_score = 0;
    g_presence_count = 0;
    g_no_hit_rounds = 0;
    g_last_max_round_hit = 0;
    g_floor_decay_counter = 0;
    LOGI("[X4] softExempt hit, soft channels reset");
}

/* ===================================================================== */
/* 主轮检                                                                  */
/* ===================================================================== */
void x4_engine_round(void) {
    int  round_score    = 0;  /* 本轮有效分(L2+L3) */
    int  round_presence = 0;  /* 本轮存在感(L1+L2+L3) */
    bool round_has_hit  = false;
    int  max_hit_this_round = 0;

    /* === 强证据通道(本引擎只透传给 response_chain)=== */
    g_strong_hit_last = check_all_strong_evidence();

    /* === 弱信号 L3(权重 50,计入有效分 + 存在感)== */
    if (check_inotify_mem()) {
        round_score += W_L3_INOTIFY_MEM;
        round_presence++;
        round_has_hit = true;
        if (W_L3_INOTIFY_MEM > max_hit_this_round) max_hit_this_round = W_L3_INOTIFY_MEM;
    }

    /* === 弱信号 L2(权重 40,计入有效分 + 存在感)== */
    /* 注:seccomp 检测已移除(Android 8+ AOSP 自带 seccomp=filter,合法状态 100% 命中,
     *    ≠0 即报是误判。详见 weak_signals.h 删除 W_L2_SECCOMP 处的注释) */
    if (check_rwx()) {
        round_score += W_L2_RWX;
        round_presence++;
        round_has_hit = true;
        if (W_L2_RWX > max_hit_this_round) max_hit_this_round = W_L2_RWX;
    }
    if (check_time_delta()) {
        round_score += W_L2_TIME_DELTA;
        round_presence++;
        round_has_hit = true;
        if (W_L2_TIME_DELTA > max_hit_this_round) max_hit_this_round = W_L2_TIME_DELTA;
    }
    if (check_creator_sys_cl()) {
        round_score += W_L2_CREATOR_SYS_CL;
        round_presence++;
        round_has_hit = true;
        if (W_L2_CREATOR_SYS_CL > max_hit_this_round) max_hit_this_round = W_L2_CREATOR_SYS_CL;
    }

    /* === 弱信号 L1(权重 30,不计入有效分,只计入存在感)==
     * Q3.3.e 锁定:L1 单条不计入 round_score,但计入 presence_count。
     * 这样 L1 永远不破 kill 阈值,但通过 presence 通道让"持续探测"可见。
     */
    if (check_memfd()) {
        round_presence++;
        round_has_hit = true;
        if (W_L1_MEMFD > max_hit_this_round) max_hit_this_round = W_L1_MEMFD;
    }
    if (check_anon_dalvik()) {
        round_presence++;
        round_has_hit = true;
        if (W_L1_ANON_DALVIK > max_hit_this_round) max_hit_this_round = W_L1_ANON_DALVIK;
    }
    if (check_frida_substr()) {
        round_presence++;
        round_has_hit = true;
        if (W_L1_FRIDA_SUBSTR > max_hit_this_round) max_hit_this_round = W_L1_FRIDA_SUBSTR;
    }
    if (check_zygisk()) {
        round_presence++;
        round_has_hit = true;
        if (W_L1_ZYGISK > max_hit_this_round) max_hit_this_round = W_L1_ZYGISK;
    }

    g_round_score_last = round_score;

    /* =================================================================
     * 衰减动力学(Q3.1/Q3.3.d/Q3.3.f 锁定)
     * 整数运算避免浮点误差累积:× 7 / 10
     * ================================================================= */
    if (round_has_hit) {
        /* 更新底噪基准:取 max,永不下降(Q3.3.f) */
        if (max_hit_this_round > g_last_max_round_hit) {
            g_last_max_round_hit = max_hit_this_round;
        }
        g_no_hit_rounds = 0;
        g_floor_decay_counter = 0;

        /* 有效分衰减 + 本轮加分 */
        g_score = round_score + (g_score * DECAY_FACTOR_NUM / DECAY_FACTOR_DEN);
        g_presence_count += round_presence;

        LOGI("[X4] round hit: +score=%d total=%d presence=%d last_max=%d",
             round_score, g_score, g_presence_count, g_last_max_round_hit);
    } else {
        /* 无命中:衰减有效分 */
        g_score = g_score * DECAY_FACTOR_NUM / DECAY_FACTOR_DEN;
        g_no_hit_rounds++;

        if (g_no_hit_rounds >= ZERO_ROUNDS) {
            /* N 轮后底噪也按 0.7 衰减,3 轮归零(防参数探测,Q3.3.f) */
            if (g_floor_decay_counter < FLOOR_DECAY_ROUNDS) {
                g_floor_decay_counter++;
                /* 底噪逻辑上衰减;last_max_round_hit 保持不动(它只是"曾达到的最高值") */
            }
            /* 有效分加速清零 */
            if (g_score < 1) g_score = 0;
        }
        /* 仍在 N 轮内:保留底噪(last_max_round_hit 不变) */
    }

    /* === 响应链判定(委托 response_chain)=== */
    extern void x4_response_evaluate(bool strong_hit, int score, int presence);
    x4_response_evaluate(g_strong_hit_last, g_score, g_presence_count);
}
