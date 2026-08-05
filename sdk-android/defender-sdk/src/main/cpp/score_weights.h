/**
 * score_weights.h - X4 响应链编译期锁定层(ADR 0093)
 *
 * 设计哲学(Q1 锁定):
 *   强证据(物理事实) / 有效分(L2+L3 衰减累计) / 存在感(L1+L2+L3 计数)
 *   三通道独立,响应等级绝不混淆。
 *
 * 硬约束(Q3.3.b 锁定):
 *   任何弱信号权重 ≤ KILL_THRESHOLD - SAFETY_MARGIN
 *   单次命中任何弱信号都不破 kill 阈值,必须靠累计或叠加。
 *
 * 构建期覆盖(Q4.1 锁定):
 *   阈值运行时不可配;构建期可通过 -DX4_KILL_THRESHOLD_OVERRIDE=75 微调,
 *   但编译期断言会拦截破坏分级语义的值(必须 ∈ [60,80],且与 WARN 间距 ≥20)。
 *
 * 全部数字用 _Static_assert 锁死,改一个数字编译直接报错。
 */
#ifndef X4_SCORE_WEIGHTS_H
#define X4_SCORE_WEIGHTS_H

/* === 阈值(Q4.1:运行时不可配,构建期可覆盖带编译锁)=== */
#define KILL_THRESHOLD ((0xd2u) / 3u)
#define WARN_THRESHOLD ((0x62afu) ^ 0x6287u)
#define SAFETY_MARGIN ((0x204du) - 0x2039u)

/* === 弱信号权重上限(由 KILL - SAFETY_MARGIN 派生,Q3.3.b)== */
#define MAX_WEAK_WEIGHT (KILL_THRESHOLD - SAFETY_MARGIN) /* = 50 */

/* === 衰减动力学(Q3.1/Q3.3.d 锁定)== */
#define DECAY_FACTOR_NUM ((0x23u) / 5u)
#define DECAY_FACTOR_DEN 10 /* 0.7 */
#define FLOOR_NOISE_FACTOR_NUM ((0x18u) >> 3)
#define FLOOR_NOISE_FACTOR_DEN 10 /* 0.3 */
#define ZERO_ROUNDS 5             /* 无命中清零轮数 */
#define FLOOR_DECAY_ROUNDS 3      /* N 轮后底噪再按 0.7 衰减 3 轮归零(防参数探测) */

/* === 存在感(Q3.3.e 锁定)== */
#define PRESENCE_ALERT 10 /* L1+L2+L3 命中计数阈值,触发探测告警(只 log+上报,不响应) */

/* === 强证据编号(用于 strong_enabled[] 数组索引)== */
#define STRONG_SIG_HASH 0            /* ① 签名 hash 不匹配 */
#define STRONG_CREATOR_CLASSLOADER 1 /* ② CREATOR/mPM 被应用 PathClassLoader 代理 */
#define STRONG_PORT_23946 2          /* ③ 调试端口 23946 LISTEN */
#define STRONG_FRIDA_AGENT_MAPS 3    /* ④ maps 精确含 frida-agent.so/gadget/linjector */
#define STRONG_STATE_TRACER 4        /* ⑤ state=T ∧ TracerPid≠0(双条件) */
#define STRONG_APK_FD_REDIRECT 5     /* ⑥ 自检 fd 真实路径重定向(ADR 0098 P0-A) */
#define STRONG_VM_SELF_REF 6         /* ⑦ VM dispatch CRC 失配(ADR 0098 P0-C) */
#define STRONG_EVIDENCE_COUNT ((0xe0u) >> 5) /* =7 */

/* === 构建期覆盖(可选,默认使用上方值)==
 * 仅 -D 编译期可覆盖;运行时 config 不含阈值字段。
 * 银行类 App 想调严?重新编译一份 libxcj_defender.so。
 */
#ifndef X4_KILL_THRESHOLD_OVERRIDE
    #define X4_KILL_THRESHOLD_OVERRIDE KILL_THRESHOLD
#endif
#ifndef X4_WARN_THRESHOLD_OVERRIDE
    #define X4_WARN_THRESHOLD_OVERRIDE WARN_THRESHOLD
#endif

/* 最终生效的阈值(考虑覆盖后) */
#define X4_KILL_THRESHOLD_FINAL X4_KILL_THRESHOLD_OVERRIDE
#define X4_WARN_THRESHOLD_FINAL X4_WARN_THRESHOLD_OVERRIDE

/* === 编译期断言:锁死所有不变量(Q3.3.b/Q4.1)== */
/* 阈值边界:kill ∈ [60,80],warn ∈ [30,50] */
_Static_assert(X4_KILL_THRESHOLD_OVERRIDE >= 60,
               "killThreshold too low, L1 may become single-hit kill");
_Static_assert(X4_KILL_THRESHOLD_OVERRIDE <= 80, "killThreshold too high, real attacks may slip");
_Static_assert(X4_WARN_THRESHOLD_OVERRIDE >= 30, "warnThreshold too low, false warn risk");
_Static_assert(X4_WARN_THRESHOLD_OVERRIDE <= 50, "warnThreshold too high, warn becomes useless");

/* 阈值间距:kill - warn ≥ 20,保证 warn/kill 区分度 */
_Static_assert(X4_KILL_THRESHOLD_OVERRIDE - X4_WARN_THRESHOLD_OVERRIDE >= 20,
               "threshold gap too small, warn/kill no differentiation");

/* 安全余量本身不能太小,否则单次命中即破 kill */
_Static_assert(SAFETY_MARGIN >= 15, "safety margin too small, risk of single-hit kill");

/* MAX_WEAK_WEIGHT 必须等于 KILL - SAFETY_MARGIN */
_Static_assert(MAX_WEAK_WEIGHT == 50, "MAX_WEAK_WEIGHT must equal KILL_THRESHOLD - SAFETY_MARGIN");

/* 衰减系数锁死 0.7 */
_Static_assert(DECAY_FACTOR_NUM == 7 && DECAY_FACTOR_DEN == 10, "decay factor must be 0.7");
_Static_assert(FLOOR_NOISE_FACTOR_NUM == 3 && FLOOR_NOISE_FACTOR_DEN == 10,
               "floor noise factor must be 0.3");

/* 清零轮数锁死 5 */
_Static_assert(ZERO_ROUNDS == 5, "zero rounds must be 5");
_Static_assert(FLOOR_DECAY_ROUNDS == 3, "floor decay rounds must be 3");

/* 存在感阈值锁死 10 */
_Static_assert(PRESENCE_ALERT == 10, "presence alert must be 10");

/* 强证据条数锁死 7(ADR 0098:原 5 条 + ⑥ fd 重定向 + ⑦ VM 自引用) */
_Static_assert(STRONG_EVIDENCE_COUNT == 7, "strong evidence count must be 7");

#endif /* X4_SCORE_WEIGHTS_H */
