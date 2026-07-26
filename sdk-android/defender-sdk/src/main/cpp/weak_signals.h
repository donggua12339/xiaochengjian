/**
 * weak_signals.h - X4 弱信号权重表(ADR 0093)
 *
 * 三级分类(Q3.3.c 锁定):
 *   L3 攻击指纹(50):"攻击正在发生",确定性最高但仍属弱信号
 *   L2 行为异常(40):"有异常行为发生",但可能有合法解释
 *   L1 环境噪声(30):"设备有某种能力",不构成攻击证据
 *
 * 通道归属(Q3.3.e 锁定):
 *   L3/L2 计入有效分(round_score)→ 走衰减累计 + 阈值判定
 *   L1 不计入有效分,只计入存在感(presence_count)→ 走探测告警
 *
 * 编译期硬约束(Q3.3.b 锁定):
 *   每条权重 ≤ MAX_WEAK_WEIGHT (=50),否则编译失败。
 *   这条 _Static_assert 把"弱信号权重 ≤ killThreshold - 安全余量"
 *   从文档约定升级为编译器强制。
 */
#ifndef X4_WEAK_SIGNALS_H
#define X4_WEAK_SIGNALS_H

#include "score_weights.h"

/* === L3 攻击指纹(权重 50)== */
#define W_L3_INOTIFY_MEM        50  /* inotify /proc/self/mem 写入事件 */

/* === L2 行为异常(权重 40)== */
#define W_L2_RWX                40  /* maps 含 rwx 段(已过滤 ART JIT code cache) */
#define W_L2_TIME_DELTA         40  /* 5 个时间 API 最大差值 > 200ms */
#define W_L2_CREATOR_SYS_CL     40  /* CREATOR 被系统 CL 加载的非标准类替换(ROM 合法魔改可能) */

/* === L1 环境噪声(权重 30,不计入有效分)== */
#define W_L1_MEMFD              30  /* memfd_create 数量超基线 */
#define W_L1_ANON_DALVIK        30  /* anon:dalvik 段大小超基线 */
#define W_L1_FRIDA_SUBSTR       30  /* maps 模糊匹配 frida / gum- / gmain 子串 */
#define W_L1_ZYGISK             30  /* maps 含 zygisk 字符串 */

/* === 编译期断言:每条弱信号权重 ≤ MAX_WEAK_WEIGHT(=50)==
 * 任何开发者(包括三个月后的你)想"临时把 inotify 调到 60 试试",
 * 编译直接报错——硬约束从文档约定升级为编译器强制。
 */
_Static_assert(W_L3_INOTIFY_MEM     <= MAX_WEAK_WEIGHT, "inotify weight exceeds limit");
_Static_assert(W_L2_RWX            <= MAX_WEAK_WEIGHT, "rwx weight exceeds limit");
_Static_assert(W_L2_TIME_DELTA      <= MAX_WEAK_WEIGHT, "time_delta weight exceeds limit");
_Static_assert(W_L2_CREATOR_SYS_CL  <= MAX_WEAK_WEIGHT, "creator_sys_cl weight exceeds limit");
_Static_assert(W_L1_MEMFD           <= MAX_WEAK_WEIGHT, "memfd weight exceeds limit");
_Static_assert(W_L1_ANON_DALVIK     <= MAX_WEAK_WEIGHT, "anon_dalvik weight exceeds limit");
_Static_assert(W_L1_FRIDA_SUBSTR    <= MAX_WEAK_WEIGHT, "frida_substr weight exceeds limit");
_Static_assert(W_L1_ZYGISK          <= MAX_WEAK_WEIGHT, "zygisk weight exceeds limit");

/* === 弱信号层级枚举(用于 score_engine 区分通道)== */
typedef enum {
    X4_LEVEL_L1 = 1,  /* 环境噪声,只计入存在感 */
    X4_LEVEL_L2 = 2,  /* 行为异常,计入有效分 */
    X4_LEVEL_L3 = 3,  /* 攻击指纹,计入有效分 */
} x4_signal_level_t;

#endif /* X4_WEAK_SIGNALS_H */
