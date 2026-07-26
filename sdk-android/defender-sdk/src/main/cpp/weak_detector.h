/**
 * weak_detector.h - X4 弱信号 L1/L2/L3 检测(ADR 0093)
 *
 * 设计哲学(Q3.3.c 锁定):
 *   L3 攻击指纹(50):"攻击正在发生",计入有效分
 *   L2 行为异常(40):"有异常行为",可能有合法解释,计入有效分
 *   L1 环境噪声(30):"设备有某种能力",不构成攻击证据,只计入存在感
 *
 * 通道归属(Q3.3.e 锁定):
 *   L3/L2 返回 true → score_engine 加 round_score + 加 presence_count
 *   L1 返回 true   → score_engine 不加 round_score,只加 presence_count
 *
 * 弱信号列表:
 *   L3: inotify /proc/self/mem 写入事件
 *   L2: rwx(过滤ART) / 时间差 >200ms / CREATOR 系统 CL 非标准类
 *   L1: memfd 超基线 / anon:dalvik 超基线 / frida 子串 / zygisk
 *
 * 注:seccomp 检测已移除(Android 8+ AOSP 自带 seccomp=filter,合法状态 100% 命中,
 *     ≠0 即报是误判。原 W_L2_SECCOMP=40 已从 weak_signals.h 删除)
 *
 * 合规声明:
 *   所有检测读 /proc/self/(自身进程),不读其他进程,符合 ADR 0077 边界。
 */
#ifndef X4_WEAK_DETECTOR_H
#define X4_WEAK_DETECTOR_H

#include <stdbool.h>

/* === L3 攻击指纹 === */
bool check_inotify_mem(void);

/* === L2 行为异常 === */
bool check_rwx(void);
bool check_time_delta(void);
bool check_creator_sys_cl(void);

/* === L1 环境噪声 === */
bool check_memfd(void);
bool check_anon_dalvik(void);
bool check_frida_substr(void);
bool check_zygisk(void);

/* === 基线初始化(在 .init_array 或 x4_init 调一次)==
 * 部分弱信号(memfd / anon:dalvik)需要先记基线,运行期比对。
 * L1 不计入有效分,即使基线漂移也只是降级存在感,不破阈值。
 */
void x4_weak_baseline_init(void);

/* === 分段搜索 /proc/self/maps(不受文件大小限制)==
 * /proc/self/maps 在注入 frida 后可达 200-300KB,单次 read 64KB 会截断。
 * 本函数分 64KB 块顺序读取,块间保留 256B 重叠防关键词跨块丢失。
 * 供 check_frida_substr / check_zygisk / strong_evidence④ 共用。
 */
bool x4_search_maps(const char *patterns[], int count);

#endif /* X4_WEAK_DETECTOR_H */
