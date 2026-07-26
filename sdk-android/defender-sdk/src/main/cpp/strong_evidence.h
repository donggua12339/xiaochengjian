/**
 * strong_evidence.h - X4 强证据 5 条检测(ADR 0093)
 *
 * 设计哲学(Q2 锁定):
 *   强证据 = 不可抵赖的物理事实,无视阈值,即时 kill(dry-run 除外)。
 *   5 条强证据:
 *     ① 签名 hash 不匹配(APK 字节级,零误报源)
 *     ② CREATOR/mPM 被应用 PathClassLoader 代理(注入物必然在 app CL)
 *     ③ 调试端口 23946 LISTEN(正常设备 ≈ 0)
 *     ④ maps 精确含 frida-agent.so/gadget/linjector(进程被注入的物理事实)
 *     ⑤ state=T ∧ TracerPid≠0(双条件,防系统瞬态误报)
 *
 * 开关机制(Q5.6 锁定):
 *   strong_enabled[5] 默认全 true
 *   远程 config strongEvidenceSwitches 只能从 true → false(防 MITM 重置)
 *   关闭某条后,该条降级为"既不进强通道也不进弱通道"
 */
#ifndef X4_STRONG_EVIDENCE_H
#define X4_STRONG_EVIDENCE_H

#include <stdbool.h>
#include "score_weights.h"

/* 强证据开关表(运行时可被 config_loader 关闭单条,默认全 true) */
extern bool strong_enabled[STRONG_EVIDENCE_COUNT];

/* === 5 条独立检测函数,返回 true 表示命中 === */

/**
 * ① 签名 hash 不匹配
 * 复用 sig_verify_check_b()——APK 内容 hash 与白名单比对。
 * 注意:必须用 svc 直读(绕过 NP proot Hook openat),已在 sig_verify.c 内部实现。
 */
bool check_signature_hash(void);

/**
 * ② CREATOR/mPM 被应用 PathClassLoader 代理
 * 通过 JNI 获取 PackageInfo.CREATOR,检查其 ClassLoader:
 *   - 应用 PathClassLoader 加载 → 命中(强证据)
 *   - BootClassLoader / 系统 CL 加载 → 不命中(可能走弱信号 CREATOR-sysCL)
 */
bool check_creator_classloader(void);

/**
 * ③ 调试端口 23946 LISTEN
 * 读 /proc/net/tcp + /proc/net/tcp6,搜 5D8A(23946 hex),状态 0A(LISTEN)。
 * 全部用 svc 直读,绕过 libc hook。
 */
bool check_port_23946(void);

/**
 * ④ maps 精确含 frida-agent.so / frida-gadget.so / linjector
 * 读 /proc/self/maps,精确匹配(非子串),用自实现 x4_strstr 防 libc hook strstr。
 */
bool check_frida_agent_maps(void);

/**
 * ⑤ state=T ∧ TracerPid≠0(双条件)
 * 读 /proc/self/stat 第 3 字段 + /proc/self/status TracerPid:,
 * 两个条件同时满足才命中(防系统瞬态 stop 误报)。
 */
bool check_state_and_tracer(void);

/**
 * 总入口:遍历 5 条强证据,命中任一(且开关为 true)即返回 true。
 * 响应链 response_chain.c 直接调这个。
 */
bool check_all_strong_evidence(void);

#endif /* X4_STRONG_EVIDENCE_H */
