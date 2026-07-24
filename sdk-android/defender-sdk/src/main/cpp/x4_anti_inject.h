/**
 * x4_anti_inject.h - X4-1 L1 反注入(ADR 0093)
 *
 * 检测 SO 注入 / ptrace 注入 / 异常可执行段。全部用 x4_svc 直发系统调用 +
 * x4_str 自实现比较 + OBF 运行时解密关键词——抗 libc hook 与静态字符串提取。
 *
 * 返回约定:>=0 为可疑计数(0=干净);负数为内部错误(非致命,按 0 处理)。
 * 检测点设计来源:docs/x4/X4-IMPLEMENTATION-PLAN.md L1(调研 W4/C2/看雪3/K1)。
 */
#ifndef X4_ANTI_INJECT_H
#define X4_ANTI_INJECT_H

/* dl_iterate_phdr 枚举已加载 SO,匹配注入框架特征(frida/gadget/zygisk/riru/...)。
 * 比读 maps 更底层,抗 magiskhide/maps 重命名。返回可疑 SO 数。 */
int x4_detect_injected_so(void);

/* 扫 /proc/self/maps,统计路径含注入框架特征的可执行段(r-xp/rwxp)= 注入落点。
 * 返回可疑段数。 */
int x4_detect_exec_segments(void);

/* 读 /proc/self/status(TracerPid)+ /proc/self/wchan(ptrace_stop)。
 * 返回 1=被 ptrace 附加 / 0=否 / 负=内部错误。 */
int x4_detect_ptrace(void);

/* L1 综合:返回总可疑计数(0=干净)。供 x4_daemon 周期调用。 */
int x4_anti_inject_check(void);

#endif /* X4_ANTI_INJECT_H */
