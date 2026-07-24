/**
 * x4_anti_debug.h - X4-3 L2 反调试(ADR 0093)
 *
 * 四项检测(与 L1 的 ptrace TracerPid/wchan 互补):
 *  1. /proc/self/stat state 字段(T/t = traced/stopped)
 *  2. 时间差(clock_gettime 夹被测代码,多次采样超阈值)
 *  3. 断点指令扫描(ARM64 BRK 0xD420 模式)
 *  4. Frida 端口(/proc/net/tcp 搜 :69A2)
 */
#ifndef X4_ANTI_DEBUG_H
#define X4_ANTI_DEBUG_H

int x4_check_stat_state(void);
int x4_check_time_delta(void);
int x4_check_breakpoints(void);
int x4_check_frida_port(void);

/* L2 综合:返回可疑计数(0=干净)。 */
int x4_anti_debug_check(void);

#endif
