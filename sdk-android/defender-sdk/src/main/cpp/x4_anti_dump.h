/**
 * x4_anti_dump.h - X4-4 L3 反内存 Dump(ADR 0093)
 *
 * 四项检测:
 *  1. 异常 rwx 段(正常 app 永不需要,出现 = dump/hook 工具)
 *  2. anon:dalvik 段异常(玄甲不加载额外 DEX,额外 = FART/dump 工具)
 *  3. memfd 数量基线(玄甲自身 1 个;额外 = 可疑)
 *  4. inotify 监控 /proc/self/mem IN_OPEN(预警层)
 */
#ifndef X4_ANTI_DUMP_H
#define X4_ANTI_DUMP_H

/* 初始化:记录 memfd 基线 + 启动 inotify 监控线程。须在 X0 加载完成后调用。 */
void x4_anti_dump_init(void);

/* 检测 1:扫 maps 找 rwxp 段(正常 app 永不需要 rwx)。返回 rwx 段数。 */
int x4_check_rwx_segments(void);

/* 检测 2:扫 maps 找 anon:dalvik- 段,玄甲不加载额外 DEX,基线固定(0 或已知值)。
 * 返回超出基线的 anon:dalvik 段数(0=正常)。 */
int x4_check_anon_dalvik(void);

/* 检测 3:扫 /proc/self/fd 找 memfd 数量,与基线比对。返回超出基线数(0=正常)。 */
int x4_check_memfd_count(void);

/* 检测 4:inotify 监控是否被触发(/proc/self/mem 被打开)。返回 1=触发/0=否。
 * ⚠️ procfs inotify 部分内核不可靠,仅预警层,不单独作为判定依据。 */
int x4_check_inotify_triggered(void);

/* L3 综合:返回可疑计数(0=干净)。 */
int x4_anti_dump_check(void);

#endif
