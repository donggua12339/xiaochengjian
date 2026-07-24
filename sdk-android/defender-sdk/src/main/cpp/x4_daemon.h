/**
 * x4_daemon.h - X4-0 基建:多回调守护线程框架(ADR 0093)
 *
 * 注册多个检测回调,守护线程以随机间隔(默认 5-15s)周期运行,异步执行 L1-L5 检测,
 * 不占冷启动预算(冷启动 <50ms,昂贵检测放此处)。回调返回 0=正常、非 0=异常,
 * 由回调自行渐进式处置(延迟+污染,不立即崩溃)。
 */
#ifndef X4_DAEMON_H
#define X4_DAEMON_H

#define X4_DAEMON_MAX_CHECKS 16

typedef int (*x4_check_fn)(void *ctx);

/* 注册检测回调(成功返回 0);须在 x4_daemon_start 前注册。 */
int  x4_daemon_register(x4_check_fn fn, void *ctx);
/* 启动守护线程(已启动则忽略);成功返回 0。 */
int  x4_daemon_start(void);
/* 停止守护线程(分离线程,下一周期退出)。 */
void x4_daemon_stop(void);
/* 设置周期间隔范围(秒,默认 5-15)。 */
void x4_daemon_set_interval(int min_sec, int max_sec);

#endif /* X4_DAEMON_H */
