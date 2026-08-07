/*
 * host/android/log.h - Android 日志头宿主桩
 *
 * 供 tests/test_*.c 在 PC 上编译含 defender_log.h 的模块:
 * __android_log_print 置为静默空实现。
 */
#ifndef HOST_ANDROID_LOG_H
#define HOST_ANDROID_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ANDROID_LOG_UNKNOWN = 0,
    ANDROID_LOG_DEFAULT,
    ANDROID_LOG_VERBOSE,
    ANDROID_LOG_DEBUG,
    ANDROID_LOG_INFO,
    ANDROID_LOG_WARN,
    ANDROID_LOG_ERROR,
    ANDROID_LOG_FATAL,
    ANDROID_LOG_SILENT,
} android_LogPriority;

static inline int __android_log_print(int prio, const char *tag, const char *fmt, ...)
{
    (void)prio; (void)tag; (void)fmt;
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* HOST_ANDROID_LOG_H */
