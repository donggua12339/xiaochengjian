/**
 * defender_log.h - 统一日志宏(ADR 0094 日志脱敏)
 *
 * Release(NDEBUG):LOGI/LOGW 编译期移除,LOGE 保留但敏感值须手动脱敏。
 * Debug:全量输出。
 *
 * 用法:在 .c 文件顶部 #define DEFENDER_TAG "XXX" 后 #include "defender_log.h"
 */
#ifndef DEFENDER_LOG_H
#define DEFENDER_LOG_H

#include <android/log.h>

#ifndef DEFENDER_TAG
#define DEFENDER_TAG "Defender"
#endif

#ifdef NDEBUG
/* Release:砍掉 INFO/WARN,只保留 ERROR */
#define LOGI(...) ((void)0)
#define LOGW(...) ((void)0)
#else
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  DEFENDER_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  DEFENDER_TAG, __VA_ARGS__)
#endif

/* LOGE 始终保留(错误/安全事件必须可排查),但调用处须脱敏:
 * hash/CRC/偏移/路径等敏感值用 "***" 或只打前 8 字符。 */
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, DEFENDER_TAG, __VA_ARGS__)

#endif /* DEFENDER_LOG_H */
