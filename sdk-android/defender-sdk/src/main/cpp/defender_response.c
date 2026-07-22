/**
 * defender_response.c - 响应策略(kill / warn 限流)
 *
 * 详见 ADR 0088 §响应策略
 *
 * kill:
 *  - 随机延迟 [delay_min_ms, delay_max_ms](防逆向定位触发点)
 *  - method=sigabrt: raise(SIGABRT) + _exit(1)
 *  - method=exit:    _exit(1)
 *
 * warn:
 *  - 限流时间戳记录(线程安全,基于 violation_key)
 *  - 返回 1 = 应该上报(首次或已过 throttle_ms),0 = 限流中跳过
 *  - Toast + HTTP 上报由 Java 层 DefenderResponse 处理
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <android/log.h>

#define TAG "DefenderResponse"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ============= kill 响应 ============= */

/**
 * 随机延迟 [delay_min_ms, delay_max_ms] 后 kill
 *
 * 防逆向定位触发点:逆向工程师无法从 kill 时间反推检测代码位置
 *
 * @param delay_min_ms 最小延迟(毫秒)
 * @param delay_max_ms 最大延迟(毫秒)
 * @param method       "sigabrt" / "exit"(NULL 默认 sigabrt)
 */
void defender_kill(int delay_min_ms, int delay_max_ms, const char *method) {
    /* 参数合法化 */
    if (delay_min_ms < 0) delay_min_ms = 0;
    if (delay_max_ms < delay_min_ms) delay_max_ms = delay_min_ms;

    /* 随机延迟(use time + pid 做种子) */
    int delay_ms = delay_min_ms;
    if (delay_max_ms > delay_min_ms) {
        unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)getpid();
        delay_ms = delay_min_ms + (int)(rand_r(&seed) % (unsigned int)(delay_max_ms - delay_min_ms + 1));
    }

    LOGE("defender_kill: 延迟 %d ms 后触发(method=%s)", delay_ms, method ? method : "sigabrt");

    /* 延迟 */
    if (delay_ms > 0) {
        usleep((useconds_t)(delay_ms * 1000));
    }

    /* 触发 kill */
    if (method != NULL && strcmp(method, "exit") == 0) {
        LOGE("defender_kill: _exit(1)");
        _exit(1);
    } else {
        /* 默认 sigabrt:产生 tombstone(供后续分析)+ 非零退出 */
        LOGE("defender_kill: raise(SIGABRT)");
        raise(SIGABRT);
        _exit(1);  /* 兜底,raise 失败也强制退出 */
    }

    /* 不会到达 */
}

/* ============= warn 限流 ============= */

/* 限流表:violation_key -> 上次上报时间戳(秒)
 * 简化实现:固定 32 槽,线性查找
 * SDK 内置场景 key 数量有限(各模块名),32 足够 */
#define THROTTLE_TABLE_SIZE 32
#define THROTTLE_KEY_MAX_LEN 64

typedef struct {
    char    key[THROTTLE_KEY_MAX_LEN];
    time_t  last_report_ts;
} throttle_entry_t;

static throttle_entry_t throttle_table[THROTTLE_TABLE_SIZE];
static pthread_mutex_t  throttle_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * warn 限流检查
 *
 * @param violation_key 违规类型 key(如 "frida_detected", "root_detected")
 * @param throttle_ms   限流周期(毫秒)
 * @return 1 = 应该上报(首次或已过限流期),0 = 限流中跳过
 */
int defender_warn_throttle(const char *violation_key, int throttle_ms) {
    if (violation_key == NULL || violation_key[0] == '\0') {
        return 1;  /* 无 key,不限流 */
    }

    time_t now = time(NULL);
    time_t throttle_sec = (time_t)(throttle_ms / 1000);

    pthread_mutex_lock(&throttle_mutex);

    /* 查找已有 entry */
    int empty_slot = -1;
    for (int i = 0; i < THROTTLE_TABLE_SIZE; i++) {
        if (throttle_table[i].key[0] == '\0') {
            if (empty_slot < 0) empty_slot = i;
            continue;
        }
        if (strcmp(throttle_table[i].key, violation_key) == 0) {
            /* 找到,检查限流 */
            if (now - throttle_table[i].last_report_ts < throttle_sec) {
                /* 限流中,跳过 */
                pthread_mutex_unlock(&throttle_mutex);
                LOGW("warn 限流中(key=%s, 距上次 %lld s < %lld s)",
                     violation_key,
                     (long long)(now - throttle_table[i].last_report_ts),
                     (long long)throttle_sec);
                return 0;
            }
            /* 已过限流期,更新时间戳 */
            throttle_table[i].last_report_ts = now;
            pthread_mutex_unlock(&throttle_mutex);
            LOGI("warn 上报(key=%s, 限流通过)", violation_key);
            return 1;
        }
    }

    /* 未找到,新建 entry */
    if (empty_slot >= 0) {
        strncpy(throttle_table[empty_slot].key, violation_key, THROTTLE_KEY_MAX_LEN - 1);
        throttle_table[empty_slot].key[THROTTLE_KEY_MAX_LEN - 1] = '\0';
        throttle_table[empty_slot].last_report_ts = now;
        pthread_mutex_unlock(&throttle_mutex);
        LOGI("warn 首次上报(key=%s)", violation_key);
        return 1;
    }

    /* 表满,找最旧的 entry 覆盖(真 LRU,而非固定覆盖 entry 0) */
    int oldest = 0;
    time_t oldest_ts = throttle_table[0].last_report_ts;
    for (int i = 1; i < THROTTLE_TABLE_SIZE; i++) {
        if (throttle_table[i].last_report_ts < oldest_ts) {
            oldest_ts = throttle_table[i].last_report_ts;
            oldest = i;
        }
    }
    strncpy(throttle_table[oldest].key, violation_key, THROTTLE_KEY_MAX_LEN - 1);
    throttle_table[oldest].key[THROTTLE_KEY_MAX_LEN - 1] = '\0';
    throttle_table[oldest].last_report_ts = now;
    pthread_mutex_unlock(&throttle_mutex);
    LOGW("warn 限流表满,覆盖最旧 entry %d(key=%s)", oldest, violation_key);
    return 1;
}
