/**
 * trigger_scheduler.c - 多点触发调度(方案 A+B)
 *
 * 详见 xcj_blue_demo_v2.1.1_prompt.md §2.5
 *
 * 触发点:
 *  - .init_proc:SO 加载最早时机(早于 Java) -- 由 ELF .init 段自动调用
 *  - JNI_OnLoad:Native 层初始化 -- 在 defender_jni.c 中调用
 *  - Application.attachBaseContext:Java 层最早 -- 由 DefenderInitProvider 调用
 *  - 主 Activity.onCreate:UI 初始化 -- 由 DefenderInitProvider 调度
 *  - 独立守护线程:间隔 5-15 秒随机 -- 本文件实现
 *
 * 本文件实现守护线程(周期性校验 + 随机延迟,防逆向定位触发点)。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <android/log.h>

#define TAG "DefenderTriggerScheduler"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ============= 校验回调(由 validator_core.c 注册) ============= */

typedef int (*verify_callback_t)(void);
static verify_callback_t g_callback = NULL;
static int g_scheduler_running = 0;

/**
 * 注册校验回调(守护线程周期性调用)
 */
void trigger_scheduler_set_callback(verify_callback_t cb) {
    g_callback = cb;
}

/* ============= 守护线程 ============= */

/**
 * 守护线程:周期性校验(5-15 秒随机间隔)
 *
 * 随机间隔防逆向定位触发点:
 *  攻击者无法从 kill 时间反推检测代码位置。
 */
static void *guard_thread(void *arg) {
    (void)arg;
    LOGI("守护线程启动(5-15s 随机间隔)");

    /* 初始延迟 3-8 秒(避免与启动阶段冲突) */
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)getpid();
    sleep(3 + rand_r(&seed) % 6);

    while (g_scheduler_running) {
        if (g_callback) {
            int result = g_callback();
            if (result != 0) {
                LOGE("守护线程校验失败: result=%d", result);
                /* 由 validator_core 决定响应(kill/warn),此处只报告 */
            }
        }

        /* 5-15 秒随机间隔 */
        int delay = 5 + rand_r(&seed) % 11;
        LOGI("守护线程:下次校验 %d 秒后", delay);

        /* 分段 sleep(可被 g_scheduler_running 停止) */
        for (int i = 0; i < delay && g_scheduler_running; i++) {
            sleep(1);
        }
    }

    LOGW("守护线程退出");
    return NULL;
}

/* ============= 启动/停止调度器 ============= */

/**
 * 启动守护线程(由 DefenderInitProvider 调用)
 */
void trigger_scheduler_start(void) {
    if (g_scheduler_running) {
        LOGW("守护线程已运行");
        return;
    }
    g_scheduler_running = 1;

    pthread_t tid;
    if (pthread_create(&tid, NULL, guard_thread, NULL) == 0) {
        pthread_detach(tid);
        LOGI("守护线程已启动(后台常驻)");
    } else {
        LOGE("守护线程启动失败");
        g_scheduler_running = 0;
    }
}

/**
 * 停止守护线程(通常不调用,APP 退出时自动结束)
 */
void trigger_scheduler_stop(void) {
    g_scheduler_running = 0;
}
