/**
 * x4_daemon.c - 多回调守护线程实现(X4-0)
 *
 * 单守护线程,随机间隔轮询所有已注册检测回调。调度用 libc nanosleep/rand_r
 * (调度本身非安全检测点;真正的检测回调内部应使用 x4_svc 直发系统调用)。
 */
#include "x4_daemon.h"
#include <pthread.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct { x4_check_fn fn; void *ctx; } x4_slot;

static x4_slot g_checks[X4_DAEMON_MAX_CHECKS];
static int g_count = 0;
static pthread_t g_thread;
static volatile int g_running = 0;
static int g_min_sec = 5, g_max_sec = 15;

int x4_daemon_register(x4_check_fn fn, void *ctx) {
    if (!fn || g_count >= X4_DAEMON_MAX_CHECKS) return -1;
    g_checks[g_count].fn = fn;
    g_checks[g_count].ctx = ctx;
    g_count++;
    return 0;
}

void x4_daemon_set_interval(int min_sec, int max_sec) {
    if (min_sec > 0 && max_sec >= min_sec) {
        g_min_sec = min_sec;
        g_max_sec = max_sec;
    }
}

static void *daemon_loop(void *arg) {
    (void)arg;
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)&g_running;
    while (g_running) {
        int span = g_max_sec - g_min_sec + 1;
        int delay = g_min_sec + (int)(rand_r(&seed) % (unsigned int)span);
        struct timespec ts;
        ts.tv_sec = delay;
        ts.tv_nsec = 0;
        nanosleep(&ts, NULL);
        if (!g_running) break;
        for (int i = 0; i < g_count; i++) {
            if (g_checks[i].fn) {
                (void)g_checks[i].fn(g_checks[i].ctx);   /* 异常由回调自行渐进处置 */
            }
        }
    }
    return NULL;
}

int x4_daemon_start(void) {
    if (g_running) return 0;
    g_running = 1;
    if (pthread_create(&g_thread, NULL, daemon_loop, NULL) != 0) {
        g_running = 0;
        return -1;
    }
    pthread_detach(g_thread);
    return 0;
}

void x4_daemon_stop(void) {
    g_running = 0;
}
