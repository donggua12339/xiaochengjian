/**
 * anti_dump.c - 防内存 Dump(inotify 事件驱动)
 *
 * 详见 ADR 0088 §AntiDump
 *
 * 原理:
 *  任何 dump 工具(Frida/frida-dexdump/GameGuardian)要读进程内存,
 *  必然需要打开 /proc/self/mem。
 *  inotify 监控 /proc/self/mem 的 IN_ACCESS 事件,一旦触发 = 有人在读内存。
 *
 * 方案 B:只监控 /proc/self/mem(本进程正常不读自己的 mem)
 * 事件驱动,零 CPU 开销(无事件时阻塞在 read 上)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/inotify.h>
#include <android/log.h>

#define TAG "DefenderAntiDump"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ============= inotify 监控线程 ============= */

/**
 * 后台线程:用 inotify 监控 /proc/self/mem
 *
 * 检测到 IN_ACCESS -> 外部 dump 工具在读内存 -> raise(SIGABRT)
 *
 * 注:inotify 无法区分本进程还是外部进程访问,但本进程正常不读自己的 /proc/self/mem,
 *     所以任何 IN_ACCESS 都是可疑的。
 */
static void *anti_dump_monitor_thread(void *arg) {
    (void)arg;
    LOGI("AntiDump 监控线程启动");

    int fd = inotify_init();
    if (fd < 0) {
        LOGW("inotify_init 失败,AntiDump 未启用");
        return NULL;
    }

    /* 监控 /proc/self/mem(进程内存内容) */
    int wd = inotify_add_watch(fd, "/proc/self/mem", IN_ACCESS | IN_OPEN);
    if (wd < 0) {
        LOGW("inotify_add_watch /proc/self/mem 失败,AntiDump 未启用");
        close(fd);
        return NULL;
    }

    LOGI("AntiDump 监控已启动(监控 /proc/self/mem)");

    /* 循环等待事件(阻塞,零 CPU 开销) */
    char buf[4096];
    while (1) {
        ssize_t len = read(fd, buf, sizeof(buf));
        if (len <= 0) break;

        /* 有事件 = 有人在读 /proc/self/mem = dump 攻击 */
        struct inotify_event *event;
        for (char *ptr = buf; ptr < buf + len; ptr += sizeof(*event) + event->len) {
            event = (struct inotify_event *)ptr;

            if (event->mask & (IN_ACCESS | IN_OPEN)) {
                LOGE("检测到内存 dump 攻击!/proc/self/mem 被访问");
                LOGE("触发 SIGABRT");

                /* 检测到 dump,kill */
                raise(SIGABRT);
                _exit(1);
            }
        }
    }

    close(fd);
    LOGW("AntiDump 监控线程退出");
    return NULL;
}

/* ============= 启动监控 ============= */

/**
 * 启动 AntiDump 监控线程
 *
 * 在 DefenderInitProvider 中调用(启动时 1 次)
 * 后台常驻,事件驱动,零 CPU 开销
 */
void anti_dump_start_monitor(void) {
    pthread_t tid;
    if (pthread_create(&tid, NULL, anti_dump_monitor_thread, NULL) == 0) {
        pthread_detach(tid);
        LOGI("AntiDump 监控线程已启动(后台常驻)");
    } else {
        LOGW("AntiDump 监控线程启动失败");
    }
}
