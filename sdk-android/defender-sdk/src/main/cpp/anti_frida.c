/**
 * anti_frida.c - 防 Frida 检测(Native 层)
 *
 * 详见 ADR 0088 §AntiFrida
 *
 * 检测方式:
 *  - A:扫 /proc/self/maps 找 frida/gum-js-loop/frida-agent/gadget
 *  - B:检测端口 27042(Frida 默认监听)
 *  - C:扫线程名找 gum-js-loop/gmain
 *  - D:内存特征字符串扫描(后台异步,搜 LIBFRIDA/frida:rpc)
 *  - E:inline syscall
 *
 * 检测频率:
 *  - A+B+C:启动时 1 次 + 关键节点(同步,快)
 *  - D:后台线程异步(启动后 3-10s 随机,扫 1 次)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <android/log.h>

#define TAG "DefenderAntiFrida"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ============= inline syscall 封装 ============= */

#if defined(__aarch64__)
static int af_openat(const char *path, int flags) {
    int fd;
    __asm__ volatile(
        "mov x8, #56\n"
        "mov x0, #-100\n"
        "mov x1, %1\n"
        "mov x2, %2\n"
        "svc #0\n"
        "mov %0, x0\n"
        : "=r"(fd)
        : "r"(path), "r"(flags)
        : "x0", "x1", "x2", "x8", "memory"
    );
    return fd;
}

static ssize_t af_read(int fd, void *buf, size_t count) {
    ssize_t ret;
    __asm__ volatile(
        "mov x8, #63\n"
        "mov x0, %1\n"
        "mov x1, %2\n"
        "mov x2, %3\n"
        "svc #0\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(fd), "r"(buf), "r"(count)
        : "x0", "x1", "x2", "x8", "memory"
    );
    return ret;
}

static int af_close(int fd) {
    int ret;
    __asm__ volatile(
        "mov x8, #57\n"
        "mov x0, %1\n"
        "svc #0\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(fd)
        : "x0", "x8", "memory"
    );
    return ret;
}

#elif defined(__arm__)
/* armeabi-v7a:R7 被保留为帧指针,用 syscall() 替代 inline asm */
#include <sys/syscall.h>
static int af_openat(const char *path, int flags) {
    return (int)syscall(__NR_openat, AT_FDCWD, path, flags, 0);
}
static ssize_t af_read(int fd, void *buf, size_t count) {
    return syscall(__NR_read, fd, buf, count);
}
static int af_close(int fd) {
    return (int)syscall(__NR_close, fd);
}

#else
static int af_openat(const char *path, int flags) { return open(path, flags); }
static ssize_t af_read(int fd, void *buf, size_t count) { return read(fd, buf, count); }
static int af_close(int fd) { return close(fd); }
#endif

/* ============= A:扫 /proc/self/maps ============= */

/**
 * 扫 /proc/self/maps,找 Frida 特征
 *
 * 关键词:frida, gum-js-loop, frida-agent, gadget
 *
 * @return 0=未检测到 / 1=检测到 Frida
 */
static int check_maps_frida(void) {
    int fd = af_openat("/proc/self/maps", 0);
    if (fd < 0) {
        LOGE("open /proc/self/maps 失败");
        return 0;  /* 读取失败不算检测到 */
    }

    char buf[8192];
    const char *keywords[] = { "frida", "gum-js-loop", "frida-agent", "gadget" };
    int detected = 0;

    ssize_t n;
    while ((n = af_read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        for (int i = 0; i < 4; i++) {
            if (strstr(buf, keywords[i]) != NULL) {
                LOGE("maps 检测到 Frida 特征: %s", keywords[i]);
                detected = 1;
                break;
            }
        }
        if (detected) break;
    }

    af_close(fd);
    return detected;
}

/* ============= B:检测端口 27042 ============= */

/**
 * 检测端口 27042(Frida 默认监听)
 *
 * @return 0=未检测到 / 1=检测到 Frida
 */
static int check_frida_port(void) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return 0;
    }

    /* 设置超时(100ms) */
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(27042);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    close(sock);

    if (ret == 0) {
        LOGE("端口 27042 可连接(Frida 在监听)");
        return 1;
    }

    return 0;
}

/* ============= C:扫线程名 ============= */

/**
 * 扫 /proc/self/task/ 下各线程的 comm 文件,找 gum-js-loop / gmain
 *
 * @return 0=未检测到 / 1=检测到 Frida
 */
static int check_thread_names(void) {
    DIR *d = opendir("/proc/self/task");
    if (!d) {
        LOGW("open /proc/self/task 失败");
        return 0;
    }

    int detected = 0;
    struct dirent *ent;
    char comm_path[256];
    char comm[256];

    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        snprintf(comm_path, sizeof(comm_path), "/proc/self/task/%s/comm", ent->d_name);

        int fd = af_openat(comm_path, 0);
        if (fd < 0) continue;

        ssize_t n = af_read(fd, comm, sizeof(comm) - 1);
        af_close(fd);

        if (n <= 0) continue;
        comm[n] = '\0';

        /* 去掉换行 */
        char *nl = strchr(comm, '\n');
        if (nl) *nl = '\0';

        if (strstr(comm, "gum-js-loop") != NULL ||
            strstr(comm, "gmain") != NULL) {
            LOGE("线程名检测到 Frida: %s (tid=%s)", comm, ent->d_name);
            detected = 1;
            break;
        }
    }

    closedir(d);
    return detected;
}

/* ============= D:内存特征字符串扫描(后台异步) ============= */

/**
 * 后台线程:扫描内存中的 Frida 特征字符串
 *
 * 扫描 /proc/self/maps 的 r-xp 段(可执行段),搜:
 *  - "LIBFRIDA"(Frida 内部标识)
 *  - "frida:rpc"(Frida RPC 协议)
 *
 * 启动后延迟 3-10 秒(随机),只扫 1 次
 */
static void *frida_memory_scan_thread(void *arg) {
    (void)arg;

    /* 随机延迟 3-10 秒 */
    srand((unsigned int)time(NULL));  /* NOLINT */
    int delay = 3 + rand() % 8;
    sleep(delay);

    LOGI("开始内存特征字符串扫描(延迟 %ds)", delay);

    /* 读 /proc/self/maps,找 r-xp 段 */
    int fd = af_openat("/proc/self/maps", 0);
    if (fd < 0) {
        LOGW("内存扫描:open maps 失败");
        return NULL;
    }

    char line[512];
    int line_pos = 0;
    char buf[8192];

    ssize_t n;
    while ((n = af_read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        for (int i = 0; i < n; i++) {
            if (buf[i] == '\n' || line_pos >= (int)sizeof(line) - 1) {
                line[line_pos] = '\0';

                /* 找 r-xp 段(可执行) */
                if (strstr(line, " r-xp ") != NULL) {
                    unsigned long start, end;
                    if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                        /* 在 [start, end] 范围搜 "LIBFRIDA" / "frida:rpc" */
                        void *p = (void *)start;
                        size_t len = end - start;

                        /* 用 memmem 搜索(如果可用)或手动搜 */
                        for (size_t off = 0; off + 8 < len; off++) {
                            if (memcmp((char *)p + off, "LIBFRIDA", 8) == 0) {
                                LOGE("内存扫描检测到 Frida 特征: LIBFRIDA");
                                af_close(fd);
                                /* 触发 kill(由 defender_kill 处理) */
                                raise(SIGABRT);
                                _exit(1);
                            }
                            if (off + 9 < len &&
                                memcmp((char *)p + off, "frida:rpc", 9) == 0) {
                                LOGE("内存扫描检测到 Frida 特征: frida:rpc");
                                af_close(fd);
                                raise(SIGABRT);
                                _exit(1);
                            }
                        }
                    }
                }

                line_pos = 0;
            } else {
                line[line_pos++] = buf[i];
            }
        }
    }

    af_close(fd);
    LOGI("内存特征字符串扫描完成(未检测到 Frida)");
    return NULL;
}

/**
 * 启动后台内存扫描线程
 */
void anti_frida_start_memory_scan(void) {
    pthread_t tid;
    if (pthread_create(&tid, NULL, frida_memory_scan_thread, NULL) == 0) {
        pthread_detach(tid);
        LOGI("内存扫描线程已启动(后台异步)");
    } else {
        LOGW("内存扫描线程启动失败");
    }
}

/* ============= 组合检测(同步:A+B+C) ============= */

/**
 * AntiFrida 检测(同步:A+B+C,不含 D 后台扫描)
 *
 * @return 0=未检测到 / 1=检测到 Frida
 */
int anti_frida_check(void) {
    LOGI("=== AntiFrida 检测(A+B+C) ===");

    /* A:maps 扫描 */
    if (check_maps_frida()) {
        LOGE("A 层检测到 Frida(maps)");
        return 1;
    }

    /* B:端口 27042 */
    if (check_frida_port()) {
        LOGE("B 层检测到 Frida(端口 27042)");
        return 1;
    }

    /* C:线程名 */
    if (check_thread_names()) {
        LOGE("C 层检测到 Frida(线程名)");
        return 1;
    }

    LOGI("AntiFrida 检测通过(未检测到 Frida)");
    return 0;
}
