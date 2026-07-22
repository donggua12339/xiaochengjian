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
#include <setjmp.h>
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
static int af_access(const char *path, int mode) {
    int ret;
    __asm__ volatile(
        "mov x8, #48\n"      /* __NR_faccessat */
        "mov x0, #-100\n"    /* AT_FDCWD */
        "mov x1, %1\n"
        "mov x2, %2\n"
        "svc #0\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(path), "r"(mode)
        : "x0", "x1", "x2", "x8", "memory"
    );
    return ret;
}

#elif defined(__arm__)
/* M1 说明:armeabi-v7a 的 inline syscall 需要 R7 存 syscall 号,但 R7 被 ABI 保留为
 * 帧指针,直接用 inline asm 会破坏栈帧。此处用 libc syscall() 替代(可被 hook)。
 * 权衡:armeabi-v7a 设备占比已很低,核心检测在 arm64-v8a(inline asm 不可 hook)。 */
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
static int af_access(const char *path, int mode) {
    return (int)syscall(__NR_faccessat, AT_FDCWD, path, mode, 0);
}

#else
static int af_openat(const char *path, int flags) { return open(path, flags); }
static ssize_t af_read(int fd, void *buf, size_t count) { return read(fd, buf, count); }
static int af_close(int fd) { return close(fd); }
static int af_access(const char *path, int mode) { return access(path, mode); }
#endif

/* ============= M7 修复:XOR 字符串混淆 ============= */

/*
 * 检测关键词用 XOR 0x5A 编码存储,运行时解码。
 * 静态分析(strings/IDA)看到的是编码字节,无法直接定位检测逻辑。
 * 编码值由 scripts/obf_encode.py 生成(key=0x5A)。
 */
#define OBF_KEY 0x5A

static void obf_decode(char *dst, const unsigned char *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dst[i] = (char)(src[i] ^ OBF_KEY);
    }
    dst[len] = '\0';
}

/**
 * 即时 XOR 比较:逐字节解码 obf[i] 与 mem[i] 比较,关键词永不以明文存入内存。
 * 避免解码到栈/堆后被自己的内存扫描检测到(自检测误报)。
 *
 * @return 0=匹配 / 非0=不匹配
 */
static int obf_memcmp(const void *mem, const unsigned char *obf, size_t len) {
    const unsigned char *m = (const unsigned char *)mem;
    for (size_t i = 0; i < len; i++) {
        if (m[i] != (unsigned char)(obf[i] ^ OBF_KEY)) return 1;
    }
    return 0;
}

/* "frida" */
static const unsigned char OBF_FRIDA[] = {0x3c, 0x28, 0x33, 0x3e, 0x3b};
/* "gum-js-loop" */
static const unsigned char OBF_GUM_JS_LOOP[] = {0x3d, 0x2f, 0x37, 0x77, 0x30, 0x29, 0x77, 0x36, 0x35, 0x35, 0x2a};
/* "frida-agent" */
static const unsigned char OBF_FRIDA_AGENT[] = {0x3c, 0x28, 0x33, 0x3e, 0x3b, 0x77, 0x3b, 0x3d, 0x3f, 0x34, 0x2e};
/* "gadget" */
static const unsigned char OBF_GADGET[] = {0x3d, 0x3b, 0x3e, 0x3d, 0x3f, 0x2e};
/* "gmain"(线程名) */
static const unsigned char OBF_GMAIN[] = {0x3d, 0x37, 0x28, 0x33, 0x34};
/* "LIBFRIDA"(内存特征) */
static const unsigned char OBF_LIBFRIDA[] = {0x16, 0x13, 0x18, 0x1c, 0x08, 0x13, 0x1e, 0x1b};
/* "frida:rpc"(内存特征) */
static const unsigned char OBF_FRIDA_RPC[] = {0x3c, 0x28, 0x33, 0x3e, 0x3b, 0x60, 0x28, 0x2a, 0x39};

/* ============= A:扫 /proc/self/maps ============= */

/**
 * 扫 /proc/self/maps,找 Frida 特征
 *
 * 关键词:frida, gum-js-loop, frida-agent, gadget(M7:XOR 混淆存储)
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
    /* M7:运行时解码关键词(栈缓冲区,静态分析不可见) */
    char kw_frida[6], kw_gum[12], kw_agent[12], kw_gadget[7];
    obf_decode(kw_frida, OBF_FRIDA, 5);
    obf_decode(kw_gum, OBF_GUM_JS_LOOP, 11);
    obf_decode(kw_agent, OBF_FRIDA_AGENT, 11);
    obf_decode(kw_gadget, OBF_GADGET, 6);
    const char *keywords[] = { kw_frida, kw_gum, kw_agent, kw_gadget };
    int detected = 0;

    /* L1 修复:跨 buffer 边界检测。最长关键词 "frida-agent"/"gum-js-loop" 为 11 字节,
     * 保留上一块尾部 16 字节,与当前块开头拼接后检测,防止关键词被 buffer 边界切断漏检 */
    char tail[16];
    int tail_len = 0;

    ssize_t n;
    while ((n = af_read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';

        /* 拼接上一块尾部 + 当前块开头,检测跨边界关键词 */
        if (tail_len > 0) {
            char overlap[48];
            int head_len = n < 16 ? (int)n : 16;
            memcpy(overlap, tail, tail_len);
            memcpy(overlap + tail_len, buf, head_len);
            overlap[tail_len + head_len] = '\0';
            for (int i = 0; i < 4; i++) {
                if (strstr(overlap, keywords[i]) != NULL) {
                    LOGE("maps 检测到 Frida 特征(跨边界): %s", keywords[i]);
                    detected = 1;
                    break;
                }
            }
        }

        /* 检测当前块内部 */
        if (!detected) {
            for (int i = 0; i < 4; i++) {
                if (strstr(buf, keywords[i]) != NULL) {
                    LOGE("maps 检测到 Frida 特征: %s", keywords[i]);
                    detected = 1;
                    break;
                }
            }
        }
        if (detected) break;

        /* 保存当前块尾部供下次拼接 */
        tail_len = n < 16 ? (int)n : 16;
        memcpy(tail, buf + n - tail_len, tail_len);
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
    /* Frida 默认端口 + 常见备选端口(防止 -l 0.0.0.0:27043 改端口绕过) */
    const int frida_ports[] = {27042, 27043, 27044, 27045};

    for (int i = 0; i < 4; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        /* 设置超时(100ms) */
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(frida_ports[i]);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        int ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        close(sock);

        if (ret == 0) {
            LOGE("端口 %d 可连接(Frida 在监听)", frida_ports[i]);
            return 1;
        }
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

    /* M7:运行时解码线程名关键词 */
    char kw_gum[12], kw_gmain[6];
    obf_decode(kw_gum, OBF_GUM_JS_LOOP, 11);
    obf_decode(kw_gmain, OBF_GMAIN, 5);

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

        if (strstr(comm, kw_gum) != NULL ||
            strstr(comm, kw_gmain) != NULL) {
            LOGE("线程名检测到 Frida: %s (tid=%s)", comm, ent->d_name);
            detected = 1;
            break;
        }
    }

    closedir(d);
    return detected;
}

/* ============= D:内存特征字符串扫描(后台异步) ============= */

/* M2 修复:内存扫描内存故障保护。
 * 扫描数据段时,段可能在扫描中被 unmap/改保护,直接读会 SIGSEGV 或 SIGBUS
 * (实测真机 rw-p 段触发 SIGBUS BUS_ADRERR)。
 * 用 sigsetjmp/siglongjmp 在 SIGSEGV/SIGBUS 时跳过该段,而非崩溃。 */
static sigjmp_buf scan_jmp;
static volatile sig_atomic_t scan_jmp_set = 0;

static void scan_fault_handler(int sig) {
    if (scan_jmp_set) {
        scan_jmp_set = 0;
        siglongjmp(scan_jmp, 1);
    }
    /* 未设置 jmp(非扫描期间),恢复默认处理 */
    signal(sig, SIG_DFL);
}

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

    /* M2 修复:设置 SIGSEGV + SIGBUS handler,扫描不可读段时跳过而非崩溃 */
    struct sigaction sa, old_sa_segv, old_sa_bus;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = scan_fault_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, &old_sa_segv);
    sigaction(SIGBUS, &sa, &old_sa_bus);

    /* 关键词用 obf_memcmp 即时 XOR 比较,不解码到内存(避免自检测误报) */
    char line[512];
    int line_pos = 0;
    char buf[8192];

    ssize_t n;
    while ((n = af_read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        for (int i = 0; i < n; i++) {
            if (buf[i] == '\n' || line_pos >= (int)sizeof(line) - 1) {
                line[line_pos] = '\0';

                /* 找数据段(可读非可执行:r--p / rw-p)。
                 * 不搜代码段(r-xp):机器码偶然匹配字节序列会误报。
                 * 排除 [stack]:kw_rpc/kw_libfrida 解码在栈上,扫到会自检测误报。
                 * Frida 字符串特征(LIBFRIDA/frida:rpc)在 .so 数据段。 */
                unsigned long start, end;
                char perms[8];
                if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) == 3 &&
                    perms[0] == 'r' && perms[2] != 'x' &&
                    strstr(line, "[stack]") == NULL) {
                    {
                        /* 在 [start, end] 范围搜 "LIBFRIDA" / "frida:rpc" */
                        void *p = (void *)start;
                        size_t len = end - start;

                        /* M2 修复:sigsetjmp 保护,段被 unmap/改保护时 SIGSEGV 跳过该段 */
                        if (sigsetjmp(scan_jmp, 1) == 0) {
                            scan_jmp_set = 1;
                            for (size_t off = 0; off + 8 < len; off++) {
                                if (obf_memcmp((char *)p + off, OBF_LIBFRIDA, 8) == 0) {
                                    LOGE("内存扫描检测到 Frida 特征: LIBFRIDA");
                                    scan_jmp_set = 0;
                                    af_close(fd);
                                    sigaction(SIGSEGV, &old_sa_segv, NULL);
                                    sigaction(SIGBUS, &old_sa_bus, NULL);
                                    raise(SIGABRT);
                                    _exit(1);
                                }
                                if (off + 9 < len &&
                                    obf_memcmp((char *)p + off, OBF_FRIDA_RPC, 9) == 0) {
                                    LOGE("内存扫描检测到 Frida 特征: frida:rpc");
                                    scan_jmp_set = 0;
                                    af_close(fd);
                                    sigaction(SIGSEGV, &old_sa_segv, NULL);
                                    sigaction(SIGBUS, &old_sa_bus, NULL);
                                    raise(SIGABRT);
                                    _exit(1);
                                }
                            }
                            scan_jmp_set = 0;
                        } else {
                            /* SIGSEGV 发生,该段不可读,跳过 */
                            LOGW("内存扫描:段 [0x%lx-0x%lx] 不可读,跳过", start, end);
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
    /* 恢复原 SIGSEGV + SIGBUS handler */
    scan_jmp_set = 0;
    sigaction(SIGSEGV, &old_sa_segv, NULL);
    sigaction(SIGBUS, &old_sa_bus, NULL);
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

/* ============= E:文件路径检测 ============= */

/**
 * 检测 Frida 默认文件路径
 *
 * Frida server 通常推送到 /data/local/tmp/,检查常见路径。
 * 用 inline syscall 的 faccessat(避免 libc hook)。
 *
 * @return 0=未检测到 / 1=检测到 Frida 文件
 */
static int check_frida_files(void) {
    const char *paths[] = {
        "/data/local/tmp/frida-server",
        "/data/local/tmp/re.frida.server",
        "/data/local/tmp/frida-server-64",
        "/data/local/tmp/frida-server-32",
        "/data/local/tmp/frida-gadget.so",
        "/data/local/tmp/re.frida.server.so",
    };
    for (int i = 0; i < 6; i++) {
        if (af_access(paths[i], 0) == 0) {  /* F_OK=0 */
            LOGE("文件路径检测到 Frida: %s", paths[i]);
            return 1;
        }
    }
    return 0;
}

/* ============= 组合检测(同步:A+B+C+E) ============= */

/**
 * AntiFrida 检测(同步:A maps + B 端口 + C 线程名 + E 文件路径,不含 D 后台扫描)
 *
 * @return 0=未检测到 / 1=检测到 Frida
 */
int anti_frida_check(void) {
    LOGI("=== AntiFrida 检测(A+B+C+E) ===");

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

    /* E:文件路径 */
    if (check_frida_files()) {
        LOGE("E 层检测到 Frida(文件路径)");
        return 1;
    }

    LOGI("AntiFrida 检测通过(未检测到 Frida)");
    return 0;
}
