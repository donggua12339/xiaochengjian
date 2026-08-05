/**
 * x4_gc_roots.c - GC 根巡检实现(ADR 0098 P0-D)
 *
 * 安全纪律:
 *   - 本模块运行于客户 APP 进程内,任何故障都必须优雅降级(返回 0),
 *     绝不允许 defensive SDK 自身成为崩溃源。
 *   - VisitRoots 全程 sigsetjmp 守护;visitor 内不做任何可能长时间持锁的操作。
 *   - 符号解析失败 / API 版本不符 / 映射解析失败 → 跳过,不误杀。
 */
#include "x4_gc_roots.h"

#include <dlfcn.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "x4_svc.h"

#ifdef __ANDROID__
    #include <android/api-level.h>
#endif

#define DEFENDER_TAG "X4-GcRoots"
#include "defender_log.h"

/* ============= 参数与上限 ============= */

#define GC_ROOTS_API_MIN 26 /* VisitRoots 稳定期起点(Android 8) */
#define GC_ROOTS_API_MAX 35
#define GC_ROOTS_MAX_VISITS 65536  /* visitor 访问上限,防异常表拖死 */
#define GC_ROOTS_COUNT_ALERT 20000 /* 全局根总数告警阈值(保守) */
#define GC_HEAP_RANGES_MAX 256
#define GC_KLASS_SET_SIZE 2048 /* 2 的幂,开放寻址 */

/* JavaVMExt::VisitRoots(art::RootVisitor*) 的 mangled 候选(跨版本收集) */
static const char *kVisitRootsSymbols[] = {
    "_ZN3art9JavaVMExt10VisitRootsEPNS_11RootVisitorE",
};

/* ============= 映射区解析(/proc/self/maps,svc 直读) ============= */

typedef struct {
    unsigned long start;
    unsigned long end;
} heap_range_t;

static heap_range_t g_heap_ranges[GC_HEAP_RANGES_MAX];
static int g_heap_range_count = 0;

/* 纯函数:host 单测可用。判定映射是否为 Java 堆/镜像区。
 * 规则:名字含 "dalvik"(anonymous: dalvik-* 各堆空间)或以 ".art" 结尾
 * (boot/app image)。JNI 全局根对象必然位于这些区域。 */
int x4_gc_roots_range_is_heap(unsigned long start, unsigned long end, const char *name)
{
    (void) start;
    if (end <= start)
        return 0;
    if (!name || name[0] == '\0')
        return 0;
    if (strstr(name, "dalvik") != NULL)
        return 1;
    size_t len = strlen(name);
    if (len >= 4 && strcmp(name + len - 4, ".art") == 0)
        return 1;
    return 0;
}

static void heap_range_add(unsigned long start, unsigned long end)
{
    if (g_heap_range_count >= GC_HEAP_RANGES_MAX)
        return;
    g_heap_ranges[g_heap_range_count].start = start;
    g_heap_ranges[g_heap_range_count].end = end;
    g_heap_range_count++;
}

/* maps 行解析:按 start 有序插入(maps 本身有序,追加即可) */
static int parse_heap_ranges(void)
{
    g_heap_range_count = 0;

    int fd = x4_svc_openat(-100, "/proc/self/maps", 0, 0);
    if (fd < 0)
        return -1;

    char buf[8192];
    char line[1024];
    int line_pos = 0;
    ssize_t n;
    while ((n = x4_svc_read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        for (int i = 0; i < n; i++) {
            if (buf[i] == '\n' || line_pos >= (int) sizeof(line) - 1) {
                line[line_pos] = '\0';
                unsigned long s, e;
                char perms[8] = {0};
                /* 格式: start-end perms offset dev inode  pathname */
                if (sscanf(line, "%lx-%lx %7s", &s, &e, perms) == 3) {
                    char *name = strrchr(line, ' ');
                    if (name != NULL) {
                        name++; /* 跳过空白定位 pathname(maps 尾列) */
                        while (*name == ' ')
                            name++;
                        if (x4_gc_roots_range_is_heap(s, e, name)) {
                            heap_range_add(s, e);
                        }
                    }
                }
                line_pos = 0;
            } else {
                line[line_pos++] = buf[i];
            }
        }
    }
    x4_svc_close(fd);
    return (g_heap_range_count > 0) ? 0 : -1;
}

/* 二分:地址是否落在任一堆/镜像区 */
static int addr_in_heap(unsigned long addr)
{
    int lo = 0, hi = g_heap_range_count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (addr < g_heap_ranges[mid].start) {
            hi = mid - 1;
        } else if (addr >= g_heap_ranges[mid].end) {
            lo = mid + 1;
        } else {
            return 1;
        }
    }
    return 0;
}

/* ============= klass 指纹集(开放寻址,供后续天衍增强用) ============= */

static uintptr_t g_klass_set[GC_KLASS_SET_SIZE];
static int g_klass_distinct = 0;

static void klass_set_reset(void)
{
    memset(g_klass_set, 0, sizeof(g_klass_set));
    g_klass_distinct = 0;
}

static void klass_set_insert(uintptr_t klass)
{
    if (klass == 0 || g_klass_distinct >= GC_KLASS_SET_SIZE / 2)
        return;
    uint32_t h = 2166136261u; /* FNV-1a over pointer bytes */
    const uint8_t *p = (const uint8_t *) &klass;
    for (size_t i = 0; i < sizeof(klass); i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    uint32_t idx = h & (GC_KLASS_SET_SIZE - 1);
    for (int probe = 0; probe < GC_KLASS_SET_SIZE; probe++) {
        uintptr_t slot = g_klass_set[idx];
        if (slot == klass)
            return;
        if (slot == 0) {
            g_klass_set[idx] = klass;
            g_klass_distinct++;
            return;
        }
        idx = (idx + 1) & (GC_KLASS_SET_SIZE - 1);
    }
}

/* ============= 伪 RootVisitor(Itanium ABI) =============
 *
 * art::RootVisitor 布局:C++ 抽象类,虚析构 + 纯虚 VisitRoots。
 * 对象首字 = vtable 指针;vtable 条目序:[0]完全析构 [1]删除析构 [2]VisitRoots。
 * 我们只被调用不被析构,析构槽放空操作。
 *
 * VisitRoots(mirror::Object*** root, const RootInfo& info):
 *   *root = 根对象指针。RootInfo 按引用传入,本实现忽略(不依赖其布局)。
 * 部分版本按 batch 调用(槽 3),参数序为 (root, num_roots, info);
 * 单根 handler 把 num_roots 误当 info 引用忽略即可,最多漏计不崩溃。 */

typedef struct {
    const void **vtable;
} fake_root_visitor_t;

typedef struct {
    uint32_t total;
    uint32_t offheap;
    int capped;
} gc_visit_stats_t;

static gc_visit_stats_t g_stats;

static void fake_visitor_dtor(fake_root_visitor_t *self)
{
    (void) self; /* 永不发生(ART 不持有所有权) */
}

static void fake_visitor_visit(fake_root_visitor_t *self, void ***root_slot, const void *root_info)
{
    (void) self;
    (void) root_info;
    if (g_stats.total >= GC_ROOTS_MAX_VISITS) {
        g_stats.capped = 1;
        return; /* 不再深入,等 ART 遍历自然结束(不可中途 longjmp,防留锁) */
    }
    g_stats.total++;
    if (root_slot == NULL)
        return;
    void *obj = *root_slot;
    if (obj == NULL)
        return;

    /* 物理事实 1:根对象必须位于 Java 堆/镜像映射区 */
    if (!addr_in_heap((unsigned long) (uintptr_t) obj)) {
        g_stats.offheap++;
    }

    /* klass 指纹(mirror::Object 首字 = klass_);对象存活期读取安全 */
    uintptr_t klass = *(uintptr_t *) obj;
    klass_set_insert(klass);
}

/* vtable:[0][1]=析构空操作,[2]=单根访问,[3]=预留 batch(同实现兼容) */
static const void *g_fake_vtable[4] = {
    (const void *) fake_visitor_dtor,
    (const void *) fake_visitor_dtor,
    (const void *) fake_visitor_visit,
    (const void *) fake_visitor_visit,
};

/* ============= 故障守护(复用 anti_frida 模式) ============= */

static sigjmp_buf g_gc_jmp;
static volatile sig_atomic_t g_gc_jmp_set = 0;

static void gc_fault_handler(int sig)
{
    if (g_gc_jmp_set) {
        g_gc_jmp_set = 0;
        siglongjmp(g_gc_jmp, 1);
    }
    signal(sig, SIG_DFL);
}

/* ============= 主入口 ============= */

int x4_gc_roots_scan(void *java_vm)
{
    if (java_vm == NULL)
        return 0;

#ifdef __ANDROID__
    int api = android_get_device_api_level();
    if (api < GC_ROOTS_API_MIN || api > GC_ROOTS_API_MAX) {
        return 0; /* 版本外 → 跳过 */
    }
#endif

    /* 1. 解析 VisitRoots 符号 */
    void *visit_roots_fn = NULL;
    void *libart = dlopen("libart.so", RTLD_NOW | RTLD_NOLOAD);
    if (libart == NULL)
        return 0;
    for (size_t i = 0; i < sizeof(kVisitRootsSymbols) / sizeof(kVisitRootsSymbols[0]); i++) {
        visit_roots_fn = dlsym(libart, kVisitRootsSymbols[i]);
        if (visit_roots_fn != NULL)
            break;
    }
    if (visit_roots_fn == NULL)
        return 0; /* 符号不可得 → 优雅降级 */

    /* 2. 解析堆映射区(分类用) */
    if (parse_heap_ranges() != 0)
        return 0;

    /* 3. 守护下调用 VisitRoots */
    g_stats.total = 0;
    g_stats.offheap = 0;
    g_stats.capped = 0;
    klass_set_reset();

    fake_root_visitor_t visitor;
    visitor.vtable = g_fake_vtable;

    struct sigaction sa, old_segv, old_bus;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = gc_fault_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS, &sa, &old_bus);

    int faulted = 0;
    if (sigsetjmp(g_gc_jmp, 1) == 0) {
        g_gc_jmp_set = 1;
        typedef void (*visit_roots_fn_t)(void *jvm, void *visitor);
        ((visit_roots_fn_t) visit_roots_fn)(java_vm, &visitor);
        g_gc_jmp_set = 0;
    } else {
        faulted = 1; /* ART 内部访问故障 → 本次结果作废 */
        g_gc_jmp_set = 0;
    }

    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS, &old_bus, NULL);

    if (faulted) {
        LOGW("[X4] gc-root scan faulted, degraded");
        return 0;
    }

    /* 4. 计分(保守:两条独立物理事实,各 +1) */
    int suspicious = 0;
    if (g_stats.offheap > 0) {
        suspicious++;
        LOGW("[X4] gc-root: %u roots outside heap regions", g_stats.offheap);
    }
    if (g_stats.total > GC_ROOTS_COUNT_ALERT) {
        suspicious++;
        LOGW("[X4] gc-root: total=%u exceeds alert threshold", g_stats.total);
    }
    LOGI("[X4] gc-root scan done: total=%u offheap=%u distinct_klass=%d suspicious=%d",
         g_stats.total, g_stats.offheap, g_klass_distinct, suspicious);
    return suspicious;
}
