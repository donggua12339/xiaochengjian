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
#include <unistd.h> /* lseek(随机读自身映射文件) */

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

/* ============= maps + ELF 符号解析(绕开链接器命名空间) =============
 *
 * dlopen("libart.so") 在 app 链接器命名空间不可见(apex 库不对 app 暴露),
 * RTLD_NOLOAD 返回 NULL(2026-08-06 真机实证)。正确姿势:
 *   1. /proc/self/maps 找 libart.so 首个映射(文件头基址)与路径;
 *   2. open 该文件直接解析 ELF:PT_DYNAMIC 取 DT_SYMTAB/DT_STRTAB/DT_GNU_HASH;
 *   3. GNU hash 链求符号数,遍历 .dynsym 按名匹配;
 *   4. 运行时地址 = load_bias + st_value(load_bias = 头映射基址 - 首 PT_LOAD p_vaddr)。
 * 全程只读文件,失败即 NULL(优雅降级)。 */

typedef struct {
    unsigned long base; /* libart 头映射基址 */
    char path[512];
} art_map_info_t;

static int find_libart_map(art_map_info_t *out)
{
    int fd = x4_svc_openat(-100, "/proc/self/maps", 0, 0);
    if (fd < 0)
        return -1;
    out->base = 0;
    out->path[0] = '\0';
    char buf[8192];
    char line[1024];
    int line_pos = 0;
    ssize_t n;
    while ((n = x4_svc_read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        for (int i = 0; i < n; i++) {
            if (buf[i] == '\n' || line_pos >= (int) sizeof(line) - 1) {
                line[line_pos] = '\0';
                if (strstr(line, "/libart.so") != NULL && out->path[0] == '\0') {
                    unsigned long s = 0;
                    int k = 0; /* 行首 hex start */
                    while ((line[k] >= '0' && line[k] <= '9') ||
                           (line[k] >= 'a' && line[k] <= 'f')) {
                        int c = line[k] <= '9' ? line[k] - '0' : line[k] - 'a' + 10;
                        s = s * 16 + (unsigned long) c;
                        k++;
                    }
                    /* 路径=最后一个空白后的部分(maps 尾列) */
                    size_t ll = strlen(line);
                    while (ll > 0 && line[ll - 1] == '\n')
                        line[--ll] = '\0';
                    char *sp = strrchr(line, ' ');
                    const char *path_start = (sp != NULL) ? sp + 1 : line;
                    size_t len = strlen(path_start);
                    if (len > 0 && len < sizeof(out->path)) {
                        memcpy(out->path, path_start, len + 1);
                    }
                    out->base = s; /* maps 升序,首个 libart 映射=ELF 头 */
                }
                line_pos = 0;
            } else {
                line[line_pos++] = buf[i];
            }
        }
    }
    x4_svc_close(fd);
    return (out->path[0] != '\0') ? 0 : -1;
}

/* PT_LOAD 段表(从文件一次读入缓存;程序头在文件里,绝不可从 64B 头缓冲读——
 * 2026-08-06 真机实证:从头缓冲越界读 phdr 恒 -1) */
typedef struct {
    unsigned long p_offset, p_vaddr, p_filesz;
} gc_load_seg_t;
#define GC_LOAD_SEGS_MAX 8

/* vaddr → 文件偏移(查段表) */
static long segs_v2f(const gc_load_seg_t *segs, int n, unsigned long vaddr)
{
    for (int i = 0; i < n; i++) {
        if (vaddr >= segs[i].p_vaddr && vaddr < segs[i].p_vaddr + segs[i].p_filesz)
            return (long) (segs[i].p_offset + (vaddr - segs[i].p_vaddr));
    }
    return -1;
}

/* 读文件一块到 buf;返回实际字节 */
static size_t read_at(int fd, long off, uint8_t *buf, size_t want)
{
    /* x4_svc_read 无 pread:用 lseek?svc 未提供;直接 open+read 顺序不适用随机读。
     * 退化:svc 无 lseek 时,用 libc lseek(读自己进程文件,无 hook 风险面)。 */
    if (lseek(fd, (off_t) off, SEEK_SET) < 0)
        return 0;
    ssize_t n = x4_svc_read(fd, buf, want);
    return (n > 0) ? (size_t) n : 0;
}

static void *resolve_art_symbol(const char *want)
{
    art_map_info_t mi;
    if (find_libart_map(&mi) != 0) {
        return NULL;
    }

    int fd = x4_svc_openat(-100, mi.path, 0, 0);
    if (fd < 0) {
        return NULL;
    }

    uint8_t eh[64];
    if (read_at(fd, 0, eh, 64) < 52 || eh[0] != 0x7F || eh[1] != 'E' || eh[2] != 'L' ||
        eh[3] != 'F') {
        x4_svc_close(fd);
        return NULL;
    }
    int is64 = (eh[4] == 2);

    /* PT_DYNAMIC 位置 + 首 PT_LOAD p_vaddr(load_bias 用) */
    long dyn_off = -1;
    uint64_t dyn_size = 0;
    unsigned long first_load_vaddr = 0;
    gc_load_seg_t segs[GC_LOAD_SEGS_MAX];
    int nloads = 0;
    {
        int phnum;
        uint64_t phoff;
        if (is64) {
            memcpy(&phoff, eh + 0x20, 8);
            memcpy(&phnum, eh + 0x38, 2);
        } else {
            uint32_t t;
            memcpy(&t, eh + 0x1C, 4);
            phoff = t;
            uint16_t h;
            memcpy(&h, eh + 0x2C, 2);
            phnum = h;
        }
        uint8_t ph[64];
        for (int i = 0; i < phnum; i++) {
            size_t entsz = is64 ? 56 : 32;
            if (read_at(fd, (long) (phoff + (uint64_t) i * entsz), ph, entsz) < entsz)
                break;
            uint32_t ptype;
            memcpy(&ptype, ph, 4);
            if (ptype == 2) { /* PT_DYNAMIC */
                if (is64) {
                    uint64_t o, s;
                    memcpy(&o, ph + 8, 8);
                    memcpy(&s, ph + 40, 8);
                    dyn_off = (long) o;
                    dyn_size = s;
                } else {
                    uint32_t o, s;
                    memcpy(&o, ph + 4, 4);
                    memcpy(&s, ph + 16, 4);
                    dyn_off = (long) o;
                    dyn_size = s;
                }
            } else if (ptype == 1) { /* PT_LOAD → 记段表 */
                unsigned long off, va, fsz;
                if (is64) {
                    uint64_t a, b, c;
                    memcpy(&a, ph + 8, 8);
                    memcpy(&b, ph + 16, 8);
                    memcpy(&c, ph + 32, 8);
                    off = (unsigned long) a;
                    va = (unsigned long) b;
                    fsz = (unsigned long) c;
                } else {
                    uint32_t a, b, c;
                    memcpy(&a, ph + 4, 4);
                    memcpy(&b, ph + 8, 4);
                    memcpy(&c, ph + 16, 4);
                    off = a;
                    va = b;
                    fsz = c;
                }
                if (first_load_vaddr == 0)
                    first_load_vaddr = va;
                if (nloads < GC_LOAD_SEGS_MAX) {
                    segs[nloads].p_offset = off;
                    segs[nloads].p_vaddr = va;
                    segs[nloads].p_filesz = fsz;
                    nloads++;
                }
            }
        }
    }
    if (dyn_off < 0) {
        x4_svc_close(fd);
        return NULL;
    }
    unsigned long load_bias = mi.base - first_load_vaddr;

    /* 解析 dynamic:SYMTAB/STRTAB/GNU_HASH */
    unsigned long dt_symtab = 0, dt_strtab = 0, dt_gnuhash = 0;
    {
        size_t entsz = is64 ? 16 : 8;
        uint64_t n = dyn_size / entsz;
        uint8_t d[16];
        for (uint64_t i = 0; i < n; i++) {
            if (read_at(fd, dyn_off + (long) (i * entsz), d, entsz) < entsz)
                break;
            unsigned long tag, val;
            if (is64) {
                uint64_t a, b;
                memcpy(&a, d, 8);
                memcpy(&b, d + 8, 8);
                tag = (unsigned long) a;
                val = (unsigned long) b;
            } else {
                uint32_t a, b;
                memcpy(&a, d, 4);
                memcpy(&b, d + 4, 4);
                tag = a;
                val = b;
            }
            if (tag == 6)
                dt_symtab = val;
            else if (tag == 5)
                dt_strtab = val;
            else if (tag == 1879047925ul) /* DT_GNU_HASH=0x6ffffef5;用十进制:
                    Hikari 数字混淆对 hex+UL 后缀变换会留悬空 L(构建炸),十进制不变换 */
                dt_gnuhash = val;
            else if (tag == 0)
                break; /* DT_NULL */
        }
    }
    if (dt_symtab == 0 || dt_strtab == 0 || dt_gnuhash == 0) {
        x4_svc_close(fd);
        return NULL;
    }

    /* GNU hash → 符号数 */
    uint32_t nsyms = 0;
    {
        uint8_t h[16];
        long gnu_foff = segs_v2f(segs, nloads, dt_gnuhash);
        if (gnu_foff < 0 || read_at(fd, gnu_foff, h, 16) < 16) {
            x4_svc_close(fd);
            return NULL;
        }
        uint32_t nbuckets, symoffset, bloom_size;
        memcpy(&nbuckets, h, 4);
        memcpy(&symoffset, h + 4, 4);
        memcpy(&bloom_size, h + 8, 4);
        long buckets_off = gnu_foff + 16 + (long) bloom_size * (is64 ? 8 : 4);
        long chains_off = buckets_off + (long) nbuckets * 4;
        /* 找 max bucket */
        uint32_t maxsym = 0;
        uint8_t b[4];
        for (uint32_t i = 0; i < nbuckets; i++) {
            if (read_at(fd, buckets_off + (long) i * 4, b, 4) < 4)
                break;
            uint32_t v;
            memcpy(&v, b, 4);
            if (v > maxsym)
                maxsym = v;
        }
        if (maxsym < symoffset) {
            nsyms = symoffset;
        } else {
            /* 从 maxsym 沿链走到终止位 */
            uint32_t idx = maxsym;
            for (uint32_t guard = 0; guard < 1000000; guard++) {
                if (read_at(fd, chains_off + (long) (idx - symoffset) * 4, b, 4) < 4)
                    break;
                uint32_t v;
                memcpy(&v, b, 4);
                if (v & 1) {
                    nsyms = idx + 1;
                    break;
                }
                idx++;
            }
        }
    }
    if (nsyms == 0) {
        x4_svc_close(fd);
        return NULL;
    }

    /* 遍历 dynsym[symoffset..nsyms) 按名匹配 */
    size_t symentsz = is64 ? 24 : 16;
    long sym_foff = segs_v2f(segs, nloads, dt_symtab);
    long str_foff = segs_v2f(segs, nloads, dt_strtab);
    if (sym_foff < 0 || str_foff < 0) {
        x4_svc_close(fd);
        return NULL;
    }
    uint8_t sym[24];
    char namebuf[256];
    /* 遍历 [0, nsyms)(含未哈希前缀符号) */
    for (uint32_t i = 0; i < nsyms; i++) {
        if (read_at(fd, sym_foff + (long) i * (long) symentsz, sym, symentsz) < symentsz)
            break;
        uint32_t st_name;
        memcpy(&st_name, sym, 4);
        uint64_t st_value;
        uint16_t st_shndx;
        if (is64) {
            /* Elf64_Sym: st_name@0 st_info@4 st_other@5 st_shndx@6 st_value@8 */
            memcpy(&st_shndx, sym + 6, 2);
            memcpy(&st_value, sym + 8, 8);
        } else {
            uint32_t v;
            memcpy(&v, sym + 4, 4);
            st_value = v;
            memcpy(&st_shndx, sym + 14, 2);
        }
        if (st_shndx == 0 || st_value == 0)
            continue;
        long noff = str_foff + (long) st_name;
        /* 读名字(限长) */
        size_t rn = read_at(fd, noff, (uint8_t *) namebuf, sizeof(namebuf) - 1);
        if (rn == 0)
            continue;
        namebuf[rn] = '\0';
        /* 截到 NUL */
        size_t L = 0;
        while (L < rn && namebuf[L] != '\0')
            L++;
        namebuf[L] = '\0';
        if (strcmp(namebuf, want) == 0) {
            x4_svc_close(fd);
            return (void *) (load_bias + (unsigned long) st_value);
        }
    }
    x4_svc_close(fd);
    return NULL;
}

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

    /* 1. 解析 VisitRoots 符号:maps+ELF 直解为主(命名空间无关),dlopen 回退 */
    void *visit_roots_fn = NULL;
    for (size_t i = 0; i < sizeof(kVisitRootsSymbols) / sizeof(kVisitRootsSymbols[0]); i++) {
        visit_roots_fn = resolve_art_symbol(kVisitRootsSymbols[i]);
        if (visit_roots_fn != NULL)
            break;
    }
    if (visit_roots_fn == NULL) {
        void *libart = dlopen("libart.so", RTLD_NOW | RTLD_NOLOAD);
        if (libart != NULL) {
            for (size_t i = 0; i < sizeof(kVisitRootsSymbols) / sizeof(kVisitRootsSymbols[0]);
                 i++) {
                visit_roots_fn = dlsym(libart, kVisitRootsSymbols[i]);
                if (visit_roots_fn != NULL)
                    break;
            }
        }
    }
    if (visit_roots_fn == NULL) {
        return 0; /* 符号不可得 → 优雅降级 */
    }

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
