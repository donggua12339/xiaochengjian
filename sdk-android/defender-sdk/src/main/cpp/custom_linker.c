/**
 * custom_linker.c - 小城笺加固 v0.2: 自实现 ELF Linker 实现
 *
 * 从内存缓冲区加载 ELF .so,完全不依赖系统 dlopen。
 *
 * 实现参考 AOSP bionic/linker,裁剪为最小可用集:
 *  - 只读 Program Header(不依赖 Section Header)
 *  - 只处理第一个 PT_DYNAMIC
 *  - 重定位: RELATIVE + GLOB_DAT + JUMP_SLOT + ABS64
 *  - 外部符号: dlsym(RTLD_DEFAULT) 回退(安全:hook 框架不改 dlsym 返回值)
 */

#include "custom_linker.h"

#include <elf.h>
#include <link.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <android/log.h>

#define TAG "DefenderCustomLinker"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ============= 页对齐宏(复用 bionic 定义) ============= */
#define CL_PAGE_SIZE 4096
#define CL_PAGE_MASK (~(CL_PAGE_SIZE - 1))
#define CL_PAGE_START(x) ((x) & CL_PAGE_MASK)
#define CL_PAGE_END(x)   (((x) + CL_PAGE_SIZE - 1) & CL_PAGE_MASK)
#define CL_PAGE_OFFSET(x) ((x) & (CL_PAGE_SIZE - 1))

/* ============= inline syscall(防 hook) ============= */
#if defined(__aarch64__)
static void *cl_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    void *ret;
    __asm__ volatile(
        "mov x8, #222\n mov x0,%1\n mov x1,%2\n mov x2,%3\n mov x3,%4\n mov x4,%5\n mov x5,%6\n svc #0\n mov %0,x0\n"
        : "=r"(ret) : "r"(addr),"r"(len),"r"(prot),"r"(flags),"r"(fd),"r"(offset)
        : "x0","x1","x2","x3","x4","x5","x8","memory");
    return ret;
}
static int cl_mprotect(void *addr, size_t len, int prot) {
    int ret;
    __asm__ volatile(
        "mov x8, #226\n mov x0,%1\n mov x1,%2\n mov x2,%3\n svc #0\n mov %0,x0\n"
        : "=r"(ret) : "r"(addr),"r"(len),"r"(prot)
        : "x0","x1","x2","x8","memory");
    return ret;
}
static int cl_munmap(void *addr, size_t len) {
    int ret;
    __asm__ volatile(
        "mov x8, #215\n mov x0,%1\n mov x1,%2\n svc #0\n mov %0,x0\n"
        : "=r"(ret) : "r"(addr),"r"(len)
        : "x0","x1","x8","memory");
    return ret;
}
#else
static void *cl_mmap(void *a, size_t l, int p, int f, int fd, off_t o) { return mmap(a,l,p,f,fd,o); }
static int cl_mprotect(void *a, size_t l, int p) { return mprotect(a,l,p); }
static int cl_munmap(void *a, size_t l) { return munmap(a,l); }
#endif

/* ============= ELF 类型别名(arm64 = ELF64) ============= */
#if defined(__aarch64__)
typedef Elf64_Ehdr  Cl_Ehdr;
typedef Elf64_Phdr  Cl_Phdr;
typedef Elf64_Dyn   Cl_Dyn;
typedef Elf64_Sym   Cl_Sym;
typedef Elf64_Rela  Cl_Rel;  /* ARM64 用 RELA */
#define CL_ELFCLASS  ELFCLASS64
#define CL_R_SYM(i)  ELF64_R_SYM(i)
#define CL_R_TYPE(i) ELF64_R_TYPE(i)
#else
typedef Elf32_Ehdr  Cl_Ehdr;
typedef Elf32_Phdr  Cl_Phdr;
typedef Elf32_Dyn   Cl_Dyn;
typedef Elf32_Sym   Cl_Sym;
typedef Elf32_Rel   Cl_Rel;  /* ARM32 用 REL */
#define CL_ELFCLASS  ELFCLASS32
#define CL_R_SYM(i)  ELF32_R_SYM(i)
#define CL_R_TYPE(i) ELF32_R_TYPE(i)
#endif

/* ============= ARM64 重定位类型 ============= */
#if defined(__aarch64__)
#define CL_R_NONE        R_AARCH64_NONE
#define CL_R_ABS64       R_AARCH64_ABS64
#define CL_R_GLOB_DAT    R_AARCH64_GLOB_DAT
#define CL_R_JUMP_SLOT   R_AARCH64_JUMP_SLOT
#define CL_R_RELATIVE    R_AARCH64_RELATIVE
#else
#define CL_R_NONE        R_ARM_NONE
#define CL_R_ABS32       R_ARM_ABS32
#define CL_R_GLOB_DAT    R_ARM_GLOB_DAT
#define CL_R_JUMP_SLOT   R_ARM_JUMP_SLOT
#define CL_R_RELATIVE    R_ARM_RELATIVE
#endif

/* ============= soinfo 结构体 ============= */
#define CL_NAME_MAX 128

struct cl_soinfo {
    char        name[CL_NAME_MAX];
    uintptr_t   load_base;      /* mmap 起始地址 */
    size_t      load_size;      /* 映射总大小 */
    uintptr_t   load_bias;      /* load_base - 最低 vaddr */

    /* .dynamic 解析结果 */
    Cl_Dyn     *dynamic;
    Cl_Sym     *symtab;
    const char *strtab;
    size_t      strtab_size;

    /* 重定位表 */
#if defined(__aarch64__)
    Elf64_Rela *rela;           /* DT_RELA */
    size_t      rela_count;
    Elf64_Rela *plt_rela;      /* DT_JMPREL (PLT) */
    size_t      plt_rela_count;
#else
    Elf32_Rel  *rel;
    size_t      rel_count;
    Elf32_Rel  *plt_rel;
    size_t      plt_rel_count;
#endif

    /* 构造函数 */
    uintptr_t   init_func;      /* DT_INIT */
    uintptr_t  *init_array;     /* DT_INIT_ARRAY */
    size_t      init_array_count;

    /* 原始数据(用于 munmap 时释放) */
    void       *mmap_base;
    size_t      mmap_size;
};

/* ============= 辅助函数 ============= */

static const char *cl_strtab_get(const struct cl_soinfo *si, size_t offset) {
    if (!si->strtab || offset >= si->strtab_size) return "";
    return si->strtab + offset;
}

static int cl_elf_check(const Cl_Ehdr *ehdr) {
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) return -1;
    if (ehdr->e_ident[EI_CLASS] != CL_ELFCLASS) return -1;
    if (ehdr->e_type != ET_DYN && ehdr->e_type != ET_EXEC) return -1;
#if defined(__aarch64__)
    if (ehdr->e_machine != EM_AARCH64) return -1;
#else
    if (ehdr->e_machine != EM_ARM) return -1;
#endif
    return 0;
}

/* ============= 1. ReserveAddressSpace ============= */

static int cl_reserve_space(const Cl_Ehdr *ehdr, const Cl_Phdr *phdr,
                            uintptr_t *out_base, size_t *out_size, uintptr_t *out_bias) {
    /* 找最低和最高 vaddr */
    uintptr_t vaddr_min = UINTPTR_MAX;
    uintptr_t vaddr_max = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) continue;
        uintptr_t start = CL_PAGE_START(phdr[i].p_vaddr);
        uintptr_t end = CL_PAGE_END(phdr[i].p_vaddr + phdr[i].p_memsz);
        if (start < vaddr_min) vaddr_min = start;
        if (end > vaddr_max) vaddr_max = end;
    }

    if (vaddr_min >= vaddr_max) return -1;

    size_t load_size = vaddr_max - vaddr_min;
    void *base = cl_mmap(NULL, load_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return -1;

    *out_base = (uintptr_t)base;
    *out_size = load_size;
    *out_bias = (uintptr_t)base - vaddr_min;
    return 0;
}

/* ============= 2. LoadSegments ============= */

static int cl_load_segments(const void *data, size_t data_len,
                            const Cl_Ehdr *ehdr, const Cl_Phdr *phdr,
                            uintptr_t load_bias) {
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) continue;

        uintptr_t seg_start = CL_PAGE_START(phdr[i].p_vaddr) + load_bias;
        uintptr_t seg_end = CL_PAGE_END(phdr[i].p_vaddr + phdr[i].p_memsz) + load_bias;
        size_t seg_size = seg_end - seg_start;

        /* 先映射为可读写 */
        void *mapped = cl_mmap((void *)seg_start, seg_size,
                               PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (mapped == MAP_FAILED) {
            LOGE("LoadSegments: mmap 失败 seg[%d]", i);
            return -1;
        }

        /* 从源数据 memcpy 文件内容 */
        if (phdr[i].p_filesz > 0) {
            if (phdr[i].p_offset + phdr[i].p_filesz > data_len) {
                LOGE("LoadSegments: 文件偏移越界 seg[%d]", i);
                return -1;
            }
            memcpy((void *)(phdr[i].p_vaddr + load_bias),
                   (const uint8_t *)data + phdr[i].p_offset,
                   phdr[i].p_filesz);
        }

        /* BSS 清零(filesz < memsz 的部分已被 MAP_ANONYMOUS 清零) */

        /* 设置段权限 */
        int prot = 0;
        if (phdr[i].p_flags & PF_R) prot |= PROT_READ;
        if (phdr[i].p_flags & PF_W) prot |= PROT_WRITE;
        if (phdr[i].p_flags & PF_X) prot |= PROT_EXEC;
        cl_mprotect((void *)seg_start, seg_size, prot);
    }
    return 0;
}

/* ============= 3. ParseDynamic ============= */

static void cl_parse_dynamic(struct cl_soinfo *si) {
    if (!si->dynamic) return;

    for (Cl_Dyn *d = si->dynamic; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
        case DT_SYMTAB:
            si->symtab = (Cl_Sym *)(d->d_un.d_ptr + si->load_bias);
            break;
        case DT_STRTAB:
            si->strtab = (const char *)(d->d_un.d_ptr + si->load_bias);
            break;
        case DT_STRSZ:
            si->strtab_size = d->d_un.d_val;
            break;
#if defined(__aarch64__)
        case DT_RELA:
            si->rela = (Elf64_Rela *)(d->d_un.d_ptr + si->load_bias);
            break;
        case DT_RELASZ:
            si->rela_count = d->d_un.d_val / sizeof(Elf64_Rela);
            break;
        case DT_JMPREL:
            si->plt_rela = (Elf64_Rela *)(d->d_un.d_ptr + si->load_bias);
            break;
        case DT_PLTRELSZ:
            si->plt_rela_count = d->d_un.d_val / sizeof(Elf64_Rela);
            break;
#else
        case DT_REL:
            si->rel = (Elf32_Rel *)(d->d_un.d_ptr + si->load_bias);
            break;
        case DT_RELSZ:
            si->rel_count = d->d_un.d_val / sizeof(Elf32_Rel);
            break;
        case DT_JMPREL:
            si->plt_rel = (Elf32_Rel *)(d->d_un.d_ptr + si->load_bias);
            break;
        case DT_PLTRELSZ:
            si->plt_rel_count = d->d_un.d_val / sizeof(Elf32_Rel);
            break;
#endif
        case DT_INIT:
            si->init_func = d->d_un.d_ptr + si->load_bias;
            break;
        case DT_INIT_ARRAY:
            si->init_array = (uintptr_t *)(d->d_un.d_ptr + si->load_bias);
            break;
        case DT_INIT_ARRAYSZ:
            si->init_array_count = d->d_un.d_val / sizeof(uintptr_t);
            break;
        }
    }
}

/* ============= 4. Relocate ============= */

static int cl_relocate_one(struct cl_soinfo *si, uintptr_t reloc_addr,
                           unsigned long r_type, unsigned long r_sym,
                           uintptr_t addend) {
    switch (r_type) {
    case CL_R_NONE:
        break;

#if defined(__aarch64__)
    case R_AARCH64_RELATIVE:
        *(uintptr_t *)reloc_addr = si->load_bias + addend;
        break;
    case R_AARCH64_GLOB_DAT:
    case R_AARCH64_JUMP_SLOT: {
        const char *name = cl_strtab_get(si, si->symtab[r_sym].st_name);
        void *sym_addr = dlsym(RTLD_DEFAULT, name);
        if (!sym_addr) {
            LOGE("重定位: 符号未找到: %s", name);
            return -1;
        }
        *(uintptr_t *)reloc_addr = (uintptr_t)sym_addr;
        break;
    }
    case R_AARCH64_ABS64: {
        const char *name = cl_strtab_get(si, si->symtab[r_sym].st_name);
        void *sym_addr = dlsym(RTLD_DEFAULT, name);
        if (!sym_addr) {
            LOGE("重定位 ABS64: 符号未找到: %s", name);
            return -1;
        }
        *(uintptr_t *)reloc_addr = (uintptr_t)sym_addr + addend;
        break;
    }
#else
    case R_ARM_RELATIVE:
        *(uintptr_t *)reloc_addr += si->load_bias;
        break;
    case R_ARM_GLOB_DAT:
    case R_ARM_JUMP_SLOT: {
        const char *name = cl_strtab_get(si, si->symtab[r_sym].st_name);
        void *sym_addr = dlsym(RTLD_DEFAULT, name);
        if (!sym_addr) {
            LOGE("重定位: 符号未找到: %s", name);
            return -1;
        }
        *(uintptr_t *)reloc_addr = (uintptr_t)sym_addr;
        break;
    }
    case R_ARM_ABS32: {
        const char *name = cl_strtab_get(si, si->symtab[r_sym].st_name);
        void *sym_addr = dlsym(RTLD_DEFAULT, name);
        if (!sym_addr) {
            LOGE("重定位 ABS32: 符号未找到: %s", name);
            return -1;
        }
        *(uintptr_t *)reloc_addr = (uintptr_t)sym_addr + addend;
        break;
    }
#endif

    default:
        LOGW("重定位: 未处理类型 %lu (sym=%lu)", r_type, r_sym);
        break;
    }
    return 0;
}

static int cl_relocate(struct cl_soinfo *si) {
    /* 重定位前使整个区域可写 */
    cl_mprotect((void *)si->load_base, si->load_size, PROT_READ | PROT_WRITE);

#if defined(__aarch64__)
    for (size_t i = 0; i < si->rela_count; i++) {
        uintptr_t addr = si->rela[i].r_offset + si->load_bias;
        if (cl_relocate_one(si, addr, CL_R_TYPE(si->rela[i].r_info),
                            CL_R_SYM(si->rela[i].r_info), si->rela[i].r_addend) != 0)
            return -1;
    }
    for (size_t i = 0; i < si->plt_rela_count; i++) {
        uintptr_t addr = si->plt_rela[i].r_offset + si->load_bias;
        if (cl_relocate_one(si, addr, CL_R_TYPE(si->plt_rela[i].r_info),
                            CL_R_SYM(si->plt_rela[i].r_info), si->plt_rela[i].r_addend) != 0)
            return -1;
    }
#else
    for (size_t i = 0; i < si->rel_count; i++) {
        uintptr_t addr = si->rel[i].r_offset + si->load_bias;
        if (cl_relocate_one(si, addr, CL_R_TYPE(si->rel[i].r_info),
                            CL_R_SYM(si->rel[i].r_info), 0) != 0)
            return -1;
    }
    for (size_t i = 0; i < si->plt_rel_count; i++) {
        uintptr_t addr = si->plt_rel[i].r_offset + si->load_bias;
        if (cl_relocate_one(si, addr, CL_R_TYPE(si->plt_rel[i].r_info),
                            CL_R_SYM(si->plt_rel[i].r_info), 0) != 0)
            return -1;
    }
#endif
    return 0;
}

/**
 * 重定位后恢复段权限(关键! 不恢复则 .text 无执行权限 → SEGV_ACCERR)
 */
static void cl_protect_segments(struct cl_soinfo *si, const Cl_Phdr *phdr, int phnum) {
    for (int i = 0; i < phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) continue;

        uintptr_t seg_start = CL_PAGE_START(phdr[i].p_vaddr) + si->load_bias;
        uintptr_t seg_end = CL_PAGE_END(phdr[i].p_vaddr + phdr[i].p_memsz) + si->load_bias;

        int prot = 0;
        if (phdr[i].p_flags & PF_R) prot |= PROT_READ;
        if (phdr[i].p_flags & PF_W) prot |= PROT_WRITE;
        if (phdr[i].p_flags & PF_X) prot |= PROT_EXEC;
        cl_mprotect((void *)seg_start, seg_end - seg_start, prot);
    }
}

/* ============= 5. 符号查找 ============= */

static void *cl_find_symbol(struct cl_soinfo *si, const char *name) {
    if (!si->symtab || !si->strtab) return NULL;

    /* 线性扫描符号表(简化;生产可用 hash table DT_HASH/DT_GNU_HASH) */
    /* 遍历到 strtab 末尾为止 — 用 strtab_size 估算符号数 */
    /* 更可靠的方式: 用 DT_HASH 的 nbucket+nchains */
    /* 简化: 扫描足够多的条目 */
    for (int i = 0; i < 4096; i++) {
        if (si->symtab[i].st_name == 0) continue;
        const char *sym_name = cl_strtab_get(si, si->symtab[i].st_name);
        if (strcmp(sym_name, name) == 0) {
            if (si->symtab[i].st_shndx != SHN_UNDEF) {
                return (void *)(si->symtab[i].st_value + si->load_bias);
            }
        }
        /* 简单终止条件: st_name 超出 strtab */
        if (si->symtab[i].st_name >= si->strtab_size) break;
    }
    return NULL;
}

/* ============= 公共 API ============= */

cl_handle_t cl_dlopen_mem(const void *data, size_t data_len, const char *name) {
    if (!data || data_len < sizeof(Cl_Ehdr)) {
        LOGE("cl_dlopen_mem: 无效数据");
        return NULL;
    }

    const Cl_Ehdr *ehdr = (const Cl_Ehdr *)data;
    if (cl_elf_check(ehdr) != 0) {
        LOGE("cl_dlopen_mem: ELF 校验失败");
        return NULL;
    }

    /* 读取 program headers */
    if (ehdr->e_phoff + ehdr->e_phnum * sizeof(Cl_Phdr) > data_len) {
        LOGE("cl_dlopen_mem: phdr 越界");
        return NULL;
    }
    const Cl_Phdr *phdr = (const Cl_Phdr *)((const uint8_t *)data + ehdr->e_phoff);

    /* 分配 soinfo */
    struct cl_soinfo *si = (struct cl_soinfo *)calloc(1, sizeof(struct cl_soinfo));
    if (!si) return NULL;
    if (name) strncpy(si->name, name, CL_NAME_MAX - 1);

    /* 1. ReserveAddressSpace */
    if (cl_reserve_space(ehdr, phdr, &si->load_base, &si->load_size, &si->load_bias) != 0) {
        LOGE("cl_dlopen_mem: ReserveAddressSpace 失败");
        free(si);
        return NULL;
    }

    /* 2. LoadSegments */
    if (cl_load_segments(data, data_len, ehdr, phdr, si->load_bias) != 0) {
        LOGE("cl_dlopen_mem: LoadSegments 失败");
        cl_munmap((void *)si->load_base, si->load_size);
        free(si);
        return NULL;
    }

    /* 3. 定位 PT_DYNAMIC */
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            si->dynamic = (Cl_Dyn *)(phdr[i].p_vaddr + si->load_bias);
            break;  /* 只处理第一个 PT_DYNAMIC(迷惑 IDA) */
        }
    }

    /* 4. 解析 .dynamic */
    cl_parse_dynamic(si);

    /* 5. 重定位 */
    if (cl_relocate(si) != 0) {
        LOGE("cl_dlopen_mem: 重定位失败");
        cl_munmap((void *)si->load_base, si->load_size);
        free(si);
        return NULL;
    }

    /* 6. 恢复段权限(重定位时临时设为 RW,现在恢复为 R/RX/RW) */
    cl_protect_segments(si, phdr, ehdr->e_phnum);

    si->mmap_base = (void *)si->load_base;
    si->mmap_size = si->load_size;

    LOGI("cl_dlopen_mem: 加载成功 name=%s base=0x%lx size=%zu bias=0x%lx",
         si->name, (unsigned long)si->load_base, si->load_size, (unsigned long)si->load_bias);

    return si;
}

int cl_call_constructors(cl_handle_t si) {
    if (!si) return -1;

    /* 调用 DT_INIT */
    if (si->init_func) {
        LOGI("cl_call_constructors: DT_INIT=0x%lx", (unsigned long)si->init_func);
        ((void (*)(void))si->init_func)();
    }

    /* 调用 DT_INIT_ARRAY */
    for (size_t i = 0; i < si->init_array_count; i++) {
        uintptr_t func = si->init_array[i];
        if (func && func != (uintptr_t)-1) {
            LOGI("cl_call_constructors: init_array[%zu]=0x%lx", i, (unsigned long)func);
            ((void (*)(void))func)();
        }
    }

    return 0;
}

void *cl_dlsym(cl_handle_t si, const char *symbol) {
    if (!si || !symbol) return NULL;
    return cl_find_symbol(si, symbol);
}

void cl_dlclose(cl_handle_t si) {
    if (!si) return;
    if (si->mmap_base && si->mmap_size) {
        cl_munmap(si->mmap_base, si->mmap_size);
    }
    free(si);
}

uintptr_t cl_get_base(cl_handle_t si) {
    return si ? si->load_base : 0;
}

size_t cl_get_size(cl_handle_t si) {
    return si ? si->load_size : 0;
}
