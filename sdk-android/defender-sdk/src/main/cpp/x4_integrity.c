/**
 * x4_integrity.c - X4-2 L4 运行时完整性实现(ADR 0093)
 *
 * 1. libc 四入口 CRC:用 dlsym 定位 open/openat/fopen/syscall,读入口 16 字节
 *    算 CRC32 作基线。守护线程周期重读,若 CRC 变 → 被 inline hook(NP/MT killOpen)。
 * 2. inline hook 指纹:ARM64 下 inline hook 通常在函数入口写 LDR+BR(含 0xD61F 字节);
 *    扫自身关键函数入口 16 字节检测此模式。
 * 3. svc openat 签名块验证:svc 直读 APK 尾部 EOCD + "APK Sig Block 42" 魔数,
 *    与 init 时基线比对——若 IO 重定向把 APK 换了,signing block 不同。
 */
#include "x4_integrity.h"
#include "x4_svc.h"
#include "x4_str.h"
#include "obfstr_poly.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <android/log.h>

/* ============= CRC32 ============= */

static uint32_t crc32_tab[256];
static int crc32_ready = 0;

static void crc32_init(void) {
    if (crc32_ready) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        crc32_tab[i] = c;
    }
    crc32_ready = 1;
}

static uint32_t crc32_calc(const uint8_t *data, size_t len) {
    if (!crc32_ready) crc32_init();
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) c = crc32_tab[(c ^ data[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

/* ============= 1. libc 四入口 CRC ============= */

#define LIBC_N 4
static uint32_t g_libc_crc[LIBC_N];
static void    *g_libc_addr[LIBC_N];
static int      g_libc_ok = 0;
static const char *libc_fn[LIBC_N] = {"open", "openat", "fopen", "syscall"};

void x4_integrity_init(const char *apk_path) {
    (void)apk_path;
    crc32_init();
    for (int i = 0; i < LIBC_N; i++) {
        void *a = dlsym(RTLD_DEFAULT, libc_fn[i]);
        g_libc_addr[i] = a;
        g_libc_crc[i] = a ? crc32_calc((const uint8_t *)a, 16) : 0;
    }
    g_libc_ok = 1;
}

int x4_check_libc_hooked(void) {
    if (!g_libc_ok) return -1;
    int hooked = 0;
    for (int i = 0; i < LIBC_N; i++) {
        if (!g_libc_addr[i]) continue;
        if (crc32_calc((const uint8_t *)g_libc_addr[i], 16) != g_libc_crc[i]) hooked++;
    }
    return hooked;
}

/* ============= 2. inline hook 指纹(ARM64 BR 指令 0xD61F) ============= */

static int has_br_insn(const void *func, size_t bytes) {
    const uint8_t *p = (const uint8_t *)func;
    for (size_t i = 0; i + 3 < bytes; i += 4) {
        if (p[i + 2] == 0x1F && p[i + 3] == 0xD6) return 1;  /* BR Xn */
    }
    return 0;
}

extern int x4_anti_inject_check(void);
extern int x4_check_libc_hooked(void);

int x4_check_inline_hook(void) {
    int hooked = 0;
    void *targets[] = { (void *)x4_anti_inject_check, (void *)x4_check_libc_hooked };
    int n = (int)(sizeof(targets) / sizeof(targets[0]));
    for (int i = 0; i < n; i++) {
        if (has_br_insn(targets[i], 16)) hooked++;
    }
    return hooked;
}

/* ============= 3. svc openat 签名块验证 ============= */

static uint32_t g_sig_crc = 0;

/* svc lseek(ARM64 __NR_lseek=62) */
static long x4_svc_lseek(int fd, long off, int whence) {
#if defined(__aarch64__)
    register long x8 __asm__("x8") = 62;
    register long x0 __asm__("x0") = fd;
    register long x1 __asm__("x1") = off;
    register long x2 __asm__("x2") = whence;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory", "cc");
    return x0;
#else
    extern long lseek(long, long, int);
    return lseek((long)fd, off, whence);
#endif
}

static uint32_t calc_sig_block_crc(int fd, size_t fsize) {
    /* 200KB tail 覆盖 signing block + CD + EOCD(V2/V3 签名块可达数十 KB) */
    size_t tail_sz = (fsize < 200000) ? fsize : 200000;
    uint8_t *tail = (uint8_t *)malloc(tail_sz);
    if (!tail) return 0;
    x4_svc_lseek(fd, (long)(fsize - tail_sz), 0);
    ssize_t n = x4_svc_read(fd, tail, tail_sz);
    if (n <= 0) { free(tail); return 0; }

    /* 倒扫 EOCD(0x06054b50) */
    int eocd = -1;
    for (ssize_t i = n - 22; i >= 0; i--) {
        uint32_t s = (uint32_t)tail[i] | ((uint32_t)tail[i+1]<<8) |
                     ((uint32_t)tail[i+2]<<16) | ((uint32_t)tail[i+3]<<24);
        if (s == 0x06054b50u) { eocd = (int)i; break; }
    }
    if (eocd < 0) { free(tail); return 0; }

    uint32_t cd_off = (uint32_t)tail[eocd+16] | ((uint32_t)tail[eocd+17]<<8) |
                      ((uint32_t)tail[eocd+18]<<16) | ((uint32_t)tail[eocd+19]<<24);
    /* "APK Sig Block 42" 在全局 cd_off-16;tail 对应全局 [fsize-tail_sz, fsize) */
    size_t base = fsize - tail_sz;
    if ((size_t)cd_off < 16 + base) { free(tail); return 0; }
    size_t magic_in_tail = (size_t)cd_off - 16 - base;
    if (magic_in_tail + 16 > (size_t)n) { free(tail); return 0; }
    if (x4_memcmp(tail + magic_in_tail, "APK Sig Block 42", 16) != 0) {
        free(tail); return 0;
    }
    /* 签名块区域 CRC(magic 前后各 32 字节) */
    size_t h0 = (magic_in_tail > 32) ? (magic_in_tail - 32) : 0;
    size_t h1 = (magic_in_tail + 48 < (size_t)n) ? (magic_in_tail + 48) : (size_t)n;
    uint32_t crc = crc32_calc(tail + h0, h1 - h0);
    free(tail);
    return crc;
}

int x4_check_signing_block(const char *apk_path) {
    if (!apk_path) return -1;
    int fd = x4_svc_openat(AT_FDCWD, apk_path, O_RDONLY, 0);
    if (fd < 0) return -1;
    struct stat st;
    if (x4_svc_fstat(fd, &st) != 0) { x4_svc_close(fd); return -1; }
    uint32_t cur = calc_sig_block_crc(fd, (size_t)st.st_size);
    x4_svc_close(fd);
    if (cur == 0) return 1;
    if (g_sig_crc == 0) { g_sig_crc = cur; return 0; }
    return (cur != g_sig_crc) ? 1 : 0;
}

/* ============= L4 综合 ============= */

int x4_integrity_check(const char *apk_path) {
    int score = 0;
    int l = x4_check_libc_hooked();
    int h = x4_check_inline_hook();
    int s = x4_check_signing_block(apk_path);
    if (l > 0) score += l;
    if (h > 0) score += h;
    if (s > 0) score += s;
    return score;
}
