/**
 * x4_svc.c - svc 内联系统调用实现(ADR 0093 / X4-0)
 *
 * ARM64:x8 = 系统调用号,x0-x3 = 参数,svc #0。
 * ARM32:r7 = 系统调用号,r0-r3 = 参数,svc #0(fstat 走 libc syscall 保 struct 布局正确)。
 * 其他(宿主 x86):libc 回退,仅供结构编译/host 测试。
 *
 * 全部 noinline + visibility hidden:防 CFI/LTO 内联合并(致函数体 CRC 不稳定),
 * 且不导出符号(从 .dynsym 隐藏)。
 */
#include "x4_svc.h"
#include <sys/syscall.h>
#include <unistd.h>

#define X4_ATTR __attribute__((noinline, visibility("hidden")))

#if defined(__aarch64__)

#define A64_0(ret, fn, nr) X4_ATTR ret fn(void) { \
    register long x8 __asm__("x8") = (nr); register long x0 __asm__("x0"); \
    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8) : "memory", "cc"); return (ret)x0; }
#define A64_1(ret, fn, nr, t1) X4_ATTR ret fn(t1 a) { \
    register long x8 __asm__("x8") = (nr); register long x0 __asm__("x0") = (long)(a); \
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory", "cc"); return (ret)x0; }
#define A64_2(ret, fn, nr, t1, t2) X4_ATTR ret fn(t1 a, t2 b) { \
    register long x8 __asm__("x8") = (nr); register long x0 __asm__("x0") = (long)(a); \
    register long x1 __asm__("x1") = (long)(b); \
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1) : "memory", "cc"); return (ret)x0; }
#define A64_3(ret, fn, nr, t1, t2, t3) X4_ATTR ret fn(t1 a, t2 b, t3 c) { \
    register long x8 __asm__("x8") = (nr); register long x0 __asm__("x0") = (long)(a); \
    register long x1 __asm__("x1") = (long)(b); register long x2 __asm__("x2") = (long)(c); \
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory", "cc"); return (ret)x0; }
#define A64_4(ret, fn, nr, t1, t2, t3, t4) X4_ATTR ret fn(t1 a, t2 b, t3 c, t4 d) { \
    register long x8 __asm__("x8") = (nr); register long x0 __asm__("x0") = (long)(a); \
    register long x1 __asm__("x1") = (long)(b); register long x2 __asm__("x2") = (long)(c); \
    register long x3 __asm__("x3") = (long)(d); \
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory", "cc"); return (ret)x0; }

A64_4(int,     x4_svc_openat,        __NR_openat,        int, const char *, int, int)
A64_3(ssize_t, x4_svc_read,          __NR_read,          int, void *, size_t)
A64_1(int,     x4_svc_close,         __NR_close,         int)
A64_2(int,     x4_svc_fstat,         __NR_fstat,         int, struct stat *)
A64_4(ssize_t, x4_svc_readlinkat,    __NR_readlinkat,    int, const char *, char *, size_t)
A64_3(ssize_t, x4_svc_getdents64,    __NR_getdents64,    int, void *, size_t)
A64_2(int,     x4_svc_clock_gettime, __NR_clock_gettime, int, struct timespec *)
A64_0(pid_t,   x4_svc_getpid,        __NR_getpid)
A64_0(pid_t,   x4_svc_gettid,        __NR_gettid)
A64_2(int,     x4_svc_nanosleep,     __NR_nanosleep,     const struct timespec *, struct timespec *)

#undef A64_0
#undef A64_1
#undef A64_2
#undef A64_3
#undef A64_4

#elif defined(__arm__)
/* ARM32 编译为 Thumb 模式(-mthumb),R7 是保留寄存器(帧指针),无法用 register var
 * 直接内联 svc(报 "write to reserved register R7")。此处用 libc syscall() 包装,
 * 与既有 mmap_reader.c ARM32 路径一致。主目标 arm64 用内联 svc 抗 hook;ARM32 钩抗
 * 性稍弱,后续可用 push/pop {{r7} 的内联 svc 加强。 */
X4_ATTR int     x4_svc_openat(int d, const char *p, int f, int m) { return (int)syscall(__NR_openat, d, p, f, m); }
X4_ATTR ssize_t x4_svc_read(int fd, void *b, size_t n) { return (ssize_t)syscall(__NR_read, fd, b, n); }
X4_ATTR int     x4_svc_close(int fd) { return (int)syscall(__NR_close, fd); }
X4_ATTR int     x4_svc_fstat(int fd, struct stat *st) { return (int)syscall(__NR_fstat, fd, st); }
X4_ATTR ssize_t x4_svc_readlinkat(int d, const char *p, char *b, size_t n) { return (ssize_t)syscall(__NR_readlinkat, d, p, b, n); }
X4_ATTR ssize_t x4_svc_getdents64(int fd, void *d, size_t n) { return (ssize_t)syscall(__NR_getdents64, fd, d, n); }
X4_ATTR int     x4_svc_clock_gettime(int c, struct timespec *t) { return (int)syscall(__NR_clock_gettime, c, t); }
X4_ATTR pid_t   x4_svc_getpid(void) { return (pid_t)syscall(__NR_getpid); }
X4_ATTR pid_t   x4_svc_gettid(void) { return (pid_t)syscall(__NR_gettid); }
X4_ATTR int     x4_svc_nanosleep(const struct timespec *q, struct timespec *r) { return (int)syscall(__NR_nanosleep, q, r); }

#else
/* 宿主(x86 等):libc 回退,仅供结构编译 / host 测试 */
#include <fcntl.h>
X4_ATTR int     x4_svc_openat(int d, const char *p, int f, int m) { return openat(d, p, f, m); }
X4_ATTR ssize_t x4_svc_read(int fd, void *b, size_t n) { return read(fd, b, n); }
X4_ATTR int     x4_svc_close(int fd) { return close(fd); }
X4_ATTR int     x4_svc_fstat(int fd, struct stat *st) { return fstat(fd, st); }
X4_ATTR ssize_t x4_svc_readlinkat(int d, const char *p, char *b, size_t n) { return readlinkat(d, p, b, n); }
X4_ATTR ssize_t x4_svc_getdents64(int fd, void *d, size_t n) { return syscall(__NR_getdents64, fd, d, n); }
X4_ATTR int     x4_svc_clock_gettime(int c, struct timespec *t) { return clock_gettime(c, t); }
X4_ATTR pid_t   x4_svc_getpid(void) { return getpid(); }
X4_ATTR pid_t   x4_svc_gettid(void) { return gettid(); }
X4_ATTR int     x4_svc_nanosleep(const struct timespec *q, struct timespec *r) { return nanosleep(q, r); }
#endif
