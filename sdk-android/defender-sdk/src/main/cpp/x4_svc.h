/**
 * x4_svc.h - X4-0 基建:svc 内联系统调用原语(ADR 0093)
 *
 * 目的:绕过 libc 的 PLT/inline hook——攻击者 hook open/openat/read/readlinkat 等
 * libc 函数对 svc 直发无效(MT killOpen / Frida 一把梭hook libc 均失效)。
 *
 * 工程兼容(调研 M5/MT-8 结论):
 *  - noinline + visibility hidden:防 NDK r25+ CFI/LTO 内联合并 svc 代码致 CRC 失效;
 *  - ARM64 内联 svc(x8=号);ARM32 内联 svc(r7=号),fstat 走 libc syscall 保 struct 正确;
 *  - seccomp 白名单内 openat/read/close 可用,ptrace 类慎用(本库不含 ptrace)。
 *
 * 返回:系统调用返回值;负数为错误(-errno 风格)。
 */
#ifndef X4_SVC_H
#define X4_SVC_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

int     x4_svc_openat(int dirfd, const char *path, int flags, int mode);
ssize_t x4_svc_read(int fd, void *buf, size_t count);
int     x4_svc_close(int fd);
int     x4_svc_fstat(int fd, struct stat *st);
ssize_t x4_svc_readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz);
ssize_t x4_svc_getdents64(int fd, void *dirp, size_t count);
int     x4_svc_clock_gettime(int clk_id, struct timespec *tp);
pid_t   x4_svc_getpid(void);
pid_t   x4_svc_gettid(void);
int     x4_svc_nanosleep(const struct timespec *req, struct timespec *rem);

#endif /* X4_SVC_H */
