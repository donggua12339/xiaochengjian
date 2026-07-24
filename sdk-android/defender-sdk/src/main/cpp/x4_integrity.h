/**
 * x4_integrity.h - X4-2 L4 运行时完整性(ADR 0093)
 *
 * 三类检测,补全 L4(与已有 self_integrity .text CRC 互补):
 *  1. libc 四入口 CRC 基线 + 周期比对(检测 NP/MT 的 inline hook IO 重定向)
 *  2. inline hook 指令级检测(扫关键函数入口 0xD61F 指纹)
 *  3. svc openat 自签名块验证(确认 svc 能读到真实 APK,对抗 IO 重定向)
 *
 * 返回:>=0 可疑计数(0=干净);负=内部错误(非致命)。
 */
#ifndef X4_INTEGRITY_H
#define X4_INTEGRITY_H

/* 启动时调用:记录 libc 四入口 CRC 基线 + 签名块基线。必须在主线程。 */
void x4_integrity_init(const char *apk_path);

/* 检测 1:libc open/openat/fopen/syscall 入口 16 字节 CRC 是否被改(inline hook)。
 * 返回被 hook 的函数数(0=干净)。 */
int x4_check_libc_hooked(void);

/* 检测 2:扫描自身关键函数入口,检测 ARM64 inline hook 指令指纹(0xD61F)。
 * 返回被 hook 的函数数(0=干净)。 */
int x4_check_inline_hook(void);

/* 检测 3:svc openat 打开 APK,读 EOCD + signing block 魔数,确认未被 IO 重定向。
 * 返回 0=正常 / 1=异常(签名块不匹配或读不到)。 */
int x4_check_signing_block(const char *apk_path);

/* L4 综合:返回总可疑计数(0=干净)。供 x4_daemon 周期调用。 */
int x4_integrity_check(const char *apk_path);

#endif /* X4_INTEGRITY_H */
