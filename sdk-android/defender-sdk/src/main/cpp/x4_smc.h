/**
 * x4_smc.h - X4-5 L5 SMC 自修改代码引擎(ADR 0093)
 *
 * 两段式 SMC:敏感计算以"加密机器码"形态存放,运行时才解密到独立沙箱页执行,
 * 执行完立即擦除。对抗静态 dump / idapython 离线复现。
 *
 * 设计要点(与现有 .text CRC 自检物理隔离,不互相破坏):
 *  - 沙箱页 = 独立匿名 mmap,不在 .text 段 → self_integrity 的 .text CRC 不受影响;
 *  - 权限时序零 rwx:PROT_NONE ↔ RW(写)↔ RX(执行),从不同时 W+X;
 *  - 明文机器码模板 XOR 混淆存 .rodata(抗静态识别),init 时解出后立即用
 *    运行时密钥 RC4 加密成缓存并清零明文;执行时解密缓存→沙箱页→执行→全擦除;
 *  - 运行时密钥 = salt(OBF) ^ getpid ^ 引擎地址低字节,进程内确定、静态不可复现。
 *
 * 提供最小可验证敏感计算 smc_add(a,b)(加密 add+ret 机器码),证明机制可跑通;
 * 复杂业务逻辑的 SMC/VMP 由 inner 引擎承担,本引擎在主 .so 提供原语 + 纪律。
 */
#ifndef X4_SMC_H
#define X4_SMC_H

#include <stdint.h>

/* 初始化:预分配沙箱页(PROT_NONE)+ 派生运行时密钥 + 生成 RC4 密文缓存。
 * 须在 X0 加载完成后、首次 smc 调用前调用。返回 0=成功。 */
int  x4_smc_init(void);

/* 演示敏感计算:解密缓存→沙箱页(零 rwx 时序)→执行→擦除。返回 a+b。 */
int  x4_smc_add(int a, int b);

/* 诊断:上次执行后沙箱页是否已被擦除(应全 0)。1=已擦/0=未擦/-1=未初始化。 */
int  x4_smc_sandbox_wiped(void);

/* 自测(host + 真机):XOR/RC4 往返 + 零 rwx 标志。返回 0=通过。 */
int  x4_smc_selftest(void);

#endif
