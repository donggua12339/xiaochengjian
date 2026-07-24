/**
 * so_cipher.h - 玄甲 X0 外壳 SO 加密(运行时解密/提取库)
 *
 * 详见 docs/PRODUCT_XUANJIA_TIANYAN.md §X0 + ADR 0091 §3.1
 * 设计借鉴看雪 thread-287254(yuuki 自定义 Linker 与 SO 加固)。
 *
 * 目标:让外壳 libxcj_defender.so 不以明文落地/可提取(抬高静态提取门槛)。
 *  - 构建期(so_cipher.py)RC4 加密 .so,按框架追加藏于 APK 资源(如
 *    ic_launcher.webp)尾部;运行时从资源尾部 O(1) 反向定位框架→RC4 解密
 *    →后续 memfd_create + android_dlopen_ext 加载(加载见 X0 后续阶段)。
 *
 * 框架布局(尾部固定 trailer,免扫描、O(1) 定位):
 *   [原始资源字节][RC4 密文(与明文等长)][MAGIC "XCJSO1"(6B)][明文长度 u32 LE(4B)]
 *   文件末 10 字节恒为 [MAGIC][len];密文为 magic 之前 len 字节。
 *
 * RC4 为流密码(加解密同函数)。密钥构建期注入、不在开源仓库;生产每构建随机,
 * 由 Packer 注入外壳 loader 并以 X1 OBF() 混淆。加密强度非目标——强防护靠五层
 * 反动态 + memfd,本层只承诺"明文 .so 不直接暴露给静态分析/喂料天衍攻击者"。
 *
 * 必补的坑(yuuki 原版残留,我们规避):解密后必须 memset 清零密文/密钥派生状态、
 * 删除临时文件、munmap 密文映射,避免取证残留与内存明文驻留。
 */
#ifndef SO_CIPHER_H
#define SO_CIPHER_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define SO_CIPHER_MAGIC      "XCJSO1"
#define SO_CIPHER_MAGIC_LEN  6
#define SO_CIPHER_TAILER_LEN (SO_CIPHER_MAGIC_LEN + 4)   /* magic + u32 len = 10 */

/* ============= RC4(流密码,加解密同函数)============= */
typedef struct { uint8_t S[256]; uint8_t i, j; } so_rc4_ctx;

static inline void so_rc4_init(so_rc4_ctx *c, const uint8_t *key, size_t klen) {
    for (int i = 0; i < 256; i++) c->S[i] = (uint8_t)i;
    uint8_t j = 0;
    for (int i = 0; i < 256; i++) {
        j = (uint8_t)(j + c->S[i] + key[i % klen]);
        uint8_t t = c->S[i]; c->S[i] = c->S[j]; c->S[j] = t;
    }
    c->i = 0; c->j = 0;
}

static inline void so_rc4_crypt(so_rc4_ctx *c, const uint8_t *in, uint8_t *out, size_t n) {
    for (size_t k = 0; k < n; k++) {
        c->i = (uint8_t)(c->i + 1);
        c->j = (uint8_t)(c->j + c->S[c->i]);
        uint8_t t = c->S[c->i]; c->S[c->i] = c->S[c->j]; c->S[c->j] = t;
        uint8_t ks = c->S[(uint8_t)(c->S[c->i] + c->S[c->j])];
        out[k] = (uint8_t)(in[k] ^ ks);
    }
}

/* ============= 框架定位 + 解密(运行时核心)=============
 * 从资源缓冲 buf[0..size) 尾部定位 [MAGIC][len],取出密文 RC4 解密到 out_plain。
 * out_plain 容量须 >= 明文长度;明文长度写入 *out_len。
 * 返回 0=成功 / -1=框架无效(魔数错/长度越界)。RC4 上下文用后清零。
 */
static inline int so_cipher_extract(const uint8_t *buf, size_t size,
                                    const uint8_t *key, size_t klen,
                                    uint8_t *out_plain, uint32_t *out_len) {
    const uint8_t *cipher = NULL;
    uint32_t len = 0;
    if (!buf || size < SO_CIPHER_TAILER_LEN) return -1;
    const uint8_t *tail = buf + size - SO_CIPHER_TAILER_LEN;
    if (memcmp(tail, SO_CIPHER_MAGIC, SO_CIPHER_MAGIC_LEN) != 0) return -1;
    len = (uint32_t)tail[SO_CIPHER_MAGIC_LEN]
        | ((uint32_t)tail[SO_CIPHER_MAGIC_LEN + 1] << 8)
        | ((uint32_t)tail[SO_CIPHER_MAGIC_LEN + 2] << 16)
        | ((uint32_t)tail[SO_CIPHER_MAGIC_LEN + 3] << 24);
    if ((size_t)len + SO_CIPHER_TAILER_LEN > size) return -1;   /* 越界保护 */
    cipher = buf + size - SO_CIPHER_TAILER_LEN - len;

    so_rc4_ctx rc4;
    so_rc4_init(&rc4, key, klen);
    so_rc4_crypt(&rc4, cipher, out_plain, len);
    *out_len = len;
    memset(&rc4, 0, sizeof(rc4));   /* 清密钥派生状态 */
    return 0;
}

/* ============= 仅定位密文(不解密;供先校验后解密/直接 mmap 的场景)============= */
static inline int so_cipher_locate(const uint8_t *buf, size_t size,
                                   const uint8_t **out_cipher, uint32_t *out_len) {
    if (!buf || size < SO_CIPHER_TAILER_LEN) return -1;
    const uint8_t *tail = buf + size - SO_CIPHER_TAILER_LEN;
    if (memcmp(tail, SO_CIPHER_MAGIC, SO_CIPHER_TAILER_LEN - 4) != 0) return -1;
    uint32_t len = (uint32_t)tail[SO_CIPHER_MAGIC_LEN]
                 | ((uint32_t)tail[SO_CIPHER_MAGIC_LEN + 1] << 8)
                 | ((uint32_t)tail[SO_CIPHER_MAGIC_LEN + 2] << 16)
                 | ((uint32_t)tail[SO_CIPHER_MAGIC_LEN + 3] << 24);
    if ((size_t)len + SO_CIPHER_TAILER_LEN > size) return -1;
    *out_cipher = buf + size - SO_CIPHER_TAILER_LEN - len;
    *out_len = len;
    return 0;
}

#endif /* SO_CIPHER_H */
