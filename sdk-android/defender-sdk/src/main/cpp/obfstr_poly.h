/**
 * obfstr_poly.h - 玄甲 X1 字符串多态加密(运行时解密库)
 *
 * 详见 docs/PRODUCT_XUANJIA_TIANYAN.md §5 + ADR 0091 §3.2
 *
 * 设计目标:让 MT/NP 的"一键字符串解密"(静态 .rodata 模板匹配)完全失效。
 *  - .rodata 中无明文,且每个字符串的密文由"4 原语某排列 + per-string seed"复合而成,
 *    统计特征各异,单 XOR/单 ADD/base64 等已知模板无法匹配。
 *  - 多态空间 = 4 原语排列(24) × per-string seed(2^27)。
 *
 * 原语集(均可逆,无大表;刻意选取"两两不互逆 + 非退化"以避免排列坍缩):
 *   op0 = XOR xk    逆 = XOR xk          (xk 非 0)
 *   op1 = ROL rn    逆 = ROL (8-rn)      (rn 非 0, 8 位循环左移)
 *   op2 = ADD ak    逆 = SUB ak          (ak 非 0, mod 256)
 *   op3 = MUL mk    逆 = MUL mulinv(mk)  (mk 奇数且非 1, mod 256; 引入非线性)
 * 说明:早期版本 op3 用 SUB,但 ADD 与 SUB 互为逆运算,当二者在排列中相邻时复合=恒等,
 *   使不同排列坍缩成相同变换(多态性失效,被交叉测试拦截)。改用 MUL 后,集合内无互逆对,
 *   且各原语经"非退化映射"保证永不为恒等变换,故 24 排列的复合彼此不同。
 *   注:产品文档提及的"查表(SBOX)"作为 v1.1 可选非线性增强;对"能读开源源码的专业逆向",
 *   玄甲靠五层反动态+SMC 挡,字符串算法本身不承担该层防护(天衍 VMP 的职责,ADR 0091 §1)。
 *
 * 加密(构建期,obfstr_poly.py):按排列正序施加 fwd(op,b)
 * 解密(运行时,本文件):      按排列逆序施加 inv(op,b)
 *
 * per-string 参数由 seed(uint32) 派生(非退化映射,保证每原语非恒等):
 *   xk = ((seed      ) & 0xff) | 1        (XOR 密钥, 奇数非 0)
 *   rn = ((seed >>  8) & 0x07) | 1        (ROL 位移, ∈{1,3,5,7})
 *   ak = ((seed >> 16) & 0xff) | 1        (ADD 密钥, 奇数非 0)
 *   mk = ((seed >> 19) & 0xff) | 1; if mk==1 then mk=3   (MUL 乘数, 奇数且非 1)
 * 注:C 端与 py 端上述派生必须逐字同义;由 test_obfstr_poly.c 的 C∘py 交叉验证兜底。
 *
 * 开源安全性说明:本 decode 算法随玄甲 SDK 开源,但每个开发者构建自己 APK 时,
 * seed/variant/密文由 obfstr_poly.py 随机生成并注入构建产物,不在开源仓库中。
 * MT/NP 是通用工具,不读 SDK 源码做针对性提取,故模板匹配失效 = 目标达成。
 */
#ifndef OBFSTR_POLY_H
#define OBFSTR_POLY_H

#include <stdint.h>
#include <stddef.h>

/* ============= 24 排列(0,1,2,3 的全排列,与 obfstr_poly.py 严格一致) ============= */
static const uint8_t OBF_PERM[24][4] = {
    {0,1,2,3},{0,1,3,2},{0,2,1,3},{0,2,3,1},{0,3,1,2},{0,3,2,1},
    {1,0,2,3},{1,0,3,2},{1,2,0,3},{1,2,3,0},{1,3,0,2},{1,3,2,0},
    {2,0,1,3},{2,0,3,1},{2,1,0,3},{2,1,3,0},{2,3,0,1},{2,3,1,0},
    {3,0,1,2},{3,0,2,1},{3,1,0,2},{3,1,2,0},{3,2,0,1},{3,2,1,0}
};

/* ============= 原语 ============= */
static inline uint8_t obf_rol8(uint8_t x, uint8_t n) {
    n &= 7;
    return (uint8_t)((x << n) | (x >> ((8 - n) & 7)));
}

/* mod 256 乘法逆元(扩展欧几里得; a 为奇数故 gcd(a,256)=1) */
static inline uint8_t obf_mulinv8(uint8_t a) {
    int32_t t = 0, nt = 1, r = 256, nr = (int32_t)a;
    while (nr != 0) {
        int32_t q = r / nr;
        int32_t tmp;
        tmp = t - nt * q; t = nt; nt = tmp;
        tmp = r - nr * q; r = nr; nr = tmp;
    }
    if (t < 0) t += 256;
    return (uint8_t)(t & 0xff);
}

/* ============= 参数派生(非退化;与 obfstr_poly.py 逐字同义) ============= */
#define OBF_XK(seed) ((uint8_t)(((seed) & 0xffu) | 1u))
#define OBF_RN(seed) ((uint8_t)((((seed) >> 8) & 0x7u) | 1u))
#define OBF_AK(seed) ((uint8_t)((((seed) >> 16) & 0xffu) | 1u))
#define OBF_MK(seed) ({ uint8_t _m = (uint8_t)((((seed) >> 19) & 0xffu) | 1u); \
                        _m == 1u ? (uint8_t)3u : _m; })

/* 正向原语(加密用,供测试与脚本对照;release 中若无调用方会被 gc-sections 移除) */
static inline uint8_t obf_fwd(uint8_t op, uint8_t b, uint8_t xk, uint8_t rn,
                              uint8_t ak, uint8_t mk) {
    switch (op) {
    case 0: return (uint8_t)(b ^ xk);
    case 1: return obf_rol8(b, rn);
    case 2: return (uint8_t)(b + ak);
    case 3: return (uint8_t)((uint16_t)b * mk);
    }
    return b;
}

/* 逆向原语(解密用) */
static inline uint8_t obf_inv(uint8_t op, uint8_t b, uint8_t xk, uint8_t rn,
                              uint8_t ak, uint8_t mk) {
    switch (op) {
    case 0: return (uint8_t)(b ^ xk);
    case 1: return obf_rol8(b, (uint8_t)((8 - rn) & 7));
    case 2: return (uint8_t)(b - ak);
    case 3: return (uint8_t)((uint16_t)b * obf_mulinv8(mk));
    }
    return b;
}

/* ============= 解密(运行时核心) ============= */
static inline void obf_poly_decode(uint8_t *out, const uint8_t *enc, size_t len,
                                   uint32_t seed, uint8_t variant) {
    const uint8_t xk = OBF_XK(seed);
    const uint8_t rn = OBF_RN(seed);
    const uint8_t ak = OBF_AK(seed);
    const uint8_t mk = OBF_MK(seed);
    const uint8_t *perm = OBF_PERM[variant & 0x1f];  /* variant ∈ [0,23] */
    for (size_t i = 0; i < len; i++) {
        uint8_t b = enc[i];
        /* 逆序施加逆原语 */
        b = obf_inv(perm[3], b, xk, rn, ak, mk);
        b = obf_inv(perm[2], b, xk, rn, ak, mk);
        b = obf_inv(perm[1], b, xk, rn, ak, mk);
        b = obf_inv(perm[0], b, xk, rn, ak, mk);
        out[i] = b;
    }
}

/* ============= 加密(仅供测试/脚本对照,非运行时路径) ============= */
static inline void obf_poly_encode(uint8_t *out, const uint8_t *plain, size_t len,
                                   uint32_t seed, uint8_t variant) {
    const uint8_t xk = OBF_XK(seed);
    const uint8_t rn = OBF_RN(seed);
    const uint8_t ak = OBF_AK(seed);
    const uint8_t mk = OBF_MK(seed);
    const uint8_t *perm = OBF_PERM[variant & 0x1f];
    for (size_t i = 0; i < len; i++) {
        uint8_t b = plain[i];
        b = obf_fwd(perm[0], b, xk, rn, ak, mk);
        b = obf_fwd(perm[1], b, xk, rn, ak, mk);
        b = obf_fwd(perm[2], b, xk, rn, ak, mk);
        b = obf_fwd(perm[3], b, xk, rn, ak, mk);
        out[i] = b;
    }
}

/* ============= 开发期 OBF 宏(明文,便于调试;构建期由 obfstr_poly.py 替换) =============
 * 源码中写 OBF("frida") -> 开发期为明文字符串;
 * 构建期 obfstr_poly.py 扫描 OBF("...") 并替换为 _OBF_USE(seed,variant,n,{cipher...})。
 */
#ifndef OBF
#define OBF(s) (s)
#endif

/* ============= 构建期替换形态:惰性解密到静态缓冲 =============
 * 用 GNU/Clang statement-expression,可在表达式位置使用(如 strcmp(_OBF_USE(...),"x"))。
 * 明文惰性解密后驻留静态缓冲(符合玄甲定位:抗静态扫描/dump 由五层+SMC 负责,
 * 字符串多态本身只承诺抗 MT 静态模板匹配)。多线程首调幂等(同密文同参->同明文)。
 * 注意:此处 cipher 用复合字面量 (const uint8_t[]){...},需 Clang/GCC 扩展(NDK=Clang ✓)。
 */
#define _OBF_USE(seed, variant, n, ...)                                     \
    ({                                                                      \
        static char _obf_buf[(n) + 1];                                      \
        static volatile int _obf_init;                                      \
        if (!_obf_init) {                                                   \
            static const uint8_t _obf_c[] = { __VA_ARGS__ };                \
            obf_poly_decode((uint8_t *)_obf_buf, _obf_c, (n),               \
                            (uint32_t)(seed), (uint8_t)(variant));          \
            _obf_buf[(n)] = '\0';                                           \
            _obf_init = 1;                                                  \
        }                                                                   \
        _obf_buf;                                                           \
    })

#endif /* OBFSTR_POLY_H */
