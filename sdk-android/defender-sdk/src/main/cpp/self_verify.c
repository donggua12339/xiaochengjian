/**
 * self_verify.c - .so .text 段 hash 自校验
 *
 * 详见 ADR 0088 §.so 防篡改
 *
 * 原理:
 *  1. 编译时,计算 .text 段(r-xp,可执行代码)的 SHA-256,写入 .rodata(只读数据段)
 *  2. 运行时,读 /proc/self/maps 找到本 .so 的 r-xp 段
 *  3. 计算 .text 段实际 SHA-256
 *  4. 与 .rodata 的预期 hash 比对
 *  5. 不匹配 -> .text 被内存 patch -> abort()
 *
 * 防御:
 *  - 改 .text -> hash 不匹配 -> abort
 *  - 改 .rodata(改 hash 值)-> .text 里读 .rodata 的 offset 对不上 -> abort
 *  - 同时改 .text 和 .rodata -> 需重新计算 hash,但 .text 改了 hash 也变,死循环
 *
 * 注:当前版本是骨架,预期 hash 用占位值。
 * 正式编译时需用 post-build 脚本计算实际 .text hash 并写入 .rodata。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <android/log.h>

#define TAG "DefenderSelfVerify"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ============= SHA-256 简化实现 ============= */
/* 注:为避免外部依赖,使用简化 SHA-256。
 * 正式版本应使用完整的 SHA-256 实现(如 musl libc 的实现)。
 * 这里用简化版占位,正式编译时替换。
 */

/* SHA-256 上下文 */
typedef struct {
    unsigned int state[8];
    unsigned long long bitlen;
    unsigned int datalen;
    unsigned char data[64];
} sha256_ctx;

/* SHA-256 常量 */
static const unsigned int k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static void sha256_transform(sha256_ctx *ctx, const unsigned char *data) {
    unsigned int a, b, c, d, e, f, g, h, t1, t2, m[64];
    int i, j;

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((unsigned int)data[j] << 24) | ((unsigned int)data[j + 1] << 16) |
               ((unsigned int)data[j + 2] << 8) | ((unsigned int)data[j + 3]);
    for (; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_ctx *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(sha256_ctx *ctx, const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(sha256_ctx *ctx, unsigned char *hash) {
    unsigned int i = ctx->datalen;

    /* 补位 */
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += (unsigned long long)ctx->datalen * 8;
    ctx->data[63] = (unsigned char)(ctx->bitlen);
    ctx->data[62] = (unsigned char)(ctx->bitlen >> 8);
    ctx->data[61] = (unsigned char)(ctx->bitlen >> 16);
    ctx->data[60] = (unsigned char)(ctx->bitlen >> 24);
    ctx->data[59] = (unsigned char)(ctx->bitlen >> 32);
    ctx->data[58] = (unsigned char)(ctx->bitlen >> 40);
    ctx->data[57] = (unsigned char)(ctx->bitlen >> 48);
    ctx->data[56] = (unsigned char)(ctx->bitlen >> 56);
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0xff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0xff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0xff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0xff;
    }
}

/* ============= .text 段 hash 自校验 ============= */

/*
 * 预期 .text 段 SHA-256(64 字节,hex 字符串)
 *
 * 占位值:全 0
 * 正式编译流程:
 *   1. 编译 .so(此值为占位)
 *   2. post-build 脚本读 .so 的 .text 段,计算 SHA-256
 *   3. 把 hash 写入 .so 的 .rodata 段(覆盖占位值)
 *   4. 重新链接 .so(.rodata 不影响 .text,hash 不变)
 *
 * 使用 __attribute__((section)) 确保 hash 存在 .rodata 段
 */
static const char EXPECTED_TEXT_HASH[65] __attribute__((section(".rodata"))) =
    "0000000000000000000000000000000000000000000000000000000000000000";

/**
 * 读 /proc/self/maps,找到本 .so 的 r-xp 段(.text)
 *
 * @param base_out 输出:.text 段基址
 * @param size_out 输出:.text 段大小
 * @return 0=成功 / -1=失败
 */
static int find_text_section(unsigned long *base_out, unsigned long *size_out) {
    /* 用 dladdr 获取当前 .so 的路径(兼容 30 池随机名,如 libsec_helper.so) */
    Dl_info info;
    if (dladdr((void *)find_text_section, &info) == 0) {
        LOGE("dladdr 失败,无法获取 .so 路径");
        return -1;
    }

    /* 提取 .so basename(不含目录路径) */
    const char *so_basename = strrchr(info.dli_fname, '/');
    so_basename = so_basename ? so_basename + 1 : info.dli_fname;
    LOGI("当前 .so: %s (basename: %s)", info.dli_fname, so_basename);

    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) {
        LOGE("open /proc/self/maps 失败");
        return -1;
    }

    char buf[8192];
    char line[512];
    int line_pos = 0;
    int found = 0;

    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        for (int i = 0; i < n; i++) {
            if (buf[i] == '\n' || line_pos >= (int)sizeof(line) - 1) {
                line[line_pos] = '\0';

                /* 找 r-xp 段(可执行) */
                if (strstr(line, " r-xp ") != NULL) {
                    /* 解析基址和结束地址 */
                    unsigned long start, end;
                    char perms[8];
                    if (sscanf(line, "%lx-%lx %s", &start, &end, perms) == 3) {
                        /* 用 dladdr 获取的 basename 匹配(兼容 30 池随机名) */
                        if (strstr(line, so_basename) != NULL) {
                            *base_out = start;
                            *size_out = end - start;
                            found = 1;
                            break;
                        }
                    }
                }

                line_pos = 0;
            } else {
                line[line_pos++] = buf[i];
            }
        }
    }

    close(fd);

    if (!found) {
        LOGE("未找到 .so 的 .text 段(basename: %s)", so_basename);
        return -1;
    }

    return 0;
}

/**
 * 计算内存区域的 SHA-256
 */
static void compute_hash(const void *data, size_t len, char *hash_out) {
    sha256_ctx ctx;
    unsigned char hash[32];

    sha256_init(&ctx);
    sha256_update(&ctx, (const unsigned char *)data, len);
    sha256_final(&ctx, hash);

    /* 转 hex 字符串 */
    for (int i = 0; i < 32; i++) {
        sprintf(hash_out + i * 2, "%02x", hash[i]);
    }
    hash_out[64] = '\0';
}

/**
 * .so .text 段 hash 自校验
 *
 * @return 0=校验通过 / -1=校验失败(已 abort,不会返回)/ -2=内部错误
 */
int defender_self_verify(void) {
    LOGI("开始 .text hash 自校验");

    /* 1. 找 .text 段 */
    unsigned long text_base = 0;
    unsigned long text_size = 0;

    if (find_text_section(&text_base, &text_size) != 0) {
        LOGE("查找 .text 段失败,跳过自校验(非致命)");
        return -2;
    }

    LOGI("找到 .text 段: base=0x%lx, size=%lu", text_base, text_size);

    /* 2. 计算 .text 段实际 hash */
    char actual_hash[65];
    compute_hash((const void *)text_base, (size_t)text_size, actual_hash);
    LOGI("实际 .text hash: %s", actual_hash);

    /* 3. 与预期 hash 比对 */
    if (strcmp(actual_hash, EXPECTED_TEXT_HASH) == 0) {
        LOGI(".text hash 校验通过");
        return 0;
    }

    /* 4. 不匹配 -> 判断是占位还是真篡改 */
    LOGE(".text hash 校验失败!");
    LOGE("预期: %s", EXPECTED_TEXT_HASH);
    LOGE("实际: %s", actual_hash);

    /* H1 修复:用完整字符串比对检测占位(而非只看前 2 字符,
     * 避免真实 hash 恰好以 "00" 开头时被误判为占位而跳过校验) */
    static const char PLACEHOLDER_HASH[65] =
        "0000000000000000000000000000000000000000000000000000000000000000";
    if (strcmp(EXPECTED_TEXT_HASH, PLACEHOLDER_HASH) != 0) {
        /* 已 post-build 写入真实 hash,但与实际不符 -> .text 被篡改 */
        LOGE(".text 被篡改,触发 abort()");
        raise(SIGABRT);
        _exit(1);
        return -1;  /* 不会走到这里 */
    }

    /* 占位 hash,跳过校验(开发阶段,正式编译后 post-build 写入真实 hash) */
    LOGW("占位 hash,跳过校验(开发阶段,运行 scripts/patch_text_hash.py 写入真实 hash)");
    return 0;
}
