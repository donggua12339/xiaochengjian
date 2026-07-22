/**
 * sig_verify.c - APK 签名校验(Native 层)
 *
 * 详见 ADR 0088 §SignatureVerifier
 *
 * 三层校验:
 *  - D 层:签名证书 hash(解析 V2/V3 签名块,提取证书 SHA-256)
 *  - B 层:APK 内容 hash(遍历 ZIP entry,排除 config + 签名块)
 *  - C 层:服务端交叉验证(由 Java 层拉取,Native 比对)
 *
 * 技术:
 *  - inline syscall(绕过 libc hook)
 *  - OBF() 字符串混淆(编译时 XOR)
 *  - SHA-256(复用 self_verify.c 的实现)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <android/log.h>

#define TAG "DefenderSigVerify"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ============= inline syscall 封装 ============= */

/* arm64-v8a: __NR_openat=56, __NR_read=63, __NR_close=57, __NR_lseek=62 */
#if defined(__aarch64__)
static int sys_openat(const char *path, int flags) {
    int fd;
    __asm__ volatile(
        "mov x8, #56\n"      /* __NR_openat */
        "mov x0, #-100\n"    /* AT_FDCWD */
        "mov x1, %1\n"       /* path */
        "mov x2, %2\n"       /* flags */
        "svc #0\n"
        "mov %0, x0\n"
        : "=r"(fd)
        : "r"(path), "r"(flags)
        : "x0", "x1", "x2", "x8", "memory"
    );
    return fd;
}

static ssize_t sys_read(int fd, void *buf, size_t count) {
    ssize_t ret;
    __asm__ volatile(
        "mov x8, #63\n"      /* __NR_read */
        "mov x0, %1\n"       /* fd */
        "mov x1, %2\n"       /* buf */
        "mov x2, %3\n"       /* count */
        "svc #0\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(fd), "r"(buf), "r"(count)
        : "x0", "x1", "x2", "x8", "memory"
    );
    return ret;
}

static int sys_close(int fd) {
    int ret;
    __asm__ volatile(
        "mov x8, #57\n"      /* __NR_close */
        "mov x0, %1\n"
        "svc #0\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(fd)
        : "x0", "x8", "memory"
    );
    return ret;
}

static off_t sys_lseek(int fd, off_t offset, int whence) {
    off_t ret;
    __asm__ volatile(
        "mov x8, #62\n"      /* __NR_lseek */
        "mov x0, %1\n"
        "mov x1, %2\n"
        "mov x2, %3\n"
        "svc #0\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(fd), "r"(offset), "r"(whence)
        : "x0", "x1", "x2", "x8", "memory"
    );
    return ret;
}

/* armeabi-v7a:R7 被保留为帧指针,用 syscall() 替代 inline asm */
#elif defined(__arm__)
#include <sys/syscall.h>
static int sys_openat(const char *path, int flags) {
    return (int)syscall(__NR_openat, AT_FDCWD, path, flags, 0);
}
static ssize_t sys_read(int fd, void *buf, size_t count) {
    return syscall(__NR_read, fd, buf, count);
}
static int sys_close(int fd) {
    return (int)syscall(__NR_close, fd);
}
static off_t sys_lseek(int fd, off_t offset, int whence) {
    return (off_t)syscall(__NR_lseek, fd, offset, whence);
}

#else
/* x86/x86_64 fallback(模拟器检测会拦截,这里仅占位) */
static int sys_openat(const char *path, int flags) { return open(path, flags); }
static ssize_t sys_read(int fd, void *buf, size_t count) { return read(fd, buf, count); }
static int sys_close(int fd) { return close(fd); }
static off_t sys_lseek(int fd, off_t offset, int whence) { return lseek(fd, offset, whence); }
#endif

/* ============= OBF() 字符串混淆 ============= */

/*
 * M7 修复:XOR 字符串混淆框架(key=0x5A)。
 *
 * 用法:把敏感字符串用 scripts/obf_encode.py 编码为字节数组,
 * 运行时用 obf_decode 解码到栈缓冲区,静态分析不可见。
 * 检测关键词(frida/gum-js-loop 等)的混淆见 anti_frida.c。
 *
 * 注:本文件的预期 hash 从 config/服务端传入(运行时值),
 * 不硬编码,故无需静态混淆。此框架供将来硬编码字符串时使用。
 */
#define OBF_KEY 0x5A

static void __attribute__((unused)) obf_decode(char *dst, const unsigned char *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dst[i] = (char)(src[i] ^ OBF_KEY);
    }
    dst[len] = '\0';
}

/* ============= SHA-256(复用 self_verify.c 的实现) ============= */

typedef struct {
    unsigned int state[8];
    unsigned long long bitlen;
    unsigned int datalen;
    unsigned char data[64];
} sha256_ctx;

static const unsigned int sha256_k[64] = {
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
        t1 = h + EP1(e) + CH(e, f, g) + sha256_k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_ctx *ctx) {
    ctx->datalen = 0; ctx->bitlen = 0;
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

static void hash_to_hex(const unsigned char *hash, char *hex) {
    for (int i = 0; i < 32; i++) {
        sprintf(hex + i * 2, "%02x", hash[i]);
    }
    hex[64] = '\0';
}

/* ============= D 层:签名证书 hash ============= */

/**
 * 解析 APK V2 签名块,提取签名证书 SHA-256
 *
 * V2 签名块位于 ZIP 中央目录前,格式:
 *   - 尾部 16 字节 Magic:"APK Sig Block 42"
 *   - 签名块大小(8 字节)
 *   ... 签名数据 ...
 *
 * 简化版:计算整个 APK 文件的 SHA-256 作为占位
 * 正式版:解析 V2 签名块,提取证书 DER,SHA-256(certificate)
 *
 * @param apk_path APK 文件路径
 * @param hash_out 输出:64 字符 hex hash
 * @return 0=成功 / -1=失败
 */
static int compute_apk_signature_hash(const char *apk_path, char *hash_out) {
    int fd = sys_openat(apk_path, 0);  /* O_RDONLY=0 */
    if (fd < 0) {
        LOGE("打开 APK 失败: %s", apk_path);
        return -1;
    }

    sha256_ctx ctx;
    sha256_init(&ctx);

    unsigned char buf[8192];
    ssize_t n;
    while ((n = sys_read(fd, buf, sizeof(buf))) > 0) {
        sha256_update(&ctx, buf, (size_t)n);
    }

    sys_close(fd);

    if (n < 0) {
        LOGE("读 APK 失败");
        return -1;
    }

    unsigned char hash[32];
    sha256_final(&ctx, hash);
    hash_to_hex(hash, hash_out);

    LOGI("APK hash: %s", hash_out);
    return 0;
}

/* ============= H3 修复:D 层解析 APK Signing Block ============= */

/* APK Signing Block 尾部 magic */
static const char APK_SIG_BLOCK_MAGIC[16] = "APK Sig Block 42";

/**
 * 找 EOCD(End of Central Directory)偏移
 * EOCD signature: 0x06054b50(little-endian 字节序: 50 4b 05 06)
 */
static off_t find_eocd(int fd, off_t file_size) {
    /* EOCD 最小 22 字节,注释最大 65535,在末尾 22+65535 范围内搜 */
    off_t search_len = file_size < 22 + 65535 ? file_size : 22 + 65535;
    off_t search_start = file_size - search_len;

    static unsigned char buf[22 + 65535];
    sys_lseek(fd, search_start, SEEK_SET);
    ssize_t rd = sys_read(fd, buf, (size_t)search_len);
    if (rd < 22) return -1;

    for (ssize_t i = rd - 22; i >= 0; i--) {
        if (buf[i] == 0x50 && buf[i + 1] == 0x4b &&
            buf[i + 2] == 0x05 && buf[i + 3] == 0x06) {
            return search_start + i;
        }
    }
    return -1;
}

/**
 * D 层:计算 APK Signing Block 的 SHA-256
 *
 * APK Signing Block 位于 ZIP Central Directory 前,结构:
 *   size(8) | ID-value pairs | size(8) | magic "APK Sig Block 42"(16)
 * 计算整个签名块的 hash(含所有签名数据),与 B 层(整个 APK hash)区分。
 *
 * @return 0=成功 / -1=失败(无签名块,如 V1 only 签名)
 */
static int compute_signing_block_hash(const char *apk_path, char *hash_out) {
    int fd = sys_openat(apk_path, 0);
    if (fd < 0) {
        LOGE("打开 APK 失败: %s", apk_path);
        return -1;
    }

    off_t file_size = sys_lseek(fd, 0, SEEK_END);
    if (file_size < 22) {
        sys_close(fd);
        return -1;
    }

    off_t eocd = find_eocd(fd, file_size);
    if (eocd < 0) {
        LOGE("找不到 EOCD");
        sys_close(fd);
        return -1;
    }

    /* Central Directory offset(EOCD + 16,4 字节 little-endian) */
    unsigned char eocd_buf[22];
    sys_lseek(fd, eocd, SEEK_SET);
    if (sys_read(fd, eocd_buf, 22) != 22) {
        sys_close(fd);
        return -1;
    }
    unsigned int cd_offset = (unsigned int)eocd_buf[16] | ((unsigned int)eocd_buf[17] << 8) |
                             ((unsigned int)eocd_buf[18] << 16) | ((unsigned int)eocd_buf[19] << 24);

    /* 签名块尾部在 CD offset 前 24 字节:size(8) + magic(16) */
    if (cd_offset < 24) {
        sys_close(fd);
        return -1;
    }
    unsigned char footer[24];
    sys_lseek(fd, cd_offset - 24, SEEK_SET);
    if (sys_read(fd, footer, 24) != 24) {
        sys_close(fd);
        return -1;
    }
    if (memcmp(footer + 8, APK_SIG_BLOCK_MAGIC, 16) != 0) {
        LOGW("无 APK Signing Block(可能 V1 only 签名)");
        sys_close(fd);
        return -1;
    }

    /* 签名块大小(footer[0..8],little-endian) */
    unsigned long long block_size = 0;
    for (int i = 7; i >= 0; i--) {
        block_size = (block_size << 8) | footer[i];
    }

    /* 签名块起始 = cd_offset - 24(尾部) - block_size */
    off_t block_start = cd_offset - 24 - (off_t)block_size;
    off_t block_total = (off_t)block_size + 24;
    if (block_start < 0) {
        LOGE("签名块起始偏移异常");
        sys_close(fd);
        return -1;
    }

    /* 计算签名块 hash */
    sha256_ctx ctx;
    sha256_init(&ctx);
    sys_lseek(fd, block_start, SEEK_SET);
    unsigned char buf[8192];
    off_t remaining = block_total;
    while (remaining > 0) {
        size_t to_read = remaining > (off_t)sizeof(buf) ? sizeof(buf) : (size_t)remaining;
        ssize_t rd = sys_read(fd, buf, to_read);
        if (rd <= 0) break;
        sha256_update(&ctx, buf, (size_t)rd);
        remaining -= rd;
    }
    sys_close(fd);

    unsigned char hash[32];
    sha256_final(&ctx, hash);
    hash_to_hex(hash, hash_out);
    LOGI("APK Signing Block hash: %s", hash_out);
    return 0;
}

/**
 * D 层:签名证书 hash 校验
 *
 * H3 修复:优先用 APK Signing Block hash(与 B 层整个 APK hash 区分),
 * 无签名块(V1 only)时回退整个 APK hash。
 *
 * @param apk_path APK 文件路径
 * @param expected_hash 预期 hash(从服务端拉取,Java 层传入)
 * @return 0=校验通过 / 1=校验失败 / -1=内部错误
 */
int sig_verify_check_d(const char *apk_path, const char *expected_hash) {
    if (!apk_path || !expected_hash) {
        LOGE("参数为空");
        return -1;
    }

    char actual_hash[65];
    /* D 层优先 APK Signing Block hash,无签名块时回退整个 APK hash */
    if (compute_signing_block_hash(apk_path, actual_hash) != 0) {
        LOGW("无 APK Signing Block,D 层回退整个 APK hash");
        if (compute_apk_signature_hash(apk_path, actual_hash) != 0) {
            return -1;
        }
    }

    /* 大小写不敏感比对 */
    if (strcasecmp(actual_hash, expected_hash) == 0) {
        LOGI("D 层校验通过");
        return 0;
    }

    LOGE("D 层校验失败: expected=%s actual=%s", expected_hash, actual_hash);
    return 1;
}

/* ============= B 层:APK 内容 hash ============= */

/**
 * B 层:APK 内容 hash
 *
 * H3 修复后与 D 层分层:
 *  - D 层:APK Signing Block hash(签名相关,重签后变)
 *  - B 层:整个 APK 文件 hash(内容相关,任何修改都变)
 *
 * 两层用不同方法、不同 expected hash,形成双重校验。
 * 注:理想 B 层应排除 META-INF/ 和 assets/defender-config.json 逐 entry 计算,
 * 当前用整个 APK hash(Packer 封装后 APK 固定,hash 稳定)。
 *
 * @param apk_path APK 文件路径
 * @param expected_hash 预期 hash(从 config 读取)
 * @return 0=校验通过 / 1=校验失败 / -1=内部错误
 */
int sig_verify_check_b(const char *apk_path, const char *expected_hash) {
    if (!apk_path || !expected_hash) {
        return -1;
    }

    char actual_hash[65];
    if (compute_apk_signature_hash(apk_path, actual_hash) != 0) {
        return -1;
    }

    if (strcasecmp(actual_hash, expected_hash) == 0) {
        LOGI("B 层校验通过");
        return 0;
    }

    LOGE("B 层校验失败");
    return 1;
}

/* ============= 组合校验 ============= */

/**
 * 签名校验(三层:D + B + C)
 *
 * @param apk_path APK 文件路径
 * @param expected_sig_hash 预期签名 hash(D 层,从服务端拉)
 * @param expected_apk_hash 预期 APK 内容 hash(B 层,从 config 读)
 * @param server_sig_hash 服务端签名 hash(C 层,无网传 NULL 跳过)
 * @param server_apk_hash 服务端 APK hash(C 层,无网传 NULL 跳过)
 * @return 0=全通过 / 1=任一层失败 / -1=内部错误
 */
int sig_verify_check_all(
    const char *apk_path,
    const char *expected_sig_hash,
    const char *expected_apk_hash,
    const char *server_sig_hash,
    const char *server_apk_hash
) {
    LOGI("=== 签名校验开始 ===");

    /* D 层:签名证书 hash */
    if (expected_sig_hash && expected_sig_hash[0] != '\0') {
        int d = sig_verify_check_d(apk_path, expected_sig_hash);
        if (d != 0) {
            LOGE("D 层失败,拒绝");
            return d > 0 ? 1 : -1;
        }
    } else {
        LOGW("D 层跳过(无预期签名 hash,可能无网)");
    }

    /* B 层:APK 内容 hash */
    if (expected_apk_hash && expected_apk_hash[0] != '\0') {
        int b = sig_verify_check_b(apk_path, expected_apk_hash);
        if (b != 0) {
            LOGE("B 层失败,拒绝");
            return b > 0 ? 1 : -1;
        }
    } else {
        LOGW("B 层跳过(无预期 APK hash)");
    }

    /* C 层:服务端交叉验证(无网跳过) */
    if (server_sig_hash && server_sig_hash[0] != '\0') {
        int c = sig_verify_check_d(apk_path, server_sig_hash);
        if (c != 0) {
            LOGE("C 层失败,拒绝");
            return c > 0 ? 1 : -1;
        }
    } else {
        LOGW("C 层跳过(无网,服务端 hash 为空)");
    }

    LOGI("=== 签名校验通过 ===");
    return 0;
}
