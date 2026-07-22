/**
 * integrity.c - APK 完整性校验(5 层)
 *
 * 详见 ADR 0088 §IntegrityChecker
 *
 * 5 层校验:
 *  层 1:签名证书 hash(已在 sig_verify.c D 层)
 *  层 2:DEX CRC 逐文件校验(CRC 表内嵌 .rodata)
 *  层 3:.so self-verify(已在 self_verify.c)
 *  层 4:文件列表完整性(遍历 entry,检测额外/缺失文件)
 *  层 5:服务端联动(已在 sig_verify.c C 层)
 *
 * 本文件实现层 2 + 层 4
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <pthread.h>
#include <zlib.h>
#include <android/log.h>

#define TAG "DefenderIntegrity"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ============= inline syscall(复用模式) ============= */

#if defined(__aarch64__)
static int ic_openat(const char *path, int flags) {
    int fd;
    __asm__ volatile(
        "mov x8, #56\n"
        "mov x0, #-100\n"
        "mov x1, %1\n"
        "mov x2, %2\n"
        "svc #0\n"
        "mov %0, x0\n"
        : "=r"(fd)
        : "r"(path), "r"(flags)
        : "x0", "x1", "x2", "x8", "memory"
    );
    return fd;
}
static ssize_t ic_read(int fd, void *buf, size_t count) {
    ssize_t ret;
    __asm__ volatile(
        "mov x8, #63\n"
        "mov x0, %1\n"
        "mov x1, %2\n"
        "mov x2, %3\n"
        "svc #0\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(fd), "r"(buf), "r"(count)
        : "x0", "x1", "x2", "x8", "memory"
    );
    return ret;
}
static int ic_close(int fd) {
    int ret;
    __asm__ volatile(
        "mov x8, #57\n"
        "mov x0, %1\n"
        "svc #0\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(fd)
        : "x0", "x8", "memory"
    );
    return ret;
}
static off_t ic_lseek(int fd, off_t offset, int whence) {
    off_t ret;
    __asm__ volatile(
        "mov x8, #62\n"
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
#elif defined(__arm__)
#include <sys/syscall.h>
static int ic_openat(const char *path, int flags) {
    return (int)syscall(__NR_openat, AT_FDCWD, path, flags, 0);
}
static ssize_t ic_read(int fd, void *buf, size_t count) {
    return syscall(__NR_read, fd, buf, count);
}
static int ic_close(int fd) {
    return (int)syscall(__NR_close, fd);
}
static off_t ic_lseek(int fd, off_t offset, int whence) {
    return (off_t)syscall(__NR_lseek, fd, offset, whence);
}
#else
static int ic_openat(const char *path, int flags) { return open(path, flags); }
static ssize_t ic_read(int fd, void *buf, size_t count) { return read(fd, buf, count); }
static int ic_close(int fd) { return close(fd); }
static off_t ic_lseek(int fd, off_t offset, int whence) { return lseek(fd, offset, whence); }
#endif

/* ============= CRC32 实现 ============= */

static unsigned int crc32_table[256];
static pthread_once_t crc32_table_once = PTHREAD_ONCE_INIT;

static void init_crc32_table(void) {
    for (unsigned int i = 0; i < 256; i++) {
        unsigned int crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        crc32_table[i] = crc;
    }
}

static unsigned int compute_crc32(const unsigned char *data, size_t len) {
    pthread_once(&crc32_table_once, init_crc32_table);
    unsigned int crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ data[i]) & 0xFF];
    }
    return crc ^ 0xFFFFFFFF;
}

/* ============= H5 修复:ZIP Central Directory 遍历 ============= */

/* ZIP entry 信息(从 Central Directory File Header 解析) */
typedef struct {
    char name[256];
    unsigned int crc32;
    unsigned int comp_size;
    unsigned int uncomp_size;
    unsigned int local_offset;
} zip_entry_t;

/* 遍历回调:返回 0 继续,非 0 中止(并作为 zip_foreach_entry 返回值) */
typedef int (*zip_entry_cb)(const zip_entry_t *entry, void *ctx);

/**
 * 遍历 APK 的 Central Directory,对每个 entry 调用回调
 *
 * @return 0=遍历完成 / 非 0=回调中止或解析失败
 */
static int zip_foreach_entry(const char *apk_path, zip_entry_cb cb, void *ctx) {
    int fd = ic_openat(apk_path, 0);
    if (fd < 0) return -1;

    off_t file_size = ic_lseek(fd, 0, SEEK_END);
    if (file_size < 22) {
        ic_close(fd);
        return -1;
    }

    /* 找 EOCD(signature 0x06054b50,字节序 50 4b 05 06) */
    off_t search_len = file_size < 22 + 65535 ? file_size : 22 + 65535;
    off_t search_start = file_size - search_len;
    static unsigned char buf[22 + 65535];
    ic_lseek(fd, search_start, SEEK_SET);
    ssize_t rd = ic_read(fd, buf, (size_t)search_len);
    if (rd < 22) {
        ic_close(fd);
        return -1;
    }

    off_t eocd = -1;
    for (ssize_t i = rd - 22; i >= 0; i--) {
        if (buf[i] == 0x50 && buf[i + 1] == 0x4b &&
            buf[i + 2] == 0x05 && buf[i + 3] == 0x06) {
            eocd = search_start + i;
            break;
        }
    }
    if (eocd < 0) {
        ic_close(fd);
        return -1;
    }

    /* EOCD:total entries(10-11),CD offset(16-19) */
    unsigned char eocd_buf[22];
    ic_lseek(fd, eocd, SEEK_SET);
    if (ic_read(fd, eocd_buf, 22) != 22) {
        ic_close(fd);
        return -1;
    }
    unsigned int total_entries = (unsigned int)eocd_buf[10] | ((unsigned int)eocd_buf[11] << 8);
    unsigned int cd_offset = (unsigned int)eocd_buf[16] | ((unsigned int)eocd_buf[17] << 8) |
                             ((unsigned int)eocd_buf[18] << 16) | ((unsigned int)eocd_buf[19] << 24);

    /* 遍历 Central Directory File Header(signature 0x02014b50) */
    ic_lseek(fd, cd_offset, SEEK_SET);
    for (unsigned int i = 0; i < total_entries; i++) {
        unsigned char h[46];
        if (ic_read(fd, h, 46) != 46) break;
        if (h[0] != 0x50 || h[1] != 0x4b || h[2] != 0x01 || h[3] != 0x02) break;

        zip_entry_t entry;
        entry.crc32 = (unsigned int)h[16] | ((unsigned int)h[17] << 8) |
                      ((unsigned int)h[18] << 16) | ((unsigned int)h[19] << 24);
        entry.comp_size = (unsigned int)h[20] | ((unsigned int)h[21] << 8) |
                          ((unsigned int)h[22] << 16) | ((unsigned int)h[23] << 24);
        entry.uncomp_size = (unsigned int)h[24] | ((unsigned int)h[25] << 8) |
                            ((unsigned int)h[26] << 16) | ((unsigned int)h[27] << 24);
        unsigned int name_len = (unsigned int)h[28] | ((unsigned int)h[29] << 8);
        unsigned int extra_len = (unsigned int)h[30] | ((unsigned int)h[31] << 8);
        unsigned int comment_len = (unsigned int)h[32] | ((unsigned int)h[33] << 8);
        entry.local_offset = (unsigned int)h[42] | ((unsigned int)h[43] << 8) |
                             ((unsigned int)h[44] << 16) | ((unsigned int)h[45] << 24);

        if (name_len >= sizeof(entry.name)) name_len = sizeof(entry.name) - 1;
        if (ic_read(fd, entry.name, name_len) != (ssize_t)name_len) break;
        entry.name[name_len] = '\0';

        /* 跳过 extra + comment */
        ic_lseek(fd, (off_t)(extra_len + comment_len), SEEK_CUR);

        int ret = cb(&entry, ctx);
        if (ret != 0) {
            ic_close(fd);
            return ret;
        }
    }

    ic_close(fd);
    return 0;
}

/* ============= 层 3:MANIFEST.MF SHA-1 校验 ============= */

/* M6:预期 CRC 表 + 文件列表改为运行时从 defender-config.json 读取
 * (Packer 封装时生成),不再用 .rodata 编译时占位表。 */

/* --- SHA-1 实现(校验 MANIFEST.MF 中的 SHA1-Digest) --- */
typedef struct {
    unsigned int state[5];
    unsigned long long count;
    unsigned char buffer[64];
} sha1_ctx;

#define SHA1_ROL(v, b) (((v) << (b)) | ((v) >> (32 - (b))))

static void sha1_transform(unsigned int state[5], const unsigned char buffer[64]) {
    unsigned int a, b, c, d, e, w[80];
    for (int i = 0; i < 16; i++)
        w[i] = (buffer[i * 4] << 24) | (buffer[i * 4 + 1] << 16) |
               (buffer[i * 4 + 2] << 8) | buffer[i * 4 + 3];
    for (int i = 16; i < 80; i++)
        w[i] = SHA1_ROL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];
    for (int i = 0; i < 80; i++) {
        unsigned int f, k;
        if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }
        unsigned int t = SHA1_ROL(a, 5) + f + e + k + w[i];
        e = d; d = c; c = SHA1_ROL(b, 30); b = a; a = t;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

static void sha1_init(sha1_ctx *ctx) {
    ctx->state[0] = 0x67452301; ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE; ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
}

static void sha1_update(sha1_ctx *ctx, const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->buffer[ctx->count % 64] = data[i];
        ctx->count++;
        if (ctx->count % 64 == 0) sha1_transform(ctx->state, ctx->buffer);
    }
}

static void sha1_final(sha1_ctx *ctx, unsigned char digest[20]) {
    unsigned long long bits = ctx->count * 8;
    unsigned char pad = 0x80;
    sha1_update(ctx, &pad, 1);
    pad = 0x00;
    while (ctx->count % 64 != 56) sha1_update(ctx, &pad, 1);
    unsigned char lenbuf[8];
    for (int i = 0; i < 8; i++) lenbuf[i] = (unsigned char)(bits >> (56 - i * 8));
    sha1_update(ctx, lenbuf, 8);
    for (int i = 0; i < 5; i++) {
        digest[i * 4] = (unsigned char)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (unsigned char)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (unsigned char)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (unsigned char)(ctx->state[i]);
    }
}

/* --- base64 解码(MANIFEST.MF 的 SHA1-Digest 是 base64) --- */
static int base64_decode(const char *in, unsigned char *out, size_t *out_len) {
    static const int table[256] = {
        ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
        ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
        ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
        ['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,
        ['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,
        ['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,
        ['w']=48,['x']=49,['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,
        ['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63,
    };
    size_t in_len = strlen(in);
    size_t o = 0;
    for (size_t i = 0; i + 3 < in_len + 1 && in[i] != '='; ) {
        if (in[i] == '\n' || in[i] == '\r') { i++; continue; }
        unsigned int n = (table[(unsigned char)in[i]] << 18) |
                         (table[(unsigned char)in[i + 1]] << 12) |
                         (i + 2 < in_len && in[i + 2] != '=' ? table[(unsigned char)in[i + 2]] << 6 : 0) |
                         (i + 3 < in_len && in[i + 3] != '=' ? table[(unsigned char)in[i + 3]] : 0);
        out[o++] = (unsigned char)(n >> 16);
        if (i + 2 < in_len && in[i + 2] != '=') out[o++] = (unsigned char)(n >> 8);
        if (i + 3 < in_len && in[i + 3] != '=') out[o++] = (unsigned char)n;
        i += 4;
    }
    *out_len = o;
    return 0;
}

/**
 * 读取 APK 中指定 entry 的内容(自动解压 deflated)
 *
 * 扫描 local file header(signature 0x04034b50)匹配 entry 名,
 * compression method 8(deflated)用 zlib inflate 解压。
 *
 * @return 0=成功(需 free *data_out)/ -1=失败
 */
static int read_apk_entry(const char *apk_path, const char *entry_name,
                          unsigned char **data_out, size_t *size_out) {
    int fd = ic_openat(apk_path, 0);
    if (fd < 0) return -1;

    unsigned char hdr[30];
    off_t pos = 0;
    int found = 0;
    unsigned int comp_method = 0, comp_size = 0, uncomp_size = 0;

    /* 扫描 local file header */
    while (1) {
        if (ic_lseek(fd, pos, SEEK_SET) < 0) break;
        if (ic_read(fd, hdr, 30) != 30) break;
        /* signature 0x04034b50(little-endian: 50 4b 03 04) */
        if (hdr[0] != 0x50 || hdr[1] != 0x4b || hdr[2] != 0x03 || hdr[3] != 0x04) break;

        unsigned int name_len = hdr[26] | (hdr[27] << 8);
        unsigned int extra_len = hdr[28] | (hdr[29] << 8);
        char name[512];
        if (name_len >= sizeof(name)) name_len = sizeof(name) - 1;
        if (ic_read(fd, name, name_len) != (ssize_t)name_len) break;
        name[name_len] = '\0';

        comp_method = hdr[8] | (hdr[9] << 8);
        comp_size = hdr[18] | (hdr[19] << 8) | (hdr[20] << 16) | (hdr[21] << 24);
        uncomp_size = hdr[22] | (hdr[23] << 8) | (hdr[24] << 16) | (hdr[25] << 24);

        if (strcmp(name, entry_name) == 0) {
            /* 跳过 extra field,定位 data */
            off_t data_pos = pos + 30 + name_len + extra_len;
            ic_lseek(fd, data_pos, SEEK_SET);
            unsigned char *comp_data = (unsigned char *)malloc(comp_size);
            if (!comp_data) break;
            if (ic_read(fd, comp_data, comp_size) != (ssize_t)comp_size) {
                free(comp_data);
                break;
            }
            if (comp_method == 0) {
                /* stored */
                *data_out = comp_data;
                *size_out = comp_size;
            } else if (comp_method == 8) {
                /* deflated:zlib inflate(raw deflate,windowBits=-15) */
                unsigned char *uncomp = (unsigned char *)malloc(uncomp_size);
                if (!uncomp) { free(comp_data); break; }
                z_stream strm;
                memset(&strm, 0, sizeof(strm));
                strm.next_in = comp_data;
                strm.avail_in = comp_size;
                strm.next_out = uncomp;
                strm.avail_out = uncomp_size;
                if (inflateInit2(&strm, -15) != Z_OK) { free(comp_data); free(uncomp); break; }
                int ret = inflate(&strm, Z_FINISH);
                inflateEnd(&strm);
                free(comp_data);
                if (ret != Z_STREAM_END && ret != Z_OK) { free(uncomp); break; }
                *data_out = uncomp;
                *size_out = uncomp_size;
            } else {
                free(comp_data);
                break;
            }
            found = 1;
            break;
        }
        /* 跳到下一个 local header */
        pos = pos + 30 + name_len + extra_len + comp_size;
    }
    ic_close(fd);
    return found ? 0 : -1;
}

/**
 * 层 3:MANIFEST.MF 中 classes.dex 的 SHA-1 校验
 *
 * 读取 META-INF/MANIFEST.MF,解析 classes.dex 的 SHA1-Digest(base64),
 * 读取 classes.dex 计算实际 SHA-1,比对。
 * DEX 被修改但未更新 MANIFEST.MF 时,SHA-1 不符 → 检测到篡改。
 *
 * @return 0=校验通过 / 1=校验失败 / -1=内部错误(如 V2 only 无 MANIFEST.MF)
 */
static int integrity_check_manifest(const char *apk_path) {
    LOGI("=== 层 3:MANIFEST.MF SHA-1 校验 ===");

    unsigned char *manifest_data = NULL;
    size_t manifest_size = 0;
    if (read_apk_entry(apk_path, "META-INF/MANIFEST.MF", &manifest_data, &manifest_size) != 0) {
        LOGW("无 META-INF/MANIFEST.MF(可能 V2/V3 only 签名),层 3 跳过");
        return -1;
    }

    /* 在 MANIFEST.MF 中找 classes.dex 的 SHA1-Digest */
    char *manifest_str = (char *)malloc(manifest_size + 1);
    memcpy(manifest_str, manifest_data, manifest_size);
    manifest_str[manifest_size] = '\0';
    free(manifest_data);

    /* 定位 "Name: classes.dex" 段落 */
    char *dex_section = strstr(manifest_str, "Name: classes.dex");
    if (!dex_section) {
        LOGW("MANIFEST.MF 无 classes.dex 条目,层 3 跳过");
        free(manifest_str);
        return -1;
    }

    /* 找该段落的 SHA1-Digest */
    char *sha1_line = strstr(dex_section, "SHA1-Digest:");
    if (!sha1_line) {
        LOGW("classes.dex 无 SHA1-Digest,层 3 跳过");
        free(manifest_str);
        return -1;
    }
    sha1_line += strlen("SHA1-Digest:");
    while (*sha1_line == ' ') sha1_line++;
    char expected_b64[64] = {0};
    int ei = 0;
    while (sha1_line[ei] && sha1_line[ei] != '\n' && sha1_line[ei] != '\r' && ei < 63) {
        expected_b64[ei] = sha1_line[ei];
        ei++;
    }
    expected_b64[ei] = '\0';
    free(manifest_str);

    /* base64 解码预期 SHA-1 */
    unsigned char expected_sha1[20];
    size_t expected_len = 0;
    base64_decode(expected_b64, expected_sha1, &expected_len);
    if (expected_len != 20) {
        LOGW("SHA1-Digest 解码失败(len=%zu),层 3 跳过", expected_len);
        return -1;
    }

    /* 读取 classes.dex,计算实际 SHA-1 */
    unsigned char *dex_data = NULL;
    size_t dex_size = 0;
    if (read_apk_entry(apk_path, "classes.dex", &dex_data, &dex_size) != 0) {
        LOGW("读取 classes.dex 失败,层 3 跳过");
        return -1;
    }

    sha1_ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, dex_data, dex_size);
    unsigned char actual_sha1[20];
    sha1_final(&ctx, actual_sha1);
    free(dex_data);

    if (memcmp(expected_sha1, actual_sha1, 20) == 0) {
        LOGI("层 3 校验通过(classes.dex SHA-1 匹配)");
        return 0;
    }
    LOGE("层 3 校验失败: classes.dex SHA-1 不匹配(DEX 被篡改)");
    return 1;
}

/* ============= 层 2:DEX CRC 逐文件校验 ============= */

/* ============= M6:JSON 字符串数组解析(从 config 读预期表) ============= */

/**
 * 解析 JSON 字符串数组(如 ["a:b","c"])为动态分配的 C 字符串数组
 * @return 数组(需 free_json_array 释放),空数组返回 NULL
 */
static char **parse_json_array(const char *json, int *count_out) {
    *count_out = 0;
    if (!json) return NULL;

    /* 第一遍:数元素个数 */
    int count = 0;
    const char *p = json;
    while (*p) {
        if (*p == '"') {
            count++;
            p++;
            while (*p && *p != '"') {
                if (*p == '\\') p++;
                p++;
            }
            if (*p == '"') p++;
        } else {
            p++;
        }
    }
    if (count == 0) return NULL;

    char **arr = (char **)malloc(sizeof(char *) * (size_t)count);
    if (!arr) return NULL;

    /* 第二遍:提取每个元素 */
    int idx = 0;
    p = json;
    while (*p && idx < count) {
        if (*p == '"') {
            p++;
            const char *start = p;
            while (*p && *p != '"') {
                if (*p == '\\') p++;
                p++;
            }
            size_t len = (size_t)(p - start);
            arr[idx] = (char *)malloc(len + 1);
            if (!arr[idx]) break;
            memcpy(arr[idx], start, len);
            arr[idx][len] = '\0';
            idx++;
            if (*p == '"') p++;
        } else {
            p++;
        }
    }

    *count_out = idx;
    return arr;
}

static void free_json_array(char **arr, int count) {
    if (!arr) return;
    for (int i = 0; i < count; i++) free(arr[i]);
    free(arr);
}

/* 层 2 回调上下文(M6:预期表从 config 传入) */
typedef struct {
    char **crc_table;  /* 每项 "entry名:crc32hex" */
    int crc_count;
    int checked;       /* 已校验的 .dex 数 */
    int mismatch;      /* 不匹配数 */
} crc_ctx_t;

/* 在预期表中查 entry 的 CRC,返回 1=找到且匹配 / 0=找到但不匹配 / -1=未找到 */
static int lookup_expected_crc(crc_ctx_t *c, const char *name, unsigned int crc) {
    char crc_str[9];
    snprintf(crc_str, sizeof(crc_str), "%08x", crc);
    for (int i = 0; i < c->crc_count; i++) {
        const char *colon = strchr(c->crc_table[i], ':');
        if (!colon) continue;
        size_t name_len = (size_t)(colon - c->crc_table[i]);
        if (strlen(name) == name_len && strncmp(name, c->crc_table[i], name_len) == 0) {
            return strcasecmp(colon + 1, crc_str) == 0 ? 1 : 0;
        }
    }
    return -1;
}

static int crc_check_cb(const zip_entry_t *entry, void *ctx) {
    crc_ctx_t *c = (crc_ctx_t *)ctx;
    size_t len = strlen(entry->name);
    /* 只校验 .dex 文件 */
    if (len >= 4 && strcasecmp(entry->name + len - 4, ".dex") == 0) {
        int r = lookup_expected_crc(c, entry->name, entry->crc32);
        if (r == 0) {
            LOGE("层 2 CRC 不匹配: %s", entry->name);
            c->mismatch++;
        } else if (r == 1) {
            c->checked++;
        }
        /* r == -1:预期表无此项,跳过 */
    }
    return 0;
}

/**
 * 层 2:DEX CRC 逐文件校验
 *
 * M6:预期 CRC 表从 config 传入(JSON 数组),遍历 APK 每个 .dex 比对 ZIP CRC32。
 * 预期表为空时跳过。
 *
 * @return 0=校验通过 / 1=校验失败 / -1=内部错误
 */
static int integrity_check_crc(const char *apk_path, const char *crc_table_json) {
    LOGI("=== 层 2:DEX CRC 校验 ===");

    crc_ctx_t ctx;
    ctx.crc_table = parse_json_array(crc_table_json, &ctx.crc_count);
    ctx.checked = 0;
    ctx.mismatch = 0;

    if (ctx.crc_count == 0) {
        LOGW("层 2 预期 CRC 表为空,跳过");
        free_json_array(ctx.crc_table, ctx.crc_count);
        return 0;
    }

    int r = zip_foreach_entry(apk_path, crc_check_cb, &ctx);
    free_json_array(ctx.crc_table, ctx.crc_count);
    if (r < 0) {
        LOGE("层 2 ZIP 解析失败");
        return -1;
    }

    LOGI("层 2 校验完成: checked=%d mismatch=%d", ctx.checked, ctx.mismatch);
    return ctx.mismatch > 0 ? 1 : 0;
}

/* ============= 层 4:文件列表完整性 ============= */

/**
 * 文件类型分类(决定 kill/warn)
 */
typedef enum {
    FILE_TYPE_KILL,      /* .so / .dex -> kill */
    FILE_TYPE_WARN,      /* .jar / 其他 -> warn */
    FILE_TYPE_IGNORE,    /* META-INF -> 忽略 */
} file_response_t;

static file_response_t classify_extra_file(const char *name) {
    /* 签名文件:忽略 */
    if (strncmp(name, "META-INF/", 9) == 0) {
        return FILE_TYPE_IGNORE;
    }

    /* 可执行代码:kill */
    size_t len = strlen(name);
    if (len >= 4 && strcasecmp(name + len - 4, ".so") == 0) {
        return FILE_TYPE_KILL;
    }
    if (len >= 4 && strcasecmp(name + len - 4, ".dex") == 0) {
        return FILE_TYPE_KILL;
    }

    /* .jar:warn(可含 dex,但可能是资源包) */
    if (len >= 4 && strcasecmp(name + len - 4, ".jar") == 0) {
        return FILE_TYPE_WARN;
    }

    /* 其他:warn */
    return FILE_TYPE_WARN;
}

/* 层 4 回调上下文(M6:预期文件列表从 config 传入) */
typedef struct {
    char **file_list;  /* 每项一个 entry 名 */
    int file_count;
    int has_kill;
    int has_warn;
} filelist_ctx_t;

static int in_expected_file_list(filelist_ctx_t *c, const char *name) {
    for (int i = 0; i < c->file_count; i++) {
        if (strcmp(c->file_list[i], name) == 0) return 1;
    }
    return 0;
}

static int filelist_check_cb(const zip_entry_t *entry, void *ctx) {
    filelist_ctx_t *c = (filelist_ctx_t *)ctx;
    if (in_expected_file_list(c, entry->name)) return 0;  /* 在预期列表,OK */

    /* 额外文件,按类型分类 */
    file_response_t resp = classify_extra_file(entry->name);
    if (resp == FILE_TYPE_KILL) {
        LOGE("层 4 额外可执行文件: %s", entry->name);
        c->has_kill = 1;
    } else if (resp == FILE_TYPE_WARN) {
        LOGW("层 4 额外文件: %s", entry->name);
        c->has_warn = 1;
    }
    /* FILE_TYPE_IGNORE(META-INF 签名文件):忽略 */
    return 0;
}

/**
 * 层 4:文件列表完整性
 *
 * M6:预期文件列表从 config 传入(JSON 数组),遍历 APK entry 检测额外文件,
 * 按类型分类(.so/.dex -> kill,.jar/其他 -> warn,META-INF -> 忽略)。
 * 预期列表为空时跳过。
 *
 * @return 0=安全 / 1=kill(额外 .so/.dex)/ 2=warn(额外资源)/ -1=内部错误
 */
static int integrity_check_file_list(const char *apk_path, const char *file_list_json) {
    LOGI("=== 层 4:文件列表完整性 ===");

    filelist_ctx_t ctx;
    ctx.file_list = parse_json_array(file_list_json, &ctx.file_count);
    ctx.has_kill = 0;
    ctx.has_warn = 0;

    if (ctx.file_count == 0) {
        LOGW("层 4 预期文件列表为空,跳过");
        free_json_array(ctx.file_list, ctx.file_count);
        return 0;
    }

    int r = zip_foreach_entry(apk_path, filelist_check_cb, &ctx);
    free_json_array(ctx.file_list, ctx.file_count);
    if (r < 0) {
        LOGE("层 4 ZIP 解析失败");
        return -1;
    }

    if (ctx.has_kill) return 1;  /* kill */
    if (ctx.has_warn) return 2;  /* warn */
    return 0;
}

/* ============= 组合校验(层 2 + 层 4) ============= */

/**
 * 完整性校验(层 2 + 层 4)
 *
 * 层 1(签名证书 hash)+ 层 3(.so self-verify)+ 层 5(服务端)由其他模块处理
 *
 * M6:预期表从 config 传入(Packer 封装时生成)
 *
 * @param apk_path        APK 文件路径
 * @param crc_table_json  预期 CRC 表 JSON 数组
 * @param file_list_json  预期文件列表 JSON 数组
 * @return 0=安全 / 1=kill / 2=warn / -1=内部错误
 */
int integrity_check(const char *apk_path, const char *crc_table_json, const char *file_list_json) {
    LOGI("=== IntegrityChecker(层 2 + 层 3 + 层 4)===");

    /* 层 2:CRC */
    int crc_result = integrity_check_crc(apk_path, crc_table_json);
    if (crc_result == 1) {
        LOGE("层 2 CRC 校验失败");
        return 1;  /* kill */
    }

    /* 层 3:MANIFEST.MF SHA-1(V1 签名时存在 MANIFEST.MF,V2/V3 only 时跳过) */
    int manifest_result = integrity_check_manifest(apk_path);
    if (manifest_result == 1) {
        LOGE("层 3 MANIFEST.MF SHA-1 校验失败(DEX 被篡改)");
        return 1;  /* kill */
    }

    /* 层 4:文件列表 */
    int list_result = integrity_check_file_list(apk_path, file_list_json);
    if (list_result == 1) {
        LOGE("层 4 检测到额外 .so/.dex");
        return 1;  /* kill */
    }
    if (list_result == 2) {
        LOGW("层 4 检测到额外资源/配置");
        return 2;  /* warn */
    }

    LOGI("IntegrityChecker 通过(层 2 + 层 3 + 层 4)");
    return 0;
}
