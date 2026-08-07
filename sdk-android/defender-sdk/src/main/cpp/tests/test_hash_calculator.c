/*
 * test_hash_calculator.c - 方案 A hash 链路宿主自测
 *
 * 与 scripts/patch_apk_hash.py 跨语言对账:C 端 compute_segment_digest /
 * compute_apk_protected_hash / find_so_exclude_ranges 的输出必须与 Python
 * 端逐字节一致。参考向量由 Python 端生成(见各用例注释)。
 *
 * 编译(在 tests/ 目录;hash_calculator.c 经 #include 并入以访问 static 函数):
 *   gcc -O2 -DNDEBUG -Ihost -I.. -o t_hash test_hash_calculator.c \
 *       ../integrity.c ../hash_storage.c -lz -lpthread
 * 运行: ./t_hash(退出码=失败数)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* 直接并入被测 .c 以访问 static 函数(单翻译单元测试模式) */
#include "../hash_calculator.c"

static int g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("FAIL: %s\n", msg); g_fail++; } } while (0)

static void hex_of(const uint8_t *d, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) sprintf(out + i * 2, "%02x", d[i]);
    out[n * 2] = '\0';
}

/* ---- 构造与 Python 同源的确定性数据 ---- */

static uint8_t *make_pattern(size_t n, uint8_t mul, uint8_t add) {
    uint8_t *p = (uint8_t *)malloc(n);
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(((size_t)i * mul + add) & 0xff);
    return p;
}

/* ZIP 合成助手(与 Python 生成器逐字段一致) */
static size_t put_le16(uint8_t *p, uint16_t v) { p[0]=v&0xff; p[1]=(v>>8)&0xff; return 2; }
static size_t put_le32(uint8_t *p, uint32_t v) {
    p[0]=v&0xff; p[1]=(v>>8)&0xff; p[2]=(v>>16)&0xff; p[3]=(v>>24)&0xff; return 4;
}
static size_t put_le64(uint8_t *p, uint64_t v) {
    put_le32(p, (uint32_t)(v & 0xffffffff)); put_le32(p + 4, (uint32_t)(v >> 32)); return 8;
}

/* local file header + data;返回总长 */
static size_t build_local(uint8_t *out, const char *name, const uint8_t *data, size_t dlen) {
    size_t n = strlen(name);
    uint8_t *p = out;
    memcpy(p, "PK\x03\x04", 4); p += 4;
    p += put_le16(p, 20);      /* version */
    p += put_le16(p, 0);       /* flags */
    p += put_le16(p, 0);       /* method */
    p += put_le16(p, 0);       /* time */
    p += put_le16(p, 0);       /* date */
    p += put_le32(p, 0x11223344); /* crc */
    p += put_le32(p, (uint32_t)dlen); /* comp */
    p += put_le32(p, (uint32_t)dlen); /* uncomp */
    p += put_le16(p, (uint16_t)n);    /* name len */
    p += put_le16(p, 0);              /* extra len */
    memcpy(p, name, n); p += n;
    memcpy(p, data, dlen); p += dlen;
    return (size_t)(p - out);
}

/* central directory entry;返回总长 */
static size_t build_cd(uint8_t *out, const char *name, size_t dlen, uint32_t local_off) {
    size_t n = strlen(name);
    uint8_t *p = out;
    memcpy(p, "PK\x01\x02", 4); p += 4;
    p += put_le16(p, 20); p += put_le16(p, 20); /* versions */
    p += put_le16(p, 0); p += put_le16(p, 0); p += put_le16(p, 0); p += put_le16(p, 0);
    p += put_le32(p, 0x11223344);
    p += put_le32(p, (uint32_t)dlen); p += put_le32(p, (uint32_t)dlen);
    p += put_le16(p, (uint16_t)n);
    p += put_le16(p, 0); p += put_le16(p, 0); p += put_le16(p, 0); p += put_le16(p, 0);
    /* ↑ extra_len / comment_len / disk# / int_attr 四个 H 字段 */
    p += put_le32(p, 0);               /* ext attr */
    p += put_le32(p, local_off);
    memcpy(p, name, n); p += n;
    return (size_t)(p - out);
}

int main(void) {
    char hex[65];
    uint8_t digest[32];

    /* ===== 1. compute_segment_digest 跨语言 KAT ===== */

    /* v1: 1KB 单块(bytes(range(256))*4) */
    {
        uint8_t *d1 = make_pattern(1024, 1, 0); /* (i*1+0)&0xff == i&0xff == bytes(range(256))*4 */
        compute_segment_digest(d1, 0, 1024, -1, 0, digest);
        hex_of(digest, 32, hex);
        CHECK(strcmp(hex, "94dd7cfacaac1846f21f79813a4f5c4e"
                          "917fad05a2e6899e7333af42a23855e3") == 0,
              "v1 small 1k digest 与 Python 一致");
        free(d1);
    }

    /* v2: 恰好 1MB(单块边界) */
    {
        uint8_t *d2 = make_pattern(1024 * 1024, 31, 7);
        compute_segment_digest(d2, 0, 1024 * 1024, -1, 0, digest);
        hex_of(digest, 32, hex);
        CHECK(strcmp(hex, "881a86bfa19bc3936e193de2d5d68582"
                          "f78912497e3e3b2406cb36bfb24cd31c") == 0,
              "v2 exact 1MB digest 与 Python 一致");
        free(d2);
    }

    /* v3: 1MB+1000(跨块)+ v4: patch 于 chunk0 尾 4 字节 + v6: patch 于 chunk1 内部。
     * 注:patch 偏移在实际场景(EOCD 区段)恒为小区段单块,不跨块;
     * Python 参考实现在 patch 跨块时行为未定义,故测试不取跨界偏移。 */
    {
        uint8_t *d3 = make_pattern(1024 * 1024 + 1000, 17, 3);
        compute_segment_digest(d3, 0, 1024 * 1024 + 1000, -1, 0, digest);
        hex_of(digest, 32, hex);
        CHECK(strcmp(hex, "33b37c7c673e3c366989b313b646d2f7"
                          "fc87c0f5ccd1320d91fd17d2cd56d387") == 0,
              "v3 cross-chunk digest 与 Python 一致");

        compute_segment_digest(d3, 0, 1024 * 1024 + 1000, 1024 * 1024 - 4, 0xDEADBEEF, digest);
        hex_of(digest, 32, hex);
        CHECK(strcmp(hex, "6b56210301baee69f26ff0cb2a634309"
                          "baaa93c0754d6d743c13258ab1327033") == 0,
              "v4 patched(chunk0 尾)digest 与 Python 一致");

        compute_segment_digest(d3, 0, 1024 * 1024 + 1000, 1024 * 1024 + 100, 0x01020304, digest);
        hex_of(digest, 32, hex);
        CHECK(strcmp(hex, "683658a3e819f06d1ef6af1f40e98ac3"
                          "53e93dc8902a04b4616f12dc674837f5") == 0,
              "v6 patched(chunk1 内)digest 与 Python 一致");
        free(d3);
    }

    /* v5: 空段 */
    {
        compute_segment_digest(NULL, 0, 0, -1, 0, digest);
        hex_of(digest, 32, hex);
        CHECK(strcmp(hex, "1043190b67a6bc391c83a3770c7c1fc5"
                          "1f694c6326bfc07b2b5cdc2f2732c4e0") == 0,
              "v5 empty segment digest 与 Python 一致");
    }

    /* ===== 2. 合成 APK 的 compute_apk_protected_hash(含 SO 排除) ===== */
    /* Python 参考(排除生效): b71d63fb762a6eb9a722594a9f0e1c39ddc8bb3eb8d3489501f9ee874e25ca3b
     * 不排除时为 8e665cae...(证明排除路径真实参与)。 */
    {
        uint8_t *so_data = make_pattern(3000, 13, 5);
        uint8_t *asset_data = make_pattern(500, 7, 1);

        static uint8_t apk[16384];
        size_t e1 = build_local(apk, "lib/arm64-v8a/libxcj_defender.so", so_data, 3000);
        size_t e2 = build_local(apk + e1, "assets/app.bin", asset_data, 500);
        size_t seg1 = e1 + e2;

        /* signing block: u64(200) + pairs + u64(200) + magic */
        size_t bs = seg1;
        put_le64(apk + bs, 200);
        for (int i = 0; i < 200; i++) apk[bs + 8 + i] = (uint8_t)((i * 3) & 0xff);
        put_le64(apk + bs + 8 + 200, 200);
        memcpy(apk + bs + 16 + 200, "APK Sig Block 42", 16);
        size_t block_total = 8 + 200 + 8 + 16; /* 232 */
        size_t cd_off = bs + block_total;

        /* CD */
        size_t c1 = build_cd(apk + cd_off, "lib/arm64-v8a/libxcj_defender.so", 3000, 0);
        size_t c2 = build_cd(apk + cd_off + c1, "assets/app.bin", 500, (uint32_t)e1);
        size_t cd_len = c1 + c2;

        /* EOCD */
        uint8_t *eo = apk + cd_off + cd_len;
        memcpy(eo, "PK\x05\x06", 4);
        put_le16(eo + 4, 0); put_le16(eo + 6, 0);
        put_le16(eo + 8, 2); put_le16(eo + 10, 2);
        put_le32(eo + 12, (uint32_t)cd_len);
        put_le32(eo + 16, (uint32_t)cd_off);
        put_le16(eo + 20, 0);
        size_t apk_size = cd_off + cd_len + 22;

        /* 排除范围应找到 defender 的 CD + local 两个条目 */
        exclude_range ranges[8];
        int rc = find_so_exclude_ranges(apk, apk_size, cd_off, cd_len, ranges, 8);
        CHECK(rc == 2, "排除范围应含 defender 的 local+CD 两条");

        /* 按生产 locate_signing_block 语义计算 block 参数:
         *   footer = cd_off-24;size_field=u64(footer);block_total=size_field+24;
         *   block_start=cd_off-24-size_field。与 Python 参考实现一致。 */
        size_t footer = cd_off - 24;
        uint64_t size_field = 0;
        for (int i = 0; i < 8; i++) size_field |= (uint64_t)apk[footer + i] << (8 * i);
        size_t blk_total = (size_t)size_field + 24;
        size_t blk_start = cd_off - 24 - (size_t)size_field;

        uint8_t h[32];
        int r = compute_apk_protected_hash(apk, apk_size, blk_start, blk_total, h);
        CHECK(r == 0, "compute_apk_protected_hash 应成功");
        hex_of(h, 32, hex);
        CHECK(strcmp(hex, "b71d63fb762a6eb9a722594a9f0e1c39" "ddc8bb3eb8d3489501f9ee874e25ca3b") == 0,
              "合成 APK 受保护 hash 与 Python 一致");

        free(so_data); free(asset_data);
    }

    if (g_fail == 0) printf("ALL PASS\n");
    else printf("%d FAILURES\n", g_fail);
    return g_fail;
}
