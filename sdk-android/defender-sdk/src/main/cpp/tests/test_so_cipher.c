/*
 * test_so_cipher.c - so_cipher.h 宿主自测(X0 RC4 + 魔数框架)
 *
 * 编译:gcc -O2 -I.. -o t test_so_cipher.c && ./t
 * 与 ../scripts/so_cipher.py 的 frame()/extract() 同义(此处内嵌构造向量,
 * 验证 C 端 so_cipher_extract 与 py 端加密互逆)。
 */
#include "so_cipher.h"
#include <stdio.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("FAIL: %s\n", msg); g_fail++; } } while (0)

/* 与 so_cipher.py frame() 同义:host 端构造 [密文][MAGIC][len] 框架 */
static size_t py_frame(const uint8_t *plain, size_t plen, const uint8_t *key, size_t klen,
                       uint8_t *out) {
    so_rc4_ctx rc4;
    so_rc4_init(&rc4, key, klen);
    so_rc4_crypt(&rc4, plain, out, plen);                       /* 密文 */
    memcpy(out + plen, SO_CIPHER_MAGIC, SO_CIPHER_MAGIC_LEN);   /* MAGIC */
    out[plen + 6] = (uint8_t)(plen & 0xff);                     /* len u32 LE */
    out[plen + 7] = (uint8_t)((plen >> 8) & 0xff);
    out[plen + 8] = (uint8_t)((plen >> 16) & 0xff);
    out[plen + 9] = (uint8_t)((plen >> 24) & 0xff);
    return plen + SO_CIPHER_TAILER_LEN;
}

int main(void) {
    const uint8_t key[] = "xcj-dev-key";
    const size_t klen = sizeof(key) - 1;

    /* 1. 往返:多种明文(含空串) */
    const char *samples[] = { "", "\x7f" "ELF fake so content", "A",
                              "secret-defender-so-bytes-1234567890" };
    for (int s = 0; s < 4; s++) {
        const uint8_t *p = (const uint8_t *)samples[s];
        size_t plen = strlen(samples[s]);
        uint8_t blob[512], dec[512];
        size_t blen = py_frame(p, plen, key, klen, blob);
        uint32_t dlen = 0;
        int r = so_cipher_extract(blob, blen, key, klen, dec, &dlen);
        CHECK(r == 0, "extract 应成功");
        CHECK(dlen == (uint32_t)plen, "长度一致");
        CHECK(plen == 0 || memcmp(dec, p, plen) == 0, "解密还原明文");
    }

    /* 2. 藏资源尾部(伪 webp 前缀)后仍可提取,且原资源完好 */
    {
        uint8_t res[512];
        memcpy(res, "RIFF\0\0WEBP", 8);
        for (int i = 8; i < 200; i++) res[i] = (uint8_t)(i * 7);
        const uint8_t *p = (const uint8_t *)"hidden-so-payload";
        size_t plen = strlen((const char *)p);
        uint8_t framed[512];
        size_t flen = py_frame(p, plen, key, klen, framed);
        memcpy(res + 200, framed, flen);

        uint8_t dec[512]; uint32_t dlen = 0;
        int r = so_cipher_extract(res, 200 + flen, key, klen, dec, &dlen);
        CHECK(r == 0, "藏资源后 extract 成功");
        CHECK(dlen == (uint32_t)plen && memcmp(dec, p, plen) == 0, "藏资源后还原明文");
        CHECK(memcmp(res, "RIFF\0\0WEBP", 8) == 0, "原资源前缀完好");

        /* so_cipher_locate 应定位到密文(不解密) */
        const uint8_t *ciph = NULL; uint32_t clen = 0;
        CHECK(so_cipher_locate(res, 200 + flen, &ciph, &clen) == 0, "locate 成功");
        CHECK(clen == (uint32_t)plen, "locate 长度一致");
        CHECK(ciph == res + 200, "locate 密文指针正确");
    }

    /* 3. 坏魔数 → -1 */
    {
        uint8_t bad[64]; memset(bad, 0x41, sizeof(bad));
        uint8_t dec[64]; uint32_t dlen;
        CHECK(so_cipher_extract(bad, sizeof(bad), key, klen, dec, &dlen) == -1,
              "坏魔数应返回 -1");
        CHECK(so_cipher_extract(bad, 4, key, klen, dec, &dlen) == -1,
              "过小缓冲应返回 -1");
    }

    /* 4. 长度越界(谎报 len)→ -1 */
    {
        uint8_t blob[64];
        size_t blen = py_frame((const uint8_t *)"x", 1, key, klen, blob);
        /* 把 trailer 里的 len 改成超大值 */
        blob[blen - 4] = 0xff; blob[blen - 3] = 0xff;
        blob[blen - 2] = 0xff; blob[blen - 1] = 0xff;
        uint8_t dec[64]; uint32_t dlen;
        CHECK(so_cipher_extract(blob, blen, key, klen, dec, &dlen) == -1,
              "长度越界应返回 -1");
    }

    /* 5. 错钥 → 解出不同 */
    {
        const uint8_t *p = (const uint8_t *)"secret";
        uint8_t blob[64], dec[64]; uint32_t dlen;
        size_t blen = py_frame(p, 6, key, klen, blob);
        so_cipher_extract(blob, blen, (const uint8_t *)"wrong-key", 9, dec, &dlen);
        CHECK(memcmp(dec, p, 6) != 0, "错钥应解出不同");
    }

    if (g_fail == 0) { printf("[test_so_cipher] ALL PASS\n"); return 0; }
    printf("[test_so_cipher] %d FAIL\n", g_fail);
    return 1;
}
