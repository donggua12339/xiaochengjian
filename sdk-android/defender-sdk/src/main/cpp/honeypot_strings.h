/**
 * honeypot_strings.h - 诱饵字符串(自动生成,请勿手动修改)
 * 由 build_honeypot.py 生成 | seed=20260728
 *
 * 这些字符串看起来像真实密钥/URL/配置,实际是无功能的诱饵。
 * 目的: 浪费攻击者静态分析时间。
 */
#ifndef HONEYPOT_STRINGS_H
#define HONEYPOT_STRINGS_H

#include <stdint.h>

/* 诱饵 API 密钥(看起来像真密钥,实际无功能) */
static volatile const char *const HONEYPOT_KEY_0 = "4fe34efa3c148793670389a403194d77";
static volatile const char *const HONEYPOT_KEY_1 = "4dd481c6b5be33fcbaa617ff9839c52b";
static volatile const char *const HONEYPOT_KEY_2 = "1b716e2d25e6d4740afcb6265996b447";

/* 诱饵 URL(看起来像服务器地址,实际不存在) */
static volatile const char *const HONEYPOT_URL_0 = "https://auth.xiaochengjian.io/api/key/validate";
static volatile const char *const HONEYPOT_URL_1 = "https://auth.xiaochengjian.io/api/key/validate";
static volatile const char *const HONEYPOT_URL_2 = "https://verify.defender-sdk.net/v2/license/check";

/* 诱饵配置 JSON(看起来像加密配置,实际是垃圾) */
static volatile const char *const HONEYPOT_CFG_0 = "{\"server\":\"https://key-server.xcj.cloud/sdk/activate\",\"key\":\"567bcf75abafc7918a9ad6b9f0abe020f96b47fc25964d7ff22365d6eaadfeb2\",\"salt\":\"9551c87ab3396621\",\"version\":2,\"debug\":false}";
static volatile const char *const HONEYPOT_CFG_1 = "{\"server\":\"https://auth.xiaochengjian.io/sdk/activate\",\"key\":\"bfdbae6694058d2c8f9a0e9f1889170fc5df1b952687dc97c0f640cdd0faeb80\",\"salt\":\"fe06114393129b94\",\"version\":2,\"debug\":false}";

static volatile const char *const HONEYPOT_RSA = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAa698d279de73748ade667a4e4b5ef1dee5a41c993bb4b9a6\n...";

/* 死引用: 确保诱饵字符串保留在 .rodata */
static volatile const void *const honeypot_anchors[] __attribute__((used)) = {
    (const void *)HONEYPOT_KEY_0,
    (const void *)HONEYPOT_KEY_1,
    (const void *)HONEYPOT_KEY_2,
    (const void *)HONEYPOT_URL_0,
    (const void *)HONEYPOT_URL_1,
    (const void *)HONEYPOT_URL_2,
    NULL
};

#endif /* HONEYPOT_STRINGS_H */
