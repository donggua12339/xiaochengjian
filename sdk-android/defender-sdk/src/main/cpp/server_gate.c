/**
 * server_gate.c - 方案 C 客户端:服务端 gate 通信
 *
 * 详见 xcj_blue_demo_v2.1.1_prompt.md §方案 C
 *
 * 流程:
 *  1. Native 层计算签名哈希(方案 A 的 compute_apk_protected_hash)
 *  2. 用服务端公钥加密哈希(防篡改传输)
 *  3. POST /v1/integrity/verify 提交加密哈希 + nonce + timestamp
 *  4. 服务端比对白名单 -> 颁发短期 token
 *  5. 核心功能请求携带 token
 *
 * 注意:Native 层 HTTP 请求复杂(需 TLS),本文件只做 token 缓存与校验调度。
 * 实际 HTTP 请求由 Java 层 DefenderResponse/OkHttp 发起(已实现 warn 上报)。
 *
 * 本文件提供:
 *  - token 缓存(进程内)
 *  - token 有效性检查(过期时间)
 *  - 签名哈希加密(简化:base64,生产需 RSA)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <android/log.h>

#define TAG "DefenderServerGate"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ============= token 缓存(线程安全) ============= */

static char g_token[2048] = {0};
static time_t g_token_expire = 0;
static pthread_mutex_t g_token_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * 缓存服务端颁发的 token
 *
 * @param token JWT token 字符串
 * @param expire_ts 过期时间(Unix 时间戳,秒)
 */
void server_gate_set_token(const char *token, time_t expire_ts) {
    pthread_mutex_lock(&g_token_mutex);
    strncpy(g_token, token, sizeof(g_token) - 1);
    g_token[sizeof(g_token) - 1] = '\0';
    g_token_expire = expire_ts;
    pthread_mutex_unlock(&g_token_mutex);
    LOGI("token 已缓存,过期时间: %ld", (long)expire_ts);
}

/**
 * 获取当前缓存的 token
 *
 * @param out_token 输出:token 字符串(至少 2048 字节)
 * @return 0=有有效 token / -1=无 token 或已过期
 */
int server_gate_get_token(char *out_token, size_t out_size) {
    pthread_mutex_lock(&g_token_mutex);
    int result = -1;
    if (g_token[0] != '\0' && g_token_expire > time(NULL)) {
        strncpy(out_token, g_token, out_size - 1);
        out_token[out_size - 1] = '\0';
        result = 0;
    }
    pthread_mutex_unlock(&g_token_mutex);
    return result;
}

/**
 * 检查 token 是否有效(供核心功能调用前校验)
 *
 * @return 1=有效 / 0=无效或过期
 */
int server_gate_has_valid_token(void) {
    pthread_mutex_lock(&g_token_mutex);
    int valid = (g_token[0] != '\0' && g_token_expire > time(NULL)) ? 1 : 0;
    pthread_mutex_unlock(&g_token_mutex);
    return valid;
}

/**
 * 清除 token(校验失败或登出时调用)
 */
void server_gate_clear_token(void) {
    pthread_mutex_lock(&g_token_mutex);
    g_token[0] = '\0';
    g_token_expire = 0;
    pthread_mutex_unlock(&g_token_mutex);
    LOGI("token 已清除");
}

/* ============= 签名哈希加密(简化) ============= */

/**
 * 加密签名哈希(用于传输)
 *
 * 简化版:直接 base64 编码(开发模式,服务端 base64 解码)。
 * 生产版:用服务端 RSA 公钥加密(需嵌入公钥 + RSA 实现,复杂度高)。
 *
 * @param hash 32 字节签名哈希
 * @param out_base64 输出:base64 字符串(至少 64 字节)
 * @return 0=成功 / -1=失败
 */
int server_gate_encrypt_hash(const unsigned char hash[32], char *out_base64, size_t out_size) {
    static const char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    if (out_size < 48) return -1;  /* 32 字节 -> 44 字节 base64 + '\0' */

    int pos = 0;
    for (int i = 0; i < 32; i += 3) {
        unsigned int n = (unsigned int)hash[i] << 16;
        if (i + 1 < 32) n |= (unsigned int)hash[i + 1] << 8;
        if (i + 2 < 32) n |= (unsigned int)hash[i + 2];

        out_base64[pos++] = base64_chars[(n >> 18) & 0x3F];
        out_base64[pos++] = base64_chars[(n >> 12) & 0x3F];
        out_base64[pos++] = (i + 1 < 32) ? base64_chars[(n >> 6) & 0x3F] : '=';
        out_base64[pos++] = (i + 2 < 32) ? base64_chars[n & 0x3F] : '=';
    }
    out_base64[pos] = '\0';
    return 0;
}

/**
 * 生成 nonce(一次性随机数,防重放)
 *
 * @param out_nonce 输出:nonce 字符串(至少 33 字节,32 hex + '\0')
 */
void server_gate_generate_nonce(char *out_nonce, size_t out_size) {
    if (out_size < 33) {
        if (out_size > 0) out_nonce[0] = '\0';
        return;
    }

    /* 用 time + pid + 计数器生成伪随机(简化版,生产用 /dev/urandom) */
    static unsigned int counter = 0;
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)getpid() ^ counter++;

    for (int i = 0; i < 32; i++) {
        /* 简化 LCG 伪随机 */
        seed = seed * 1103515245 + 12345;
        out_nonce[i] = "0123456789abcdef"[(seed >> 16) & 0xF];
    }
    out_nonce[32] = '\0';
}
