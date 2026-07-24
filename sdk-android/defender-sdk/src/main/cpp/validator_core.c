/**
 * validator_core.c - 核心校验调度(方案 A + B + C 入口)
 *
 * 详见 xcj_blue_demo_v2.1.1_prompt.md §方案选型
 *
 * 组合策略:
 *  方案 A(mmap + V2 自解析):对抗 NP IO 重定向
 *  方案 B(三角校验):对抗 MT IDA Pro 改 SO + 修改 DEX
 *  方案 C(服务端 gate):决定性防线(单独实现,本文件只做客户端调度)
 *
 * 校验流程:
 *  1. self_integrity_check()(方案 B:SO .text CRC)
 *  2. signature_verify_mmap()(方案 A:mmap + V2 自解析)
 *  3. dex_integrity_check()(方案 B:DEX CRC)
 *  任一失败 -> 响应(kill/warn)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>

#define TAG "DefenderValidatorCore"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ============= 外部函数声明 ============= */

/* 方案 A:mmap_reader.c */
extern int mmap_apk(const char *apk_path, void **out_mapped, size_t *out_size);
extern void mmap_apk_free(void *mapped, size_t size);

/* 方案 A:signing_block_parser.c */
extern int locate_signing_block(const uint8_t *data, size_t size,
                                size_t *out_block_start, size_t *out_block_size);

/* 方案 A:hash_calculator.c */
extern int compute_apk_protected_hash(const uint8_t *data, size_t size,
                                      size_t block_start, size_t block_size,
                                      uint8_t out_hash[32]);

/* 方案 A:hash_storage.c */
extern int compare_with_embedded(const uint8_t computed[32]);

/* 方案 B:self_integrity.c */
extern int self_integrity_check(void);

/* 方案 B:dex_integrity.c */
extern int dex_integrity_check(const char *apk_path, const char *expected_crcs_json);

/* ============= 方案 A:签名校验(mmap + V2) ============= */

/**
 * 方案 A 核心:mmap + V2 Signing Block 自解析
 *
 * @param apk_path APK 路径(NULL 则从 maps 定位)
 * @return 0=校验通过 / 1=校验失败(篡改) / -1=内部错误
 */
int signature_verify_mmap(const char *apk_path) {
    LOGI("=== 方案 A:签名校验(mmap + V2 自解析)===");

    void *mapped = NULL;
    size_t size = 0;
    if (mmap_apk(apk_path, &mapped, &size) != 0) {
        LOGE("mmap APK 失败");
        return -1;
    }

    size_t block_start, block_size;
    if (locate_signing_block((const uint8_t *)mapped, size,
                             &block_start, &block_size) != 0) {
        LOGW("无 Signing Block(可能 V1 only),方案 A 跳过");
        mmap_apk_free(mapped, size);
        return -1;
    }

    uint8_t computed_hash[32];
    if (compute_apk_protected_hash((const uint8_t *)mapped, size,
                                    block_start, block_size,
                                    computed_hash) != 0) {
        LOGE("哈希计算失败");
        mmap_apk_free(mapped, size);
        return -1;
    }

    int result = compare_with_embedded(computed_hash);
    mmap_apk_free(mapped, size);

    return result;  /* 0=匹配 / 1=不匹配 / -1=占位跳过 */
}

/* ============= 综合校验(方案 A + B) ============= */

/**
 * 综合校验:方案 A(签名)+ 方案 B(SO 自校验 + DEX 校验)
 *
 * @param apk_path APK 路径
 * @param expected_dex_crcs 预期 DEX CRC JSON(NULL 跳过 DEX 校验)
 * @return 0=全部通过 / 1=任一失败 / -1=内部错误
 */
int validator_core_check_all(const char *apk_path, const char *expected_dex_crcs) {
    LOGI("=== 综合校验(方案 A + B)===");

    int failed = 0;

    /* 方案 B:SO 自身完整性(防 IDA Pro 改 SO) */
    int self_result = self_integrity_check();
    if (self_result == 1) {
        LOGE("SO 自身完整性校验失败(.text 被篡改)");
        failed = 1;
    }

    /* 方案 A:签名校验(mmap + V2 自解析) */
    int sig_result = signature_verify_mmap(apk_path);
    if (sig_result == 1) {
        LOGE("签名校验失败(APK 被篡改)");
        failed = 1;
    }

    /* 方案 B:DEX 完整性 */
    int dex_result = dex_integrity_check(apk_path, expected_dex_crcs);
    if (dex_result == 1) {
        LOGE("DEX 完整性校验失败(DEX 被篡改)");
        failed = 1;
    }

    if (failed) {
        LOGE("综合校验:检测到篡改");
        return 1;
    }

    /* inner 层交叉验证(VMP 保护,与外壳独立校验) */
    extern int inner_loader_is_loaded(void);
    extern int inner_loader_env_check(const char *maps, int len);
    extern int inner_loader_verify_hash(const char *a, const char *b);

    if (inner_loader_is_loaded()) {
        /* 1. inner 环境检测: 读 maps 传给 inner, 独立检测 Frida/Xposed/SRPatch */
        int mfd = open("/proc/self/maps", 0);
        if (mfd >= 0) {
            char mbuf[8192];
            int mtotal = 0;
            ssize_t mn;
            while ((mn = read(mfd, mbuf + mtotal, sizeof(mbuf) - 1 - mtotal)) > 0)
                mtotal += (int)mn;
            close(mfd);
            mbuf[mtotal] = '\0';

            int env_score = inner_loader_env_check(mbuf, mtotal);
            if (env_score >= 40) {
                LOGE("inner 环境检测异常: score=%d (Frida/Xposed/SRPatch)", env_score);
                return 1;
            }
        }

        /* 2. VMP 引擎自检: 验证 inner_verify_hash 工作正确 */
        const char *test_a = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        const char *test_b = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        int vmp_result = inner_loader_verify_hash(test_a, test_b);
        if (vmp_result != 0) {
            LOGE("VMP 引擎自检失败: 相同 hash 应返回 0, 实际 %d", vmp_result);
            return 1;
        }
        /* 反向验证: 不同 hash 应返回 1 */
        const char *test_c = "0000000000000000000000000000000000000000000000000000000000000000";
        int vmp_result2 = inner_loader_verify_hash(test_a, test_c);
        if (vmp_result2 != 1) {
            LOGE("VMP 引擎自检失败: 不同 hash 应返回 1, 实际 %d", vmp_result2);
            return 1;
        }
    }

    LOGI("综合校验通过(含 inner 交叉验证)");
    return 0;
}

/* ============= 方案 C 辅助:获取 APK hash 的 base64 ============= */

/**
 * 计算 APK 受保护内容 hash 并 base64 编码(供方案 C 服务端校验)
 *
 * @param apk_path APK 路径(NULL 则从 maps 定位)
 * @param out_base64 输出:base64 编码的 hash(至少 48 字节)
 * @param out_size 输出缓冲区大小
 * @return 0=成功 / -1=失败
 */
int signature_verify_mmap_get_hash(const char *apk_path, char *out_base64, size_t out_size) {
    void *mapped = NULL;
    size_t size = 0;
    if (mmap_apk(apk_path, &mapped, &size) != 0) return -1;

    size_t block_start, block_size;
    if (locate_signing_block((const uint8_t *)mapped, size,
                             &block_start, &block_size) != 0) {
        mmap_apk_free(mapped, size);
        return -1;
    }

    uint8_t computed_hash[32];
    if (compute_apk_protected_hash((const uint8_t *)mapped, size,
                                    block_start, block_size,
                                    computed_hash) != 0) {
        mmap_apk_free(mapped, size);
        return -1;
    }
    mmap_apk_free(mapped, size);

    /* 先转 hex 字符串(64 字符),再 base64 编码 hex 字符串
     * 服务端 base64 解码后得到 hex 字符串,与白名单匹配 */
    char hex_str[65];
    for (int i = 0; i < 32; i++)
        snprintf(hex_str + i * 2, 3, "%02x", computed_hash[i]);
    hex_str[64] = '\0';

    /* base64 编码 hex 字符串(64 字节 → 88 字节 base64) */
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int len = 64;
    if (out_size < 92) return -1;
    int pos = 0;
    for (int i = 0; i < len; i += 3) {
        unsigned int n = (unsigned int)hex_str[i] << 16;
        if (i + 1 < len) n |= (unsigned int)hex_str[i + 1] << 8;
        if (i + 2 < len) n |= (unsigned int)hex_str[i + 2];
        out_base64[pos++] = b64[(n >> 18) & 0x3F];
        out_base64[pos++] = b64[(n >> 12) & 0x3F];
        out_base64[pos++] = (i + 1 < len) ? b64[(n >> 6) & 0x3F] : '=';
        out_base64[pos++] = (i + 2 < len) ? b64[n & 0x3F] : '=';
    }
    out_base64[pos] = '\0';
    return 0;
}

/* ============= 守护线程回调(注册给 trigger_scheduler) ============= */

static const char *g_apk_path = NULL;
static const char *g_expected_dex_crcs = NULL;

static int guard_verify_callback(void) {
    /* apk_path 为 NULL 时 signature_verify_mmap 自动从 maps 定位 */
    return validator_core_check_all(g_apk_path, g_expected_dex_crcs);
}

/**
 * 初始化守护线程校验(由 DefenderInitProvider 调用)
 *
 * @param apk_path APK 路径
 * @param expected_dex_crcs 预期 DEX CRC JSON(可 NULL)
 */
extern void trigger_scheduler_set_callback(int (*cb)(void));
extern void trigger_scheduler_start(void);

void validator_core_init_guard(const char *apk_path, const char *expected_dex_crcs) {
    g_apk_path = apk_path;
    g_expected_dex_crcs = expected_dex_crcs;
    trigger_scheduler_set_callback(guard_verify_callback);
    trigger_scheduler_start();
}
