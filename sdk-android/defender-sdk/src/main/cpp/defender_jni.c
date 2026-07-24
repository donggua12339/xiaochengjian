/**
 * defender_jni.c - JNI 桥接层
 *
 * 对应 Kotlin:DefenderNative.kt
 *
 * 详见 ADR 0088 §技术架构
 */

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <android/log.h>

#define TAG "DefenderJNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ============= Batch 1:self_verify + getVersion ============= */

/* 声明 self_verify.c 的函数 */
extern int defender_self_verify(void);

/**
 * Java: DefenderNative.selfVerify() -> int
 *
 * @return 0=校验通过 / -1=校验失败(已 abort)/ -2=内部错误
 */
JNIEXPORT jint JNICALL
defender_self_verify_jni(JNIEnv *env, jobject thiz) {
    (void)env;
    (void)thiz;
    LOGI("JNI selfVerify 调用");
    return (jint)defender_self_verify();
}

/**
 * Java: DefenderNative.getVersion() -> String
 */
JNIEXPORT jstring JNICALL
defender_get_version_jni(JNIEnv *env, jobject thiz) {
    (void)thiz;
    const char *version = "1.0.0";
    return (*env)->NewStringUTF(env, version);
}

/* ============= Batch 2:SignatureVerifier + AntiDebug + AntiFrida ============= */

/* 声明 sig_verify.c 的函数 */
extern int sig_verify_check_all(
    const char *apk_path,
    const char *expected_sig_hash,
    const char *expected_apk_hash,
    const char *server_sig_hash,
    const char *server_apk_hash
);

/* 声明 anti_debug.c 的函数 */
extern int anti_debug_check(void);

/* 声明 anti_frida.c 的函数 */
extern int anti_frida_check(void);
extern void anti_frida_start_memory_scan(void);

/**
 * Java: DefenderNative.verifySignature(apkPath, sigHash, apkHash, serverSigHash, serverApkHash) -> int
 *
 * 三层签名校验(D + B + C)
 *
 * @return 0=全通过 / 1=任一层失败 / -1=内部错误
 */
JNIEXPORT jint JNICALL
defender_verify_signature_jni(
    JNIEnv *env, jobject thiz,
    jstring apk_path_j,
    jstring sig_hash_j,
    jstring apk_hash_j,
    jstring server_sig_hash_j,
    jstring server_apk_hash_j
) {
    (void)thiz;
    const char *apk_path = (*env)->GetStringUTFChars(env, apk_path_j, NULL);
    const char *sig_hash = sig_hash_j ? (*env)->GetStringUTFChars(env, sig_hash_j, NULL) : NULL;
    const char *apk_hash = apk_hash_j ? (*env)->GetStringUTFChars(env, apk_hash_j, NULL) : NULL;
    const char *server_sig = server_sig_hash_j ? (*env)->GetStringUTFChars(env, server_sig_hash_j, NULL) : NULL;
    const char *server_apk = server_apk_hash_j ? (*env)->GetStringUTFChars(env, server_apk_hash_j, NULL) : NULL;

    int result = sig_verify_check_all(apk_path, sig_hash, apk_hash, server_sig, server_apk);

    (*env)->ReleaseStringUTFChars(env, apk_path_j, apk_path);
    if (sig_hash_j) (*env)->ReleaseStringUTFChars(env, sig_hash_j, sig_hash);
    if (apk_hash_j) (*env)->ReleaseStringUTFChars(env, apk_hash_j, apk_hash);
    if (server_sig_hash_j) (*env)->ReleaseStringUTFChars(env, server_sig_hash_j, server_sig);
    if (server_apk_hash_j) (*env)->ReleaseStringUTFChars(env, server_apk_hash_j, server_apk);

    return (jint)result;
}

/**
 * Java: DefenderNative.checkAntiDebug() -> int
 *
 * @return 0=未被调试 / 1=被调试
 */
JNIEXPORT jint JNICALL
defender_check_anti_debug_jni(JNIEnv *env, jobject thiz) {
    (void)env;
    (void)thiz;
    return (jint)anti_debug_check();
}

/**
 * Java: DefenderNative.checkAntiFrida() -> int
 *
 * 同步检测(A+B+C),不含 D 后台扫描
 *
 * @return 0=未检测到 / 1=检测到 Frida
 */
JNIEXPORT jint JNICALL
defender_check_anti_frida_jni(JNIEnv *env, jobject thiz) {
    (void)env;
    (void)thiz;
    return (jint)anti_frida_check();
}

/**
 * Java: DefenderNative.startFridaMemoryScan() -> void
 *
 * 启动后台内存特征字符串扫描(D 层)
 */
JNIEXPORT void JNICALL
defender_start_frida_memory_scan_jni(JNIEnv *env, jobject thiz) {
    (void)env;
    (void)thiz;
    anti_frida_start_memory_scan();
}

/* ============= Batch 4:响应策略(defender_response.c)============= */

/* 声明 defender_response.c 的函数 */
extern void defender_kill(int delay_min_ms, int delay_max_ms, const char *method);
extern int  defender_warn_throttle(const char *violation_key, int throttle_ms);

/**
 * Java: DefenderNative.defenderKill(delayMinMs, delayMaxMs, method) -> void
 *
 * 随机延迟后 kill(SIGABRT / _exit)
 */
JNIEXPORT void JNICALL
defender_kill_jni(JNIEnv *env, jobject thiz,
    jint delay_min_ms, jint delay_max_ms, jstring method_j
) {
    (void)thiz;
    const char *method = method_j ? (*env)->GetStringUTFChars(env, method_j, NULL) : NULL;
    defender_kill((int)delay_min_ms, (int)delay_max_ms, method);
    if (method_j) (*env)->ReleaseStringUTFChars(env, method_j, method);
}

/**
 * Java: DefenderNative.defenderWarn(violationKey, throttleMs) -> int
 *
 * warn 限流检查
 *
 * @return 1=应该上报(首次或已过限流期)/ 0=限流中跳过
 */
JNIEXPORT jint JNICALL
defender_warn_throttle_jni(JNIEnv *env, jobject thiz,
    jstring violation_key_j, jint throttle_ms
) {
    (void)thiz;
    const char *key = violation_key_j ? (*env)->GetStringUTFChars(env, violation_key_j, NULL) : NULL;
    int result = defender_warn_throttle(key, (int)throttle_ms);
    if (violation_key_j) (*env)->ReleaseStringUTFChars(env, violation_key_j, key);
    return (jint)result;
}

/* ============= Batch 3:RootDetector + IntegrityChecker + AntiDump ============= */

/* 声明 root_check.c 的函数 */
extern int root_check(void);

/* 声明 integrity.c 的函数(M6:预期表从参数传入) */
extern int integrity_check(const char *apk_path, const char *crc_table_json, const char *file_list_json);

/* 声明 anti_dump.c 的函数 */
extern void anti_dump_start_monitor(void);

/**
 * Java: DefenderNative.checkRoot() -> int
 *
 * @return 0=未检测到 root / 1=检测到 root
 */
JNIEXPORT jint JNICALL
defender_check_root_jni(JNIEnv *env, jobject thiz) {
    (void)env;
    (void)thiz;
    return (jint)root_check();
}

/**
 * Java: DefenderNative.checkIntegrity(apkPath, crcTableJson, fileListJson) -> int
 *
 * M6:预期 CRC 表 + 文件列表从 config 传入(JSON 数组字符串)
 *
 * @return 0=安全 / 1=kill / 2=warn / -1=内部错误
 */
JNIEXPORT jint JNICALL
defender_check_integrity_jni(JNIEnv *env, jobject thiz, jstring apk_path_j,
                             jstring crc_table_j, jstring file_list_j) {
    (void)thiz;
    const char *apk_path = (*env)->GetStringUTFChars(env, apk_path_j, NULL);
    const char *crc_table = crc_table_j ? (*env)->GetStringUTFChars(env, crc_table_j, NULL) : "[]";
    const char *file_list = file_list_j ? (*env)->GetStringUTFChars(env, file_list_j, NULL) : "[]";
    int result = integrity_check(apk_path, crc_table, file_list);
    (*env)->ReleaseStringUTFChars(env, apk_path_j, apk_path);
    if (crc_table_j) (*env)->ReleaseStringUTFChars(env, crc_table_j, crc_table);
    if (file_list_j) (*env)->ReleaseStringUTFChars(env, file_list_j, file_list);
    return (jint)result;
}

/**
 * Java: DefenderNative.startAntiDumpMonitor() -> void
 *
 * 启动 AntiDump inotify 监控(后台常驻)
 */
JNIEXPORT void JNICALL
defender_start_anti_dump_jni(JNIEnv *env, jobject thiz) {
    (void)env;
    (void)thiz;
    anti_dump_start_monitor();
}

/* ============= v2.1.1 方案 A+B+C 综合校验 ============= */

extern int validator_core_check_all(const char *apk_path, const char *expected_dex_crcs);
extern void validator_core_init_guard(const char *apk_path, const char *expected_dex_crcs);
extern int server_gate_has_valid_token(void);
extern void server_gate_set_token(const char *token, time_t expire_ts);
extern int server_gate_encrypt_hash(const unsigned char hash[32], char *out_base64, size_t out_size);
extern void self_integrity_init(void);

/* 详细校验用 */
extern int self_integrity_check(void);
extern int signature_verify_mmap(const char *apk_path);
extern int dex_integrity_check(const char *apk_path, const char *expected_crcs_json);
extern int mmap_reader_cached_fd_valid(void);
extern int self_integrity_path_valid(void);
extern const char *self_integrity_get_so_path(void);
extern int patch_env_detect(void);
extern int patch_env_get_result(char *buf, size_t buf_size);

/**
 * Java: DefenderNative.validatorCoreCheck(apkPath, expectedDexCrcs) -> int
 *
 * 综合校验:方案 A(签名 mmap+V2)+ 方案 B(SO 自校验 + DEX CRC)
 *
 * @return 0=通过 / 1=检测到篡改 / -1=内部错误
 */
JNIEXPORT jint JNICALL
validator_core_check_jni(JNIEnv *env, jobject thiz,
    jstring apk_path_j, jstring expected_dex_crcs_j
) {
    (void)thiz;
    const char *apk_path = apk_path_j ? (*env)->GetStringUTFChars(env, apk_path_j, NULL) : NULL;
    const char *expected_crcs = expected_dex_crcs_j
        ? (*env)->GetStringUTFChars(env, expected_dex_crcs_j, NULL) : NULL;

    int result = validator_core_check_all(apk_path, expected_crcs);

    if (apk_path_j) (*env)->ReleaseStringUTFChars(env, apk_path_j, apk_path);
    if (expected_dex_crcs_j) (*env)->ReleaseStringUTFChars(env, expected_dex_crcs_j, expected_crcs);
    return (jint)result;
}

/**
 * Java: DefenderNative.validatorInitGuard(apkPath, expectedDexCrcs) -> void
 *
 * 初始化守护线程(周期性校验)
 */
JNIEXPORT void JNICALL
validator_init_guard_jni(JNIEnv *env, jobject thiz,
    jstring apk_path_j, jstring expected_dex_crcs_j
) {
    (void)thiz;
    const char *apk_path = apk_path_j ? (*env)->GetStringUTFChars(env, apk_path_j, NULL) : NULL;
    const char *expected_crcs = expected_dex_crcs_j
        ? (*env)->GetStringUTFChars(env, expected_dex_crcs_j, NULL) : NULL;

    validator_core_init_guard(apk_path, expected_crcs);

    if (apk_path_j) (*env)->ReleaseStringUTFChars(env, apk_path_j, apk_path);
    if (expected_dex_crcs_j) (*env)->ReleaseStringUTFChars(env, expected_dex_crcs_j, expected_crcs);
}

/**
 * Java: DefenderNative.serverGateHasValidToken() -> int
 *
 * 检查服务端 gate token 是否有效(方案 C)
 *
 * @return 1=有效 / 0=无效或过期
 */
JNIEXPORT jint JNICALL
server_gate_has_valid_token_jni(JNIEnv *env, jobject thiz) {
    (void)env;
    (void)thiz;
    return (jint)server_gate_has_valid_token();
}

/* ============= 详细校验结果(供 UI 展示) ============= */

/**
 * Java: DefenderNative.detailedCheck(apkPath) -> String
 *
 * 运行所有校验并返回 JSON 格式结果(供 demo UI 逐条展示)
 */
JNIEXPORT jstring JNICALL
defender_detailed_check_jni(JNIEnv *env, jobject thiz, jstring apk_path_j) {
    (void)thiz;
    const char *apk_path = apk_path_j ? (*env)->GetStringUTFChars(env, apk_path_j, NULL) : NULL;

    char buf[4096];
    int pos = 0;

    /* 方案 B: .text CRC */
    int self_result = self_integrity_check();
    pos += snprintf(buf + pos, sizeof(buf) - pos,
        "{\"selfIntegrityCrc\":%d,", self_result == 0 ? 1 : 0);

    /* 方案 A: APK hash(mmap + V2) */
    int sig_result = signature_verify_mmap(apk_path);
    pos += snprintf(buf + pos, sizeof(buf) - pos,
        "\"signatureHashMatch\":%d,", sig_result == 0 ? 1 : 0);

    /* 方案 B: DEX CRC */
    int dex_result = dex_integrity_check(apk_path, NULL);
    pos += snprintf(buf + pos, sizeof(buf) - pos,
        "\"dexIntegrity\":%d,", dex_result == 0 ? 1 : (dex_result == -1 ? -1 : 0));

    /* 缓存 fd 状态 */
    pos += snprintf(buf + pos, sizeof(buf) - pos,
        "\"cachedFdValid\":%d,", mmap_reader_cached_fd_valid());

    /* .so 加载路径合法性(防 SRPatch/LSPatch) */
    int path_valid = self_integrity_path_valid();
    pos += snprintf(buf + pos, sizeof(buf) - pos,
        "\"soPathValid\":%d,", path_valid == 1 ? 1 : 0);

    /* .so 实际加载路径 */
    const char *so_path = self_integrity_get_so_path();
    pos += snprintf(buf + pos, sizeof(buf) - pos,
        "\"soPath\":\"%s\",", so_path ? so_path : "");

    /* Native 层通用绕过检测(maps + dl_iterate_phdr + /proc/self/fd) */
    int native_score = patch_env_detect();
    char native_detail[1024];
    patch_env_get_result(native_detail, sizeof(native_detail));
    pos += snprintf(buf + pos, sizeof(buf) - pos,
        "\"nativePatchScore\":%d,", native_score);
    pos += snprintf(buf + pos, sizeof(buf) - pos,
        "\"nativePatchDetail\":%s,", native_detail);

    /* 综合结果 */
    int all_pass = (self_result == 0 && sig_result == 0 && dex_result != 1
                    && path_valid == 1 && native_score < 40);
    pos += snprintf(buf + pos, sizeof(buf) - pos,
        "\"allPass\":%d}", all_pass ? 1 : 0);

    if (apk_path_j) (*env)->ReleaseStringUTFChars(env, apk_path_j, apk_path);
    return (*env)->NewStringUTF(env, buf);
}

/**
 * Java: DefenderNative.nativePatchDetect() -> int
 *
 * Native 层通用绕过检测(maps + dl_iterate_phdr + /proc/self/fd)
 */
JNIEXPORT jint JNICALL
defender_native_patch_detect_jni(JNIEnv *env, jobject thiz) {
    (void)env;
    (void)thiz;
    return (jint)patch_env_detect();
}

/* ============= 方案 C:服务端 gate JNI 桥接 ============= */

/**
 * Java: DefenderNative.getApkHashBase64(apkPath) -> String
 *
 * 计算 APK 受保护内容 hash + base64 编码(供 ServerGateClient POST 到服务端)
 */
JNIEXPORT jstring JNICALL
defender_get_apk_hash_base64_jni(JNIEnv *env, jobject thiz, jstring apk_path_j) {
    (void)thiz;
    const char *apk_path = apk_path_j ? (*env)->GetStringUTFChars(env, apk_path_j, NULL) : NULL;

    /* 复用方案 A 的 mmap + hash 计算 */
    extern int signature_verify_mmap_get_hash(const char *apk_path, char *out_base64, size_t out_size);
    char base64[64] = {0};
    int ret = signature_verify_mmap_get_hash(apk_path, base64, sizeof(base64));

    if (apk_path_j) (*env)->ReleaseStringUTFChars(env, apk_path_j, apk_path);

    if (ret != 0) return NULL;
    return (*env)->NewStringUTF(env, base64);
}

/**
 * Java: DefenderNative.setServerToken(token, expireTs) -> void
 *
 * 将服务端返回的 token 存入 native 缓存
 */
JNIEXPORT void JNICALL
defender_set_server_token_jni(JNIEnv *env, jobject thiz,
    jstring token_j, jlong expire_ts) {
    (void)thiz;
    const char *token = token_j ? (*env)->GetStringUTFChars(env, token_j, NULL) : NULL;
    if (token) {
        server_gate_set_token(token, (time_t)expire_ts);
        (*env)->ReleaseStringUTFChars(env, token_j, token);
    }
}

/* ============= JNI_OnLoad ============= */

/**
 * .so 加载时调用
 */
JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    LOGI("JNI_OnLoad: xcj_defender.so 已加载");

    /* 主线程初始化 .text 段缓存(守护线程 dladdr 可能失败) */
    self_integrity_init();

    /* 直接在 JNI_OnLoad 启动守护线程(不依赖 Java 层调用,防 MT patch DEX 绕过) */
    validator_core_init_guard(NULL, NULL);

    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        LOGE("GetEnv 失败");
        return JNI_ERR;
    }

    /* 注册 native 方法(动态注册,比静态注册更难被定位) */
    static const char *class_name = "com/xcj/defender/DefenderNative";
    jclass clazz = (*env)->FindClass(env, class_name);
    if (clazz == NULL) {
        /* LSPosed 等工具会替换 DEX 导致 FindClass 失败。
         * 不返回 JNI_ERR(否则 .so 被卸载,守护线程死亡)。
         * 守护线程已在上方启动,保持 .so 存活即可。 */
        LOGW("FindClass 失败: %s(DEX 可能被替换,native 方法延迟注册)", class_name);
        return JNI_VERSION_1_6;
    }

    JNINativeMethod methods[] = {
        {"selfVerify",            "()I",                                                    (void *)defender_self_verify_jni},
        {"getVersion",            "()Ljava/lang/String;",                                   (void *)defender_get_version_jni},
        {"verifySignature",       "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I",
                                                                                                 (void *)defender_verify_signature_jni},
        {"checkAntiDebug",        "()I",                                                    (void *)defender_check_anti_debug_jni},
        {"checkAntiFrida",        "()I",                                                    (void *)defender_check_anti_frida_jni},
        {"startFridaMemoryScan",  "()V",                                                    (void *)defender_start_frida_memory_scan_jni},
        {"checkRoot",             "()I",                                                    (void *)defender_check_root_jni},
        {"checkIntegrity",        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I", (void *)defender_check_integrity_jni},
        {"startAntiDumpMonitor",  "()V",                                                    (void *)defender_start_anti_dump_jni},
        {"defenderKill",          "(IILjava/lang/String;)V",                                (void *)defender_kill_jni},
        {"defenderWarn",          "(Ljava/lang/String;I)I",                                 (void *)defender_warn_throttle_jni},
        {"validatorCoreCheck",    "(Ljava/lang/String;Ljava/lang/String;)I",                (void *)validator_core_check_jni},
        {"validatorInitGuard",    "(Ljava/lang/String;Ljava/lang/String;)V",                (void *)validator_init_guard_jni},
        {"serverGateHasValidToken", "()I",                                                    (void *)server_gate_has_valid_token_jni},
        {"detailedCheck",           "(Ljava/lang/String;)Ljava/lang/String;",                  (void *)defender_detailed_check_jni},
        {"nativePatchDetect",       "()I",                                                     (void *)defender_native_patch_detect_jni},
        {"getApkHashBase64",        "(Ljava/lang/String;)Ljava/lang/String;",                  (void *)defender_get_apk_hash_base64_jni},
        {"setServerToken",          "(Ljava/lang/String;J)V",                                  (void *)defender_set_server_token_jni},
    };

    jint rc = (*env)->RegisterNatives(env, clazz, methods, sizeof(methods) / sizeof(methods[0]));
    if (rc != JNI_OK) {
        LOGE("RegisterNatives 失败: %d", rc);
        return JNI_ERR;
    }

    LOGI("JNI_OnLoad 完成,native 方法已注册");
    return JNI_VERSION_1_6;
}
