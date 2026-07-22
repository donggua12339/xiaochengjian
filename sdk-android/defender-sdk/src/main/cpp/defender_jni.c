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

/* ============= JNI_OnLoad ============= */

/**
 * .so 加载时调用
 */
JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    LOGI("JNI_OnLoad: xcj_defender.so 已加载");

    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        LOGE("GetEnv 失败");
        return JNI_ERR;
    }

    /* 注册 native 方法(动态注册,比静态注册更难被定位) */
    static const char *class_name = "com/xcj/defender/DefenderNative";
    jclass clazz = (*env)->FindClass(env, class_name);
    if (clazz == NULL) {
        LOGE("FindClass 失败: %s", class_name);
        return JNI_ERR;
    }

    JNINativeMethod methods[] = {
        {"selfVerify",            "()I",                                                    (void *)defender_self_verify_jni},
        {"getVersion",            "()Ljava/lang/String;",                                   (void *)defender_get_version_jni},
        {"verifySignature",       "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I",
                                                                                                 (void *)defender_verify_signature_jni},
        {"checkAntiDebug",        "()I",                                                    (void *)defender_check_anti_debug_jni},
        {"checkAntiFrida",        "()I",                                                    (void *)defender_check_anti_frida_jni},
        {"startFridaMemoryScan",  "()V",                                                    (void *)defender_start_frida_memory_scan_jni},
    };

    jint rc = (*env)->RegisterNatives(env, clazz, methods, sizeof(methods) / sizeof(methods[0]));
    if (rc != JNI_OK) {
        LOGE("RegisterNatives 失败: %d", rc);
        return JNI_ERR;
    }

    LOGI("JNI_OnLoad 完成,native 方法已注册");
    return JNI_VERSION_1_6;
}
