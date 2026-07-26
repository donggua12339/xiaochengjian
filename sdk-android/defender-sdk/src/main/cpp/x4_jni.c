/**
 * x4_jni.c - X4 native 方法的 JNI 桥接(ADR 0093)
 *
 * x4_register_natives 由 defender_jni.c 的 JNI_OnLoad 调用,把 X4 native 检测
 * 注册到 com/xcj/defender/X4Native。
 */
#include <jni.h>
#include "x4_anti_inject.h"
#include "x4_integrity.h"
#include "x4_anti_debug.h"
#include "x4_anti_dump.h"
#include "x4_smc.h"
#include "x4_core.h"

static jint x4_anti_inject_check_jni(JNIEnv *env, jobject thiz) {
    (void)env; (void)thiz;
    return (jint)x4_anti_inject_check();
}

static jint x4_anti_debug_check_jni(JNIEnv *env, jobject thiz) {
    (void)env; (void)thiz;
    return (jint)x4_anti_debug_check();
}

static void x4_anti_dump_init_jni(JNIEnv *env, jobject thiz) {
    (void)env; (void)thiz;
    x4_anti_dump_init();
}

static jint x4_anti_dump_check_jni(JNIEnv *env, jobject thiz) {
    (void)env; (void)thiz;
    return (jint)x4_anti_dump_check();
}

static jint x4_smc_selftest_jni(JNIEnv *env, jobject thiz) {
    (void)env; (void)thiz;
    return (jint)x4_smc_selftest();
}

static jint x4_smc_add_jni(JNIEnv *env, jobject thiz, jint a, jint b) {
    (void)env; (void)thiz;
    return (jint)x4_smc_add((int)a, (int)b);
}

static jint x4_smc_wiped_jni(JNIEnv *env, jobject thiz) {
    (void)env; (void)thiz;
    return (jint)x4_smc_sandbox_wiped();
}

static void x4_integrity_init_jni(JNIEnv *env, jobject thiz, jstring apk_path_j) {
    (void)thiz;
    const char *p = apk_path_j ? (*env)->GetStringUTFChars(env, apk_path_j, NULL) : NULL;
    x4_integrity_init(p);
    if (apk_path_j) (*env)->ReleaseStringUTFChars(env, apk_path_j, p);
}

static jint x4_integrity_check_jni(JNIEnv *env, jobject thiz, jstring apk_path_j) {
    (void)thiz;
    const char *p = apk_path_j ? (*env)->GetStringUTFChars(env, apk_path_j, NULL) : NULL;
    int rc = x4_integrity_check(p);
    if (apk_path_j) (*env)->ReleaseStringUTFChars(env, apk_path_j, p);
    return (jint)rc;
}

/* X4 响应链初始化:启动守护线程 + 三通道决策(强证据 / 有效分 / 存在感) */
static void x4_init_jni(JNIEnv *env, jobject thiz,
                        jstring config_path_j, jstring self_pkg_j,
                        jstring apk_path_j, jstring expected_hash_j) {
    (void)thiz;
    const char *config_path = config_path_j ? (*env)->GetStringUTFChars(env, config_path_j, NULL) : NULL;
    const char *self_pkg   = self_pkg_j   ? (*env)->GetStringUTFChars(env, self_pkg_j,   NULL) : NULL;
    const char *apk_path   = apk_path_j   ? (*env)->GetStringUTFChars(env, apk_path_j,   NULL) : NULL;
    const char *expected   = expected_hash_j ? (*env)->GetStringUTFChars(env, expected_hash_j, NULL) : NULL;
    x4_init(config_path, self_pkg, apk_path, expected);
    if (config_path_j) (*env)->ReleaseStringUTFChars(env, config_path_j, config_path);
    if (self_pkg_j)    (*env)->ReleaseStringUTFChars(env, self_pkg_j,    self_pkg);
    if (apk_path_j)    (*env)->ReleaseStringUTFChars(env, apk_path_j,    apk_path);
    if (expected_hash_j) (*env)->ReleaseStringUTFChars(env, expected_hash_j, expected);
}

int x4_register_natives(JNIEnv *env) {
    jclass clazz = (*env)->FindClass(env, "com/xcj/defender/X4Native");
    if (clazz == NULL) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        return -1;
    }
    JNINativeMethod methods[] = {
        {"antiInjectCheck",  "()I",                      (void *)x4_anti_inject_check_jni},
        {"antiDebugCheck",   "()I",                      (void *)x4_anti_debug_check_jni},
        {"antiDumpInit",     "()V",                      (void *)x4_anti_dump_init_jni},
        {"antiDumpCheck",    "()I",                      (void *)x4_anti_dump_check_jni},
        {"smcSelftest",      "()I",                      (void *)x4_smc_selftest_jni},
        {"smcAdd",           "(II)I",                    (void *)x4_smc_add_jni},
        {"smcWiped",         "()I",                      (void *)x4_smc_wiped_jni},
        {"integrityInit",    "(Ljava/lang/String;)V",    (void *)x4_integrity_init_jni},
        {"integrityCheck",   "(Ljava/lang/String;)I",    (void *)x4_integrity_check_jni},
        {"x4Init",           "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                                                         (void *)x4_init_jni},
    };
    jint rc = (*env)->RegisterNatives(env, clazz, methods, 10);
    (*env)->DeleteLocalRef(env, clazz);
    return (rc == JNI_OK) ? 0 : -1;
}
