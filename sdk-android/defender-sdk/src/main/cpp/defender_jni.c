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
Java_com_xcj_defender_DefenderNative_selfVerify(JNIEnv *env, jobject thiz) {
    (void)env;
    (void)thiz;
    LOGI("JNI selfVerify 调用");
    return (jint)defender_self_verify();
}

/**
 * Java: DefenderNative.getVersion() -> String
 */
JNIEXPORT jstring JNICALL
Java_com_xcj_defender_DefenderNative_getVersion(JNIEnv *env, jobject thiz) {
    (void)thiz;
    const char *version = "1.0.0";
    return (*env)->NewStringUTF(env, version);
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
        {"selfVerify",  "()I",                   (void *)Java_com_xcj_defender_DefenderNative_selfVerify},
        {"getVersion",  "()Ljava/lang/String;",  (void *)Java_com_xcj_defender_DefenderNative_getVersion},
    };

    jint rc = (*env)->RegisterNatives(env, clazz, methods, sizeof(methods) / sizeof(methods[0]));
    if (rc != JNI_OK) {
        LOGE("RegisterNatives 失败: %d", rc);
        return JNI_ERR;
    }

    LOGI("JNI_OnLoad 完成,native 方法已注册");
    return JNI_VERSION_1_6;
}
