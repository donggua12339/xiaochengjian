/**
 * x4_jni.c - X4 native 方法的 JNI 桥接(ADR 0093)
 *
 * x4_register_natives 由 defender_jni.c 的 JNI_OnLoad 调用,把 X4 native 检测
 * 注册到 com/xcj/defender/X4Native。
 */
#include <jni.h>
#include "x4_anti_inject.h"

static jint x4_anti_inject_check_jni(JNIEnv *env, jobject thiz) {
    (void)env;
    (void)thiz;
    return (jint)x4_anti_inject_check();
}

int x4_register_natives(JNIEnv *env) {
    jclass clazz = (*env)->FindClass(env, "com/xcj/defender/X4Native");
    if (clazz == NULL) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        return -1;
    }
    JNINativeMethod methods[] = {
        {"antiInjectCheck", "()I", (void *)x4_anti_inject_check_jni},
    };
    jint rc = (*env)->RegisterNatives(env, clazz, methods, 1);
    (*env)->DeleteLocalRef(env, clazz);
    return (rc == JNI_OK) ? 0 : -1;
}
