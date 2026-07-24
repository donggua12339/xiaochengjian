/**
 * x0test.c - X0-3 原型「载荷」:一个带 JNI_OnLoad 的极简 .so
 *
 * 用途:验证 stub(xcj_loader.c)能完成"加密 .so → memfd 加载 → 手动调 JNI_OnLoad
 * → 注册的 native 可被 Java 调用"这条 X0 最难的核心链路。
 *
 * 由 scripts/build_x0test.py 编译为 libx0test.so 并 RC4 加密(魔数框架)嵌入 stub。
 * 原型跑通后,此载荷会换成真正的 libxcj_defender.so(外壳)。
 */
#include <jni.h>
#include <android/log.h>

#define TAG "X0TestPayload"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

static jstring native_ping(JNIEnv *env, jclass clazz) {
    (void)clazz;
    return (*env)->NewStringUTF(env, "pong-from-memfd-x0");
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    LOGI("X0TestPayload: JNI_OnLoad 被(stub)手动调用");
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        LOGI("X0TestPayload: GetEnv 失败");
        return JNI_ERR;
    }
    jclass clazz = (*env)->FindClass(env, "com/xcj/defender/DefenderX0Test");
    if (clazz == NULL) {
        LOGI("X0TestPayload: FindClass 失败");
        return JNI_VERSION_1_6;
    }
    JNINativeMethod methods[] = {
        {"ping", "()Ljava/lang/String;", (void *)native_ping},
    };
    jint rc = (*env)->RegisterNatives(env, clazz, methods, 1);
    LOGI("X0TestPayload: RegisterNatives rc=%d", rc);
    return JNI_VERSION_1_6;
}
