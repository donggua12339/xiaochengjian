/**
 * x4_stubs.c - X4 占位接口 stub 实现(ADR 0093)
 *
 * 以下接口在 spec 中预留,真机实现走 JNI 调 Java 层:
 *   - x4_ui_show_toast  → 调 android.widget.Toast(Q5 灰度期补真机实现)
 *   - x4_telemetry_send → 调 Java 网络层上报(Q5 灰度策略定稿后补)
 *
 * Tier1 对抗测试只需要验证 kill 通道,toast/上报可空实现。
 * 链接需要这些符号存在,否则 undefined reference。
 */
#include <android/log.h>

#define TAG "X4-Stubs"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

/* response_chain.c 调用,占位:仅 log */
void x4_ui_show_toast(const char *msg) {
    LOGD("[X4-TOAST-STUB] %s", msg ? msg : "(null)");
    /* TODO Q5: JNI 调 android.widget.Toast.makeText(...).show() */
}

/* telemetry.c 调用,占位:仅 log */
void x4_telemetry_send(const char *json) {
    LOGD("[X4-TEL-STUB] %s", json ? json : "(null)");
    /* TODO Q5: JNI 调 Java 网络层,带 throttle + retry */
}
