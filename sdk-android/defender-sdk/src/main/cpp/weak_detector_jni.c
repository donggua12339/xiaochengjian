/* weak_detector_jni.c - CREATOR 弱信号 JNI 桥接占位
 *
 * 与强证据② 区别:
 *   强证据②: CREATOR 被"应用 PathClassLoader"加载 → 注入物确定
 *   弱信号 L2: CREATOR 被"系统 CL/BootClassLoader"加载但类名非标准 → ROM 合法魔改可能
 *
 * 占位实现:返回 false(不命中)。真机检测走 Java 层
 * X4InjectionDetector.detectCreatorHook() 的弱信号分支,通过 JNI 调用。
 */
#include "weak_detector.h"
#include <stdbool.h>

bool x4_check_creator_sys_cl_jni(void) {
    /* 占位:实际通过 JNI 调用 Java 静态方法 */
    return false;
}
