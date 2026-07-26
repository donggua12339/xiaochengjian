/* strong_evidence_classloader.c - CREATOR ClassLoader JNI 桥接(Q2 ② + Q3.3.a)
 *
 * 单独成文件的原因:需要 JNIEnv*,而 JNIEnv 在 .init_array 阶段不可用;
 * x4_core 在 Application.onCreate 时调一次(那时 Java VM 已起)。
 *
 * 此处提供占位实现(返回 false = 不命中),真机上的真实检测走 Java 层
 * X4InjectionDetector.kt,Native 通过 JNI 调用其静态方法。
 * 编译验证用占位即可;生产实现见后续 PR。
 */
#include "strong_evidence.h"
#include <stdbool.h>

bool x4_check_creator_classloader_jni(void) {
    /* 占位:实际通过 JNI 调用
     *   com.xcj.defender.X4InjectionDetector.detectCreatorHook()
     * 返回 true 表示命中(应用 PathClassLoader 加载了 CREATOR 代理类)。
     * 当前返回 false = 不命中,避免在 JNI 未就绪时误杀。 */
    return false;
}
