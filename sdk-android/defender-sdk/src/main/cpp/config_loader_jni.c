/* config_loader_jni.c - X4 config JNI 桥接占位
 *
 * 真机走 Java 层 DefenderConfig.kt 解析 JSON,通过 JNI 把字段填到
 * g_x4_config。此处占位实现:用默认值(host fallback)。
 * 生产实现见后续 PR(把 DefenderConfig 字段映射到 x4_config_t)。
 */
#include "config_loader.h"
#include "score_weights.h"
#include <stdbool.h>

void x4_config_load_from_jni(void) {
    /* 占位:不修改 g_x4_config,保持头文件默认值 */
}

bool x4_config_detect_mdm_jni(void) {
    /* 占位:不探测 MDM,返回 false */
    return false;
}
