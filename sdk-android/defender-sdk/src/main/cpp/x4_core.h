/**
 * x4_core.h - X4 主入口(ADR 0093)
 *
 * 初始化 + 守护线程调度。由 Java 层 DefenderTestApp.onCreate 通过 JNI 调用。
 */
#ifndef X4_CORE_H
#define X4_CORE_H

/**
 * 初始化 X4 响应链。
 *
 * @param config_path   配置文件路径(assets 解压后的 cache 路径;NULL 用默认值)
 * @param self_pkg      本 APP 包名(供 exempt 检查)
 * @param apk_path      本 APK 路径(供强证据 ① 签名 hash 校验)
 * @param expected_hash 预期签名 hash(64 字符 hex;NULL/空表示不校验)
 */
void x4_init(const char *config_path, const char *self_pkg,
             const char *apk_path, const char *expected_hash);

/**
 * 紧急停止(供 auto_rollback emergency 调)。
 */
void x4_emergency_stop(void);

#endif /* X4_CORE_H */
