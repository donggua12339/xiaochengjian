package com.xcj.sdk

/**
 * JNI 桥接:调用 Rust so(libxcj_core.so)
 *
 * 函数名非语义化(native01-native08),与 Rust 侧 jni_bridge.rs 对应
 * 详见 ADR 0023 (Rust 核心设计)
 *
 * 注:不用 native_1 等带下划线的命名,因为 JNI 会把 _ 编码为 _1,
 * 导致查找 native_11,与 Rust 侧 native_1 不匹配
 */
object XcjNative {
    init {
        System.loadLibrary("xcj_core")
    }

    /** native01: 初始化 SDK */
    external fun native01(appId: String, appSecret: String, serverUrl: String): Int

    /** native02: 生成机器码 */
    external fun native02(androidId: String, mediaDrmId: String, hardwareFingerprint: String): String

    /** native03: 校验卡密格式(含 Luhn mod32),返回 1 合法 / 0 非法 */
    external fun native03(cardKey: String): Int

    /** native06: 反调试 + VM 检测,返回 0=Clean / 1=Debug / 2=Emulator */
    external fun native06(): Int

    /** native08: 加密离线缓存,返回 Base64,失败返回空字符串 */
    external fun native08(cacheKey: String, deviceFingerprint: String, plaintext: String): String
}
