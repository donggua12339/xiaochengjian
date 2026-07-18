package com.xcj.sdk

/**
 * JNI 桥接:调用 Rust so(libxcj_core.so)
 *
 * 默认语义化命名(便于审计),与 Rust 侧 jni_bridge.rs 对应。
 * 若 Rust so 用 --features opaque-jni 编译,改用 native01-08 声明(见 OpaqueXcjNative)。
 *
 * 详见 ADR 0023 (Rust 核心设计)
 */
object XcjNative {
    init {
        System.loadLibrary("xcj_core")
    }

    /** SDK 初始化:存全局配置,返回 0=成功 / -1=已初始化 / -2=内部错误 */
    external fun init(appId: String, appSecret: String, serverUrl: String): Int

    /** 生成机器码(SHA-256 多因素组合,32 字符十六进制) */
    external fun generateMachineId(
        androidId: String,
        mediaDrmId: String,
        hardwareFingerprint: String,
    ): String

    /** 校验卡密格式(含 Luhn mod32),返回 1=合法 / 0=非法 */
    external fun validateCardKey(cardKey: String): Int

    /** 加密离线缓存,返回 Base64,失败返回空字符串 */
    external fun encryptCache(cacheKey: String, deviceFingerprint: String, plaintext: String): String

    /** 解密离线缓存,返回明文,失败返回空字符串 */
    external fun decryptCache(cacheKey: String, deviceFingerprint: String, encoded: String): String

    /** AES-256-GCM 加密请求体,返回 Base64(iv|ciphertext|tag),失败返回空字符串 */
    external fun encryptRequest(aesKeyHex: String, plaintext: String): String

    /** AES-256-GCM 解密响应体,返回明文 JSON,失败返回空字符串 */
    external fun decryptResponse(aesKeyHex: String, encoded: String): String

    /** HMAC-SHA256 签名,返回 64 字符十六进制签名,失败返回空字符串 */
    external fun signRequest(aesKeyHex: String, message: String): String

    /** RSA 公钥加密(handshake 用),返回 Base64 密文,失败返回空字符串 */
    external fun rsaEncrypt(publicKeyPem: String, plaintext: String): String

    /** 生成 32 字节随机 AES 密钥,返回 64 字符十六进制 */
    external fun generateAesKey(): String

    /** 生成 32 字符十六进制 nonce(防重放) */
    external fun generateNonce(): String
}

/**
 * 非语义化命名别名(opaque-jni feature 启用时使用)
 *
 * 若 Rust so 用 --features opaque-jni 编译,so 会同时导出语义化 + native01-08 两组符号。
 * 开发者想要非语义化时,把 [XcjNative] 的 external 声明替换为本对象的对应方法。
 */
object OpaqueXcjNative {
    init {
        System.loadLibrary("xcj_core")
    }

    /** native01 = init */
    external fun native01(appId: String, appSecret: String, serverUrl: String): Int

    /** native02 = generateMachineId */
    external fun native02(androidId: String, mediaDrmId: String, hardwareFingerprint: String): String

    /** native03 = validateCardKey */
    external fun native03(cardKey: String): Int

    /** native04 = encryptCache */
    external fun native04(cacheKey: String, deviceFingerprint: String, plaintext: String): String

    /** native05 = decryptCache */
    external fun native05(cacheKey: String, deviceFingerprint: String, encoded: String): String

    /** native06 = encryptRequest */
    external fun native06(aesKeyHex: String, plaintext: String): String

    /** native07 = decryptResponse */
    external fun native07(aesKeyHex: String, encoded: String): String

    /** native08 = signRequest */
    external fun native08(aesKeyHex: String, message: String): String
}
