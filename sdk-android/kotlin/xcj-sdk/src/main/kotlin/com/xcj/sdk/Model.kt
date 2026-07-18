package com.xcj.sdk

/**
 * SDK 配置
 *
 * @param appId 应用 ID(从 Web 后台创建应用获得)
 * @param appSecret 应用密钥(仅创建时显示一次,务必保存)
 * @param serverUrl 服务器 URL(如 https://xcj.winmelon.cn)
 * @param serverPublicKeyPem 服务器 RSA 公钥 PEM(handshake 用,从 Web 后台或 /v1/sdk/integrity 拉取)
 * @param offlineCacheDays 离线缓存天数(1-30,服务端配置优先)
 */
data class SdkConfig(
    val appId: String,
    val appSecret: String,
    val serverUrl: String,
    val serverPublicKeyPem: String,
    val offlineCacheDays: Int = 7,
)

/**
 * 卡密类型
 */
enum class CardKeyType(val apiValue: String) {
    DAY("DAY"),
    WEEK("WEEK"),
    MONTH("MONTH"),
    PERMANENT("PERMANENT"),
    TRIAL("TRIAL"),
}

/**
 * 激活结果
 *
 * @param success 是否成功
 * @param cardType 卡密类型(success=true 时有效)
 * @param expiresAt 过期时间 ISO8601(success=true 时有效)
 * @param cacheKey 离线缓存密钥(由服务端下发,SDK 内部管理)
 * @param offlineCacheDays 离线缓存天数
 * @param reason 失败原因(success=false 时有效,见错误码表)
 */
data class ActivationResult(
    val success: Boolean,
    val cardType: CardKeyType? = null,
    val expiresAt: String? = null,
    val cacheKey: String? = null,
    val offlineCacheDays: Int = 7,
    val reason: String? = null,
)

/**
 * 验证结果
 *
 * @param success 是否成功(网络请求成功)
 * @param valid 卡密是否有效(success=true 时才有意义)
 * @param expiresAt 过期时间
 * @param cacheKey 刷新后的离线缓存密钥
 * @param reason 失败原因(valid=false 时的原因,见错误码表)
 */
data class ValidationResult(
    val success: Boolean,
    val valid: Boolean = false,
    val expiresAt: String? = null,
    val cacheKey: String? = null,
    val offlineCacheDays: Int = 7,
    val cached: Boolean = false,
    val reason: String? = null,
)

/**
 * 会话保活结果
 *
 * @param success 是否成功
 * @param expiresAt 会话过期时间
 * @param newAesKey 轮换后的 AES 密钥(若服务端轮换则返回,否则 null)
 * @param reason 失败原因
 */
data class HeartbeatResult(
    val success: Boolean,
    val expiresAt: String? = null,
    val newAesKey: String? = null,
    val reason: String? = null,
)

/**
 * SDK 异常
 */
class SdkException(
    val code: String,
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)
