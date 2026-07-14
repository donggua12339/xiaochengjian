package com.xcj.sdk

/**
 * SDK 配置
 */
data class XcjConfig(
    val appId: String,
    val appSecret: String,
    val serverUrl: String = "http://localhost:3000",
    val offlineCacheDays: Int = 7,
    val enableAntiDebug: Boolean = true,
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
 */
data class ActivationResult(
    val success: Boolean,
    val cardKeyType: CardKeyType? = null,
    val expiresAt: String? = null,
    val cacheKey: String? = null,
    val errorMessage: String? = null,
)

/**
 * 验证结果
 */
data class ValidationResult(
    val success: Boolean,
    val expiresAt: String? = null,
    val cacheKey: String? = null,
    val cached: Boolean = false,
    val errorMessage: String? = null,
)

/**
 * SDK 回调
 */
interface XcjCallback<T> {
    fun onSuccess(result: T)
    fun onError(code: String, message: String)
}
