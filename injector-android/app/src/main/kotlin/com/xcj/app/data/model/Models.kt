package com.xcj.app.data.model

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * 登录请求
 */
@JsonClass(generateAdapter = true)
data class LoginRequest(
    val email: String,
    val password: String,
)

/**
 * 登录响应
 */
@JsonClass(generateAdapter = true)
data class LoginResponse(
    val accessToken: String,
    val refreshToken: String?,
    val developer: DeveloperInfo,
)

@JsonClass(generateAdapter = true)
data class DeveloperInfo(
    val id: String,
    val email: String,
    val name: String?,
)

/**
 * 应用列表项
 */
@JsonClass(generateAdapter = true)
data class ApplicationDto(
    val id: String,
    val name: String,
    val packageName: String?,
    val status: String,
)

@JsonClass(generateAdapter = true)
data class ApplicationListResponse(
    val items: List<ApplicationDto> = emptyList(),
    val total: Long = 0,
)

/**
 * 卡密列表项
 */
@JsonClass(generateAdapter = true)
data class CardKeyDto(
    val id: String,
    val status: String,
    val type: String,
    val cardKeyPrefix: String,
    val mask: String?,
    val activatedAt: String?,
    val expiresAt: String?,
    val maxDevices: Int,
    val bindingStrategy: String,
    val createdAt: String,
)

@JsonClass(generateAdapter = true)
data class CardKeyListResponse(
    val items: List<CardKeyDto> = emptyList(),
    val total: Long = 0,
)

/**
 * 通用操作响应
 */
@JsonClass(generateAdapter = true)
data class OperationResponse(
    val success: Boolean,
    val message: String? = null,
)

/**
 * 统计概览
 */
@JsonClass(generateAdapter = true)
data class StatsOverview(
    val appCount: Long = 0,
    val cardKeyTotal: Long = 0,
    val cardKeyActive: Long = 0,
    val deviceActive: Long = 0,
    val validationsToday: Long = 0,
)

/**
 * 通用错误响应
 */
@JsonClass(generateAdapter = true)
data class ErrorResponse(
    val statusCode: Int,
    val message: String,
    val error: String? = null,
)
