package com.xcj.sdk

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Model 数据类单元测试
 *
 * 覆盖:
 *  - SdkConfig 默认值
 *  - CardKeyType 枚举值
 *  - ActivationResult / ValidationResult / HeartbeatResult 默认参数
 */
class ModelTest {

    @Test
    fun `SdkConfig default offlineCacheDays is 7`() {
        val config = SdkConfig(
            appId = "app-1",
            appSecret = "secret",
            serverUrl = "https://xcj.winmelon.cn",
            serverPublicKeyPem = "-----BEGIN PUBLIC KEY-----\\ntest\\n-----END PUBLIC KEY-----",
        )
        assertEquals(7, config.offlineCacheDays)
    }

    @Test
    fun `SdkConfig custom offlineCacheDays`() {
        val config = SdkConfig(
            appId = "app-1",
            appSecret = "secret",
            serverUrl = "https://xcj.winmelon.cn",
            serverPublicKeyPem = "-----BEGIN PUBLIC KEY-----\\ntest\\n-----END PUBLIC KEY-----",
            offlineCacheDays = 30,
        )
        assertEquals(30, config.offlineCacheDays)
    }

    @Test
    fun `CardKeyType has 5 values`() {
        assertEquals(5, CardKeyType.values().size)
        assertEquals("DAY", CardKeyType.DAY.apiValue)
        assertEquals("WEEK", CardKeyType.WEEK.apiValue)
        assertEquals("MONTH", CardKeyType.MONTH.apiValue)
        assertEquals("PERMANENT", CardKeyType.PERMANENT.apiValue)
        assertEquals("TRIAL", CardKeyType.TRIAL.apiValue)
    }

    @Test
    fun `ActivationResult failure defaults`() {
        val result = ActivationResult(success = false, reason = "CARD_NOT_FOUND")
        assertFalse(result.success)
        assertNull(result.cardType)
        assertNull(result.expiresAt)
        assertNull(result.cacheKey)
        assertEquals(7, result.offlineCacheDays)
        assertEquals("CARD_NOT_FOUND", result.reason)
    }

    @Test
    fun `ActivationResult success defaults`() {
        val result = ActivationResult(
            success = true,
            cardType = CardKeyType.MONTH,
            expiresAt = "2026-08-15",
            cacheKey = "ck-123",
        )
        assertTrue(result.success)
        assertEquals(CardKeyType.MONTH, result.cardType)
        assertEquals("2026-08-15", result.expiresAt)
        assertEquals("ck-123", result.cacheKey)
    }

    @Test
    fun `ValidationResult failure defaults`() {
        val result = ValidationResult(success = false, reason = "NETWORK_ERROR")
        assertFalse(result.success)
        assertFalse(result.valid)
        assertFalse(result.cached)
        assertEquals("NETWORK_ERROR", result.reason)
    }

    @Test
    fun `ValidationResult cached true`() {
        val result = ValidationResult(
            success = true,
            valid = true,
            cached = true,
            expiresAt = "2026-08-15",
        )
        assertTrue(result.cached)
    }

    @Test
    fun `HeartbeatResult success without key rotation`() {
        val result = HeartbeatResult(
            success = true,
            expiresAt = "2026-07-17T15:00:00Z",
        )
        assertTrue(result.success)
        assertNull(result.newAesKey)
    }

    @Test
    fun `HeartbeatResult with key rotation`() {
        val result = HeartbeatResult(
            success = true,
            expiresAt = "2026-07-17T15:00:00Z",
            newAesKey = "base64-key",
        )
        assertEquals("base64-key", result.newAesKey)
    }

    @Test
    fun `SdkException preserves code and message`() {
        val ex = SdkException("CARD_NOT_FOUND", "卡密不存在")
        assertEquals("CARD_NOT_FOUND", ex.code)
        assertEquals("卡密不存在", ex.message)
    }

    @Test
    fun `SdkException with cause`() {
        val cause = RuntimeException("network down")
        val ex = SdkException("NETWORK_ERROR", "请求失败", cause)
        assertEquals(cause, ex.cause)
    }
}
