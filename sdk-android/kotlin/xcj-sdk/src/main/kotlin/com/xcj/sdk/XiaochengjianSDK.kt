package com.xcj.sdk

import android.content.Context
import android.provider.Settings
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * 小城笺 SDK 入口
 *
 * 用法:
 * ```
 * val sdk = XiaochengjianSDK(context, XcjConfig(appId, appSecret, serverUrl))
 * sdk.activate("ABCD-EFGH-IJKL-MNOP") { result ->
 *     if (result.success) { /* 激活成功 */ }
 * }
 * ```
 *
 * 详见 ADR 0009 (Kotlin + Rust JNI)
 */
class XiaochengjianSDK(
    private val context: Context,
    private val config: XcjConfig,
) {
    private val native = XcjNative
    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    init {
        native.native01(config.appId, config.appSecret, config.serverUrl)
    }

    /**
     * 生成机器码
     */
    fun generateMachineId(): String {
        val androidId = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ANDROID_ID,
        ) ?: ""
        val hardwareFingerprint = buildHardwareFingerprint()
        return native.native02(androidId, "", hardwareFingerprint)
    }

    /**
     * 校验卡密格式(本地,不发网络请求)
     * @return true 格式正确
     */
    fun validateCardKeyFormat(cardKey: String): Boolean {
        return native.native03(cardKey) == 1
    }

    /**
     * 反调试检测
     * @return 0=Clean, 1=DebugDetected, 2=EmulatorDetected
     */
    fun checkThreatLevel(): Int = native.native06()

    /**
     * 激活卡密(网络请求)
     */
    suspend fun activate(cardKey: String): ActivationResult = withContext(Dispatchers.IO) {
        if (!validateCardKeyFormat(cardKey)) {
            return@withContext ActivationResult(false, errorMessage = "INVALID_CARD_KEY_FORMAT")
        }

        val machineId = generateMachineId()
        val payload = JSONObject().apply {
            put("cardKey", cardKey)
            put("machineId", machineId)
            put("fingerprintHash", machineId)
        }

        try {
            val response = doHandshakeAndRequest("activate", payload)
            val result = response.getJSONObject("data")
            ActivationResult(
                success = true,
                cardKeyType = CardKeyType.valueOf(result.getString("type")),
                expiresAt = result.optString("expiresAt"),
                cacheKey = result.optString("cacheKey"),
            )
        } catch (e: SdkException) {
            ActivationResult(false, errorMessage = e.message)
        } catch (e: Exception) {
            ActivationResult(false, errorMessage = "NETWORK_ERROR: ${e.message}")
        }
    }

    /**
     * 验证卡密(网络请求,含离线缓存)
     */
    suspend fun validate(cardKey: String): ValidationResult = withContext(Dispatchers.IO) {
        if (!validateCardKeyFormat(cardKey)) {
            return@withContext ValidationResult(false, errorMessage = "INVALID_CARD_KEY_FORMAT")
        }

        val machineId = generateMachineId()
        val payload = JSONObject().apply {
            put("cardKey", cardKey)
            put("machineId", machineId)
        }

        try {
            val response = doHandshakeAndRequest("validate", payload)
            val result = response.getJSONObject("data")
            ValidationResult(
                success = true,
                expiresAt = result.optString("expiresAt"),
                cacheKey = result.optString("cacheKey"),
            )
        } catch (e: SdkException) {
            ValidationResult(false, errorMessage = e.message)
        } catch (e: Exception) {
            // 网络失败,尝试离线缓存(M2.10 完善)
            ValidationResult(false, errorMessage = "NETWORK_ERROR: ${e.message}")
        }
    }

    /**
     * handshake + 加密请求(简化版,M2.10 完善加密)
     */
    private fun doHandshakeAndRequest(endpoint: String, payload: JSONObject): JSONObject {
        // M2.10 完善:RSA handshake + AES 加密 + HMAC 签名
        // 当前简化版:直接发 JSON(仅用于联调)
        val url = "${config.serverUrl}/v1/sdk/$endpoint"
        val body = payload.toString().toRequestBody("application/json".toMediaType())
        val request = Request.Builder().url(url).post(body).build()
        val response = httpClient.newCall(request).execute()
        val responseBody = response.body?.string() ?: "{}"
        val json = JSONObject(responseBody)
        if (!response.isSuccessful) {
            throw SdkException(json.optString("code", "UNKNOWN"), json.optString("message", "请求失败"))
        }
        return json
    }

    private fun buildHardwareFingerprint(): String {
        return listOf(
            Build.MANUFACTURER,
            Build.MODEL,
            Build.HARDWARE,
            Build.BOARD,
            Build.SUPPORTED_ABIS.joinToString(","),
        ).joinToString("|")
    }

    private class SdkException(val code: String, message: String) : Exception(message)
}
