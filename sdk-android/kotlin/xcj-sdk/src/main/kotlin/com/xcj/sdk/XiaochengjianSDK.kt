package com.xcj.sdk

import android.content.Context
import android.os.Build
import android.provider.Settings
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
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
 * val sdk = XiaochengjianSDK(context, SdkConfig(appId, appSecret, "https://xcj.winmelon.cn"))
 * val result = sdk.activate("ABCD-EFGH-IJKL-MNOP")
 * if (result.success) { /* 激活成功 */ }
 * ```
 *
 * 架构:
 *  - HTTP 在 Kotlin 层(OkHttp)
 *  - 加密/签名/缓存在 Rust so(JNI 调用)
 *  - 会话(sessionId + aesKey)由 SDK 内部管理,业务层无需关心
 *
 * 详见 ADR 0009 (Kotlin + Rust JNI) / 0020 (通信加密) / 0021 (签名防重放)
 */
class XiaochengjianSDK(
    private val context: Context,
    private val config: SdkConfig,
) {
    private val native = XcjNative
    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    /** 会话状态(sessionId + aesKey,handshake 后填充) */
    private var session: SdkSession? = null
    private val sessionMutex = Mutex()

    init {
        val code = native.init(config.appId, config.appSecret, config.serverUrl)
        // 0=成功 / -1=已初始化(幂等,视为成功)/ -2=内部错误
        require(code == 0 || code == -1) { "SDK init failed: code=$code (-2=internal error)" }
    }

    // ============= 公开 API =============

    /**
     * 生成机器码(多因素组合 SHA-256)
     */
    fun generateMachineId(): String {
        val androidId = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ANDROID_ID,
        ) ?: ""
        val mediaDrmId = getMediaDrmId()
        val hardwareFingerprint = buildHardwareFingerprint()
        return native.generateMachineId(androidId, mediaDrmId, hardwareFingerprint)
    }

    /**
     * 校验卡密格式(本地,不发网络请求)
     */
    fun validateCardKeyFormat(cardKey: String): Boolean {
        return native.validateCardKey(cardKey) == 1
    }

    /**
     * 激活卡密(网络请求)
     *
     * 流程:
     *  1. 本地校验卡密格式
     *  2. handshake(RSA 协商 AES 密钥)
     *  3. AES-GCM 加密请求体 + HMAC 签名
     *  4. POST /v1/sdk/activate
     *  5. AES-GCM 解密响应
     *  6. 存离线缓存
     */
    suspend fun activate(cardKey: String): ActivationResult = withContext(Dispatchers.IO) {
        if (!validateCardKeyFormat(cardKey)) {
            return@withContext ActivationResult(success = false, reason = "INVALID_CARD_KEY_FORMAT")
        }

        val machineId = generateMachineId()
        val payload = JSONObject().apply {
            put("cardKey", cardKey)
            put("machineId", machineId)
            put("fingerprintHash", machineId)
        }

        try {
            val response = doSignedRequest("activate", payload)
            response.put("success", true)
            // 存离线缓存
            session?.let { saveOfflineCache(cardKey, machineId, response) }
            ActivationResult(
                success = true,
                cardType = parseCardType(response.optString("cardType")),
                expiresAt = response.optString("expiresAt").ifEmpty { null },
                cacheKey = response.optString("cacheKey").ifEmpty { null },
                offlineCacheDays = response.optInt("offlineCacheDays", config.offlineCacheDays),
            )
        } catch (e: SdkException) {
            Log.e(TAG, "activate SdkException: ${e.code} - ${e.message}")
            ActivationResult(success = false, reason = e.code)
        } catch (e: Exception) {
            Log.e(TAG, "activate Exception", e)
            ActivationResult(success = false, reason = "NETWORK_ERROR: ${e.message}")
        }
    }

    /**
     * 验证卡密(网络请求,刷新 cacheKey)
     */
    suspend fun validate(cardKey: String): ValidationResult = withContext(Dispatchers.IO) {
        if (!validateCardKeyFormat(cardKey)) {
            return@withContext ValidationResult(success = false, reason = "INVALID_CARD_KEY_FORMAT")
        }

        val machineId = generateMachineId()
        val payload = JSONObject().apply {
            put("cardKey", cardKey)
            put("machineId", machineId)
        }

        try {
            val response = doSignedRequest("validate", payload)
            ValidationResult(
                success = true,
                valid = response.optBoolean("valid", false),
                expiresAt = response.optString("expiresAt").ifEmpty { null },
                cacheKey = response.optString("cacheKey").ifEmpty { null },
                offlineCacheDays = response.optInt("offlineCacheDays", config.offlineCacheDays),
                reason = response.optString("reason").ifEmpty { null },
            )
        } catch (e: SdkException) {
            ValidationResult(success = false, reason = e.code)
        } catch (e: Exception) {
            // 网络失败,尝试离线缓存
            tryOfflineCache(cardKey, machineId)
        }
    }

    /**
     * 会话保活(刷新 sessionId TTL,纯 Redis 操作,轻量)
     */
    suspend fun heartbeat(): HeartbeatResult = withContext(Dispatchers.IO) {
        val currentSession = sessionMutex.withLock { session } ?: run {
            return@withContext HeartbeatResult(success = false, reason = "NO_SESSION")
        }

        try {
            val response = doSignedRequest("heartbeat", JSONObject(), currentSession)
            val result = HeartbeatResult(
                success = true,
                expiresAt = response.optString("expiresAt").ifEmpty { null },
                newAesKey = response.optString("newAesKey").ifEmpty { null },
            )
            // 若服务端轮换了 AES 密钥,更新本地 session
            result.newAesKey?.let { newKey ->
                sessionMutex.withLock {
                    session = currentSession.copy(aesKeyHex = newKey)
                }
            }
            result
        } catch (e: SdkException) {
            HeartbeatResult(success = false, reason = e.code)
        } catch (e: Exception) {
            HeartbeatResult(success = false, reason = "NETWORK_ERROR")
        }
    }

    // ============= 内部:handshake + 签名请求 =============

    /**
     * 执行签名 + 加密请求
     *
     * 流程:
     *  1. 若无 session,先 handshake
     *  2. AES-GCM 加密请求体
     *  3. 构造签名 message(method + path + timestamp + nonce + bodyHash)
     *  4. HMAC-SHA256 签名
     *  5. POST /v1/sdk/{endpoint} 带 header(x-session-id/x-timestamp/x-nonce/x-signature)
     *  6. AES-GCM 解密响应
     */
    private suspend fun doSignedRequest(
        endpoint: String,
        payload: JSONObject,
        existingSession: SdkSession? = null,
    ): JSONObject {
        val currentSession = existingSession ?: sessionMutex.withLock {
            session ?: run {
                val newSession = handshake()
                session = newSession
                newSession
            }
        }

        val path = "/v1/sdk/$endpoint"
        val plaintext = payload.toString()

        // 加密请求体
        val encryptedBody = native.encryptRequest(currentSession.aesKeyHex, plaintext)
        if (encryptedBody.isEmpty()) {
            throw SdkException("ENCRYPT_FAILED", "AES encrypt request body failed")
        }

        // 签名
        val timestamp = (System.currentTimeMillis() / 1000).toString()
        val nonce = native.generateNonce()
        val bodyHash = sha256Hex(encryptedBody)
        val signMessage = "POST$path$timestamp$nonce$bodyHash"
        val signature = native.signRequest(currentSession.aesKeyHex, signMessage)

        // 发请求
        val requestBody = JSONObject().apply {
            put("encryptedBody", encryptedBody)
        }.toString().toRequestBody(JSON_MEDIA_TYPE)

        val request = Request.Builder()
            .url("${config.serverUrl}$path")
            .header("x-session-id", currentSession.sessionId)
            .header("x-timestamp", timestamp)
            .header("x-nonce", nonce)
            .header("x-signature", signature)
            .header("Content-Type", "application/json")
            .post(requestBody)
            .build()

        return httpClient.newCall(request).execute().use { resp ->
            val responseBody = resp.body?.string() ?: "{}"
            val json = JSONObject(responseBody)
            if (!resp.isSuccessful) {
                throw SdkException(
                    json.optString("code", "UNKNOWN"),
                    json.optString("message", "Request failed: ${resp.code}"),
                )
            }
            // 解密响应
            val encryptedResp = json.optString("encryptedBody", "")
            if (encryptedResp.isEmpty()) {
                throw SdkException("INVALID_RESPONSE", "Response missing encryptedBody")
            }
            val decrypted = native.decryptResponse(currentSession.aesKeyHex, encryptedResp)
            if (decrypted.isEmpty()) {
                throw SdkException("DECRYPT_FAILED", "AES decrypt response failed")
            }
            JSONObject(decrypted)
        }
    }

    /**
     * Handshake:RSA 加密临时 AES 密钥,换取 sessionId
     */
    private suspend fun handshake(): SdkSession = withContext(Dispatchers.IO) {
        // 1. 拉取服务端公钥(从 /v1/sdk/integrity 端点,或配置中预置)
        val publicKeyPem = fetchServerPublicKey()

        // 2. 生成临时 AES 密钥
        val aesKeyHex = native.generateAesKey()

        // 3. RSA 加密 AES 密钥
        val encryptedKeyB64 = native.rsaEncrypt(publicKeyPem, aesKeyHex)
        if (encryptedKeyB64.isEmpty()) {
            throw SdkException("RSA_ENCRYPT_FAILED", "RSA encrypt AES key failed")
        }

        // 4. POST /v1/sdk/handshake
        val requestBody = JSONObject().apply {
            put("encryptedKey", encryptedKeyB64)
            put("appId", config.appId)
        }.toString().toRequestBody(JSON_MEDIA_TYPE)

        val request = Request.Builder()
            .url("${config.serverUrl}/v1/sdk/handshake")
            .header("Content-Type", "application/json")
            .post(requestBody)
            .build()

        httpClient.newCall(request).execute().use { resp ->
            val responseBody = resp.body?.string() ?: "{}"
            val json = JSONObject(responseBody)
            if (!resp.isSuccessful) {
                throw SdkException(
                    json.optString("code", "UNKNOWN"),
                    json.optString("message", "Handshake failed: ${resp.code}"),
                )
            }
            val sessionId = json.optString("sessionId")
            if (sessionId.isEmpty()) {
                throw SdkException("INVALID_HANDSHAKE_RESPONSE", "Missing sessionId")
            }
            SdkSession(sessionId = sessionId, aesKeyHex = aesKeyHex)
        }
    }

    /**
     * 拉取服务端 RSA 公钥
     *
     * 实现策略:从 [SdkConfig.serverPublicKeyPem] 读取(打包时预置,推荐)。
     *
     * 注:不从 /v1/sdk/integrity 运行时拉取,因为:
     *  1. 首次握手前没有加密通道,公钥若被中间人替换则后续所有加密失效
     *  2. 预置公钥 + 证书轮换靠 SDK 版本升级,更安全
     */
    private fun fetchServerPublicKey(): String {
        require(config.serverPublicKeyPem.isNotEmpty()) {
            "SdkConfig.serverPublicKeyPem must be set (PEM format RSA public key)"
        }
        return config.serverPublicKeyPem
    }

    // ============= 离线缓存 =============

    private fun saveOfflineCache(cardKey: String, machineId: String, response: JSONObject) {
        val cacheKey = response.optString("cacheKey").ifEmpty { return }
        val deviceFingerprint = machineId // 用 machineId 作为设备指纹
        val plaintext = response.toString()
        val encoded = native.encryptCache(cacheKey, deviceFingerprint, plaintext)
        if (encoded.isNotEmpty()) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putString(cacheKeyOffline(cardKey), encoded)
                .apply()
        }
    }

    private fun tryOfflineCache(cardKey: String, machineId: String): ValidationResult {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        // 遍历所有缓存,找到对应卡密的
        for (entry in prefs.all) {
            if (!entry.key.startsWith("offline_")) continue
            val encoded = entry.value as? String ?: continue
            // 缓存 key 是随机下发的,无法直接按 cardKey 索引
            // 简化:用 cardKey hash 作为 deviceFingerprint,尝试解密
            val deviceFingerprint = machineId
            val decrypted = native.decryptCache("", deviceFingerprint, encoded)
            if (decrypted.isNotEmpty()) {
                val json = JSONObject(decrypted)
                if (json.optString("cardType").isNotEmpty()) {
                    return ValidationResult(
                        success = true,
                        valid = true,
                        expiresAt = json.optString("expiresAt").ifEmpty { null },
                        cached = true,
                    )
                }
            }
        }
        return ValidationResult(success = false, reason = "NETWORK_ERROR")
    }

    private fun cacheKeyOffline(cardKey: String) = "offline_${cardKey.hashCode()}"

    // ============= 工具方法 =============

    private fun buildHardwareFingerprint(): String {
        return listOf(
            Build.MANUFACTURER,
            Build.MODEL,
            Build.HARDWARE,
            Build.BOARD,
            Build.SUPPORTED_ABIS.joinToString(","),
        ).joinToString("|")
    }

    private fun getMediaDrmId(): String {
        // 简化:M2.x 完善从 MediaDrm 获取
        // 实际实现需 WidevineDeviceId 或 CommonPsshBox
        return ""
    }

    private fun parseCardType(apiValue: String): CardKeyType? {
        return runCatching { CardKeyType.valueOf(apiValue) }.getOrNull()
    }

    private fun sha256Hex(data: String): String {
        // 用 Rust so 的 signRequest 间接算 hash 不行(那是 HMAC)
        // 这里用 Kotlin MessageDigest 算 SHA-256
        val md = java.security.MessageDigest.getInstance("SHA-256")
        val bytes = md.digest(data.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    companion object {
        private const val TAG = "XcjSDK"
        private const val PREFS_NAME = "xcj_sdk_cache"
        private val JSON_MEDIA_TYPE = "application/json".toMediaType()
    }
}

/**
 * SDK 会话状态(handshake 后获得)
 */
internal data class SdkSession(
    val sessionId: String,
    val aesKeyHex: String,
)
