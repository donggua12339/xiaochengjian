package com.xcj.defender

import android.util.Log
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom

/**
 * 方案 C 客户端:与服务端 integrity gate 通信
 *
 * 流程:
 *  1. Native 层计算 APK hash → base64 编码(通过 JNI getApkHashBase64)
 *  2. POST /v1/integrity/client-verify(公开端点,无需 JWT)
 *  3. 服务端比对白名单 → 颁发短期 JWT token
 *  4. Token 通过 JNI setServerToken 存入 native 层缓存
 *  5. 守护线程定期检查 token,过期重新请求
 *  6. 无法获取 token → 延迟 kill
 *
 * 对抗 SRPatch Lv.4:
 *  全 syscall hook 无法伪造服务端签名 → 这是唯一不可绕过的防线
 */
object ServerGateClient {

    private const val TAG = "DefenderServerGate"

    @Volatile
    var lastVerdict: String = "PENDING"
        private set

    @Volatile
    var lastError: String? = null
        private set

    /**
     * 执行一次完整性校验(在后台线程调用)
     *
     * @param serverUrl 服务端地址
     * @param appId 应用包名
     * @param apkPath APK 路径
     * @return true=校验通过或跳过 / false=校验失败
     */
    fun verify(serverUrl: String, appId: String, apkPath: String): Boolean {
        if (serverUrl.isEmpty()) {
            Log.w(TAG, "serverUrl 未配置,方案 C 跳过")
            lastVerdict = "SKIP"
            return true
        }

        // 1. 从 native 层获取 APK hash(base64)
        val hashBase64 = try {
            DefenderNative.getApkHashBase64(apkPath)
        } catch (e: Exception) {
            Log.e(TAG, "获取 APK hash 失败: ${e.message}")
            lastError = e.message
            lastVerdict = "HASH_ERROR"
            return false
        }

        if (hashBase64.isNullOrEmpty()) {
            Log.e(TAG, "APK hash 为空")
            lastVerdict = "HASH_EMPTY"
            return false
        }

        // 2. 生成 nonce + timestamp
        val nonce = generateNonce()
        val timestamp = System.currentTimeMillis()

        // 3. POST 到服务端公开端点
        val result = postVerify(serverUrl, appId, hashBase64, nonce, timestamp)
        if (result == null) {
            Log.e(TAG, "服务端请求失败(网络错误或超时)")
            lastVerdict = "NETWORK_ERROR"
            return false
        }

        // 4. 处理结果
        return when (result.verdict) {
            "PASS" -> {
                Log.i(TAG, "方案 C 校验通过,token 已存入 native")
                lastVerdict = "PASS"
                val expireMs = parseExpireAt(result.expireAt)
                DefenderNative.setServerToken(result.token ?: "", expireMs / 1000)
                true
            }
            "FAIL" -> {
                Log.e(TAG, "方案 C 校验失败: ${result.reason}")
                lastVerdict = "FAIL"
                lastError = result.reason
                false
            }
            else -> {
                Log.e(TAG, "方案 C 未知响应: ${result.verdict}")
                lastVerdict = "UNKNOWN"
                false
            }
        }
    }

    private data class VerifyResult(
        val verdict: String,
        val token: String?,
        val expireAt: String?,
        val reason: String?
    )

    private fun postVerify(
        serverUrl: String,
        appId: String,
        hashBase64: String,
        nonce: String,
        timestamp: Long
    ): VerifyResult? {
        var conn: HttpURLConnection? = null
        return try {
            val url = URL("$serverUrl/v1/integrity/client-verify")
            conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.doOutput = true
            conn.connectTimeout = 8000
            conn.readTimeout = 8000

            val body = JSONObject().apply {
                put("appId", appId)
                put("encryptedHash", hashBase64)
                put("nonce", nonce)
                put("timestamp", timestamp)
            }
            conn.outputStream.use { it.write(body.toString().toByteArray()) }

            val code = conn.responseCode
            if (code != 200) {
                Log.w(TAG, "服务端返回 HTTP $code")
                return null
            }

            val responseText = conn.inputStream.bufferedReader().use { it.readText() }
            val json = JSONObject(responseText)

            VerifyResult(
                verdict = json.optString("verdict", "UNKNOWN"),
                token = json.optString("token", "").ifEmpty { null },
                expireAt = json.optString("expireAt", "").ifEmpty { null },
                reason = json.optString("reason", "").ifEmpty { null }
            )
        } catch (e: Exception) {
            Log.w(TAG, "HTTP 请求异常: ${e.message}")
            null
        } finally {
            conn?.disconnect()
        }
    }

    private fun parseExpireAt(expireAt: String?): Long {
        if (expireAt.isNullOrEmpty()) return System.currentTimeMillis() + 3600_000
        return try {
            java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", java.util.Locale.US).apply {
                timeZone = java.util.TimeZone.getTimeZone("UTC")
            }.parse(expireAt)?.time ?: (System.currentTimeMillis() + 3600_000)
        } catch (_: Exception) {
            System.currentTimeMillis() + 3600_000
        }
    }

    private fun generateNonce(): String {
        val bytes = ByteArray(16)
        SecureRandom().nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
