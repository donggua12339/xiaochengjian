package com.xcj.defender

import android.content.Context
import android.util.Base64
import android.util.Log
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

/**
 * 方案 C 客户端:服务端 gate 通信(Java 层 RSA 加密)
 *
 * 详见 xcj_blue_demo_v2.1.1_prompt.md §方案 C
 *
 * 流程:
 *  1. Native 层计算签名哈希(方案 A 的 compute_apk_protected_hash)
 *  2. Java 层用服务端 RSA 公钥加密哈希(PKCS1_OAEP,防篡改传输)
 *  3. POST /v1/integrity/verify 提交加密哈希 + nonce + timestamp
 *  4. 服务端用私钥解密,比对白名单 -> 颁发短期 token
 *  5. 核心功能请求携带 token
 *
 * 注意:Native 层 server_gate.c 只做 token 缓存,实际 HTTP + RSA 在 Java 层
 * (避免 Native 层 TLS/RSA 实现复杂度)。
 */
class ServerGateClient(private val context: Context) {

    companion object {
        private const val TAG = "DefenderServerGateClient"

        /**
         * 服务端 RSA 公钥(PEM 格式,生产环境从 config 读取或硬编码)
         *
         * 占位:全 0(开发模式,服务端 integrityRsaPrivateKey 未配时直接 base64 传输)
         * 正式版:Packer 封装时把开发者后端 RSA 公钥写入 defender-config.json
         */
        private const val SERVER_PUBLIC_KEY_PEM = ""
    }

    /**
     * 加密签名哈希(用服务端 RSA 公钥)
     *
     * @param signatureHash 32 字节签名哈希(Native 层计算)
     * @return base64 编码的加密哈希(直接传给服务端)
     */
    fun encryptSignatureHash(signatureHash: ByteArray): String {
        // 开发模式:公钥未配,直接 base64(服务端 integrityRsaPrivateKey 未配时同步 base64 解码)
        if (SERVER_PUBLIC_KEY_PEM.isEmpty()) {
            Log.w(TAG, "服务端 RSA 公钥未配置,开发模式直接 base64")
            return Base64.encodeToString(signatureHash, Base64.NO_WRAP)
        }

        // 生产模式:RSA-2048 PKCS1_OAEP 加密
        try {
            val keyBytes = SERVER_PUBLIC_KEY_PEM
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("\\s".toRegex(), "")
                .let { Base64.decode(it, Base64.DEFAULT) }

            val publicKey = KeyFactory.getInstance("RSA")
                .generatePublic(X509EncodedKeySpec(keyBytes))

            val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)
            val encrypted = cipher.doFinal(signatureHash)
            return Base64.encodeToString(encrypted, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "RSA 加密失败,回退 base64: ${e.message}")
            return Base64.encodeToString(signatureHash, Base64.NO_WRAP)
        }
    }

    /**
     * 生成 nonce(一次性随机数,防重放)
     */
    fun generateNonce(): String {
        val bytes = ByteArray(16)
        java.security.SecureRandom().nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    /**
     * 请求服务端 gate 校验 + 获取 token
     *
     * @param serverUrl 服务端 URL(如 https://xcj.winmelon.cn)
     * @param appId 应用包名
     * @param signatureHash 32 字节签名哈希
     * @return token 字符串(成功)/ null(失败)
     */
    fun requestToken(
        serverUrl: String,
        appId: String,
        signatureHash: ByteArray,
    ): String? {
        val encryptedHash = encryptSignatureHash(signatureHash)
        val nonce = generateNonce()
        val timestamp = System.currentTimeMillis()

        val body = """
            {"appId":"$appId","encryptedHash":"$encryptedHash","nonce":"$nonce","timestamp":$timestamp}
        """.trimIndent()

        return try {
            val url = java.net.URL("$serverUrl/v1/integrity/verify")
            val conn = url.openConnection() as java.net.HttpURLConnection
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("Authorization", "Bearer ${getAccessToken()}")
            conn.doOutput = true
            conn.connectTimeout = 5000
            conn.readTimeout = 5000

            conn.outputStream.use { it.write(body.toByteArray()) }

            if (conn.responseCode == 200) {
                val response = conn.inputStream.bufferedReader().readText()
                // 解析 JSON 提取 token(简化:正则提取)
                val tokenMatch = Regex("\"token\"\\s*:\\s*\"([^\"]+)\"").find(response)
                val token = tokenMatch?.groupValues?.get(1)

                if (token != null) {
                    // 解析过期时间
                    val expireMatch = Regex("\"expireAt\"\\s*:\\s*\"([^\"]+)\"").find(response)
                    val expireAt = expireMatch?.groupValues?.get(1)?.let {
                        java.time.Instant.parse(it).epochSecond
                    } ?: (System.currentTimeMillis() / 1000 + 3600)

                    // 缓存 token(Native 层 server_gate.c)
                    // 通过 JNI 调用 server_gate_set_token(略,此处只返回)
                    Log.i(TAG, "token 获取成功,过期: $expireAt")
                }
                token
            } else {
                Log.w(TAG, "服务端 gate 请求失败: ${conn.responseCode}")
                null
            }
        } catch (e: Exception) {
            Log.w(TAG, "服务端 gate 请求异常: ${e.message}")
            null
        }
    }

    /**
     * 获取本地存储的 access token(用于服务端 gate 鉴权)
     * 简化:从 SharedPreferences 读(生产环境用加密存储)
     */
    private fun getAccessToken(): String {
        val prefs = context.getSharedPreferences("xcj_defender", Context.MODE_PRIVATE)
        return prefs.getString("access_token", "") ?: ""
    }
}
