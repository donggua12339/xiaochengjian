package com.xcj.defender

import android.content.Context
import android.util.Log
import com.google.android.play.core.integrity.IntegrityManager
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Play Integrity 检测(2026 服务端信任验证)
 *
 * 原理:
 *  调用 Google Play Integrity API 请求 integrity token,
 *  Google 服务端验证设备完整性(设备完整性 + 应用完整性 + 账号完整性),
 *  返回加密签名的 verdict JWT。
 *
 *  本 SDK 只负责请求 token,verdict 的解码验证需后端用 Google Cloud 公钥完成
 *  (见服务端 PlayIntegrityVerifier)。
 *
 * 检测价值:
 *  - 无 Google Play 服务(国产 ROM/模拟器)→ 请求失败 → 高风险
 *  - root/自定义 ROM → deviceIntegrity verdict 不满足 MEETS_DEVICE_INTEGRITY
 *  - 重打包 → appIntegrity verdict 不满足
 *
 * 详见 ADR 0088 §Play Integrity
 */
class PlayIntegrityDetector(private val context: Context) {

    companion object {
        private const val TAG = "DefenderPlayIntegrity"
    }

    /**
     * 请求 Play Integrity token(同步包装,最多等 10 秒)
     *
     * @param nonce 随机数(防重放,建议后端生成并下发)
     * @return Success(token) 或 Failure(原因)
     */
    fun requestToken(nonce: String): PlayIntegrityResult {
        var result: PlayIntegrityResult = PlayIntegrityResult.Failure("timeout")
        val latch = CountDownLatch(1)

        try {
            val integrityManager: IntegrityManager = IntegrityManagerFactory.create(context)
            val request = IntegrityTokenRequest.builder()
                .setNonce(nonce)
                .build()

            integrityManager.requestIntegrityToken(request)
                .addOnSuccessListener { response ->
                    Log.i(TAG, "Play Integrity token 请求成功")
                    result = PlayIntegrityResult.Success(response.token())
                    latch.countDown()
                }
                .addOnFailureListener { e ->
                    Log.w(TAG, "Play Integrity token 请求失败: ${e.message}")
                    result = PlayIntegrityResult.Failure(e.message ?: "unknown")
                    latch.countDown()
                }

            if (!latch.await(10, TimeUnit.SECONDS)) {
                Log.w(TAG, "Play Integrity token 请求超时")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Play Integrity 请求异常: ${e.message}")
            result = PlayIntegrityResult.Failure(e.message ?: "exception")
        }

        return result
    }

    /**
     * Play Integrity 结果
     *
     * Success.token 需交给后端 PlayIntegrityVerifier 解码验证 verdict。
     * Failure 表示设备无法通过 Play Integrity(无 Google Play/模拟器/root 等)。
     */
    sealed class PlayIntegrityResult {
        data class Success(val token: String) : PlayIntegrityResult()
        data class Failure(val reason: String) : PlayIntegrityResult()
    }
}
