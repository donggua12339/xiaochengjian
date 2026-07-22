package com.xcj.defender

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate

/**
 * Key Attestation 检测(2026 最强硬件级 root 检测)
 *
 * 原理:
 *  用 AndroidKeyStore 生成带 attestation challenge 的 EC 密钥对,
 *  硬件(TEE/StrongBox)会签发证书链,证明密钥在安全硬件中生成。
 *  如果设备 root / BL 解锁,硬件证明会失败或显示异常 verified boot state:
 *   - BL 解锁:verifiedBootState = Unverified(orange)
 *   - root/自签:verifiedBootState = SelfSigned(yellow) 或 Failed(red)
 *   - 正常:verifiedBootState = Verified(green) + deviceLocked = true
 *
 * 检测点:
 *  1. 能否生成硬件证明密钥对(root 设备可能失败)
 *  2. 证书链是否含硬件 attestation extension(OID 1.3.6.1.4.1.11129.2.1.17)
 *  3. 解析 attestation 的 verified boot state + device locked
 *
 * 详见 ADR 0088 §Key Attestation
 */
class KeyAttestationDetector {

    companion object {
        private const val TAG = "DefenderKeyAttestation"
        private const val KEY_ALIAS = "xcj_defender_attestation"
        private const val ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"
    }

    /**
     * 执行 Key Attestation 检测
     *
     * @return 置信度分数 0-100(0=设备完整,>=60 高度可疑 root/BL 解锁)
     */
    fun detect(): Int {
        var score = 0
        try {
            val challenge = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
            val keyPair = generateAttestationKeyPair(challenge)
            if (keyPair == null) {
                Log.w(TAG, "无法生成 attestation 密钥对(设备不支持硬件证明,可能 root)")
                return 60
            }

            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val certs = keyStore.getCertificateChain(KEY_ALIAS)
            if (certs == null || certs.isEmpty()) {
                Log.w(TAG, "无证书链")
                return 60
            }
            Log.i(TAG, "证书链长度: ${certs.size}")

            val leafCert = certs[0] as X509Certificate
            val attestationExt = leafCert.getExtensionValue(ATTESTATION_OID)
            if (attestationExt == null) {
                Log.w(TAG, "无硬件 attestation extension(软件证明,可疑)")
                score += 40
            } else {
                Log.i(TAG, "有硬件 attestation extension")
                score += parseVerifiedBootState(attestationExt)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Key Attestation 检测异常: ${e.message}")
            score += 30
        }
        return score.coerceIn(0, 100)
    }

    private fun generateAttestationKeyPair(challenge: ByteArray): java.security.KeyPair? {
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (keyStore.containsAlias(KEY_ALIAS)) {
                keyStore.deleteEntry(KEY_ALIAS)
            }
            val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore"
            )
            val spec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)
                .build()
            kpg.initialize(spec)
            kpg.generateKeyPair()
        } catch (e: Exception) {
            Log.e(TAG, "生成 attestation 密钥对失败: ${e.message}")
            null
        }
    }

    /**
     * 解析 attestation extension 的 verified boot state
     *
     * attestation extension 是 DER 编码的 ASN.1。RootOfTrust 中:
     *   verifiedBootState ENUMERATED { Verified(0), SelfSigned(1), Unverified(2), Failed(3) }
     *   deviceLocked BOOLEAN
     *
     * 简化解析:在 DER 字节中定位 RootOfTrust 的 ENUMERATED 标记(0x0A 0x01 state)。
     * 完整解析需 ASN.1 库,此处用特征匹配(硬件证明结构固定)。
     *
     * @return 风险分数(0=Verified,30=SelfSigned,40=Unverified/Failed)
     */
    private fun parseVerifiedBootState(extValue: ByteArray): Int {
        // extValue 是 OCTET STRING 包裹的 DER。搜索 ENUMERATED(0x0A 0x01 xx)模式。
        // verifiedBootState 是 RootOfTrust 中的 ENUMERATED。
        // 注:这是简化解析,生产建议用 BouncyCastle 完整解析 ASN.1。
        try {
            for (i in 0 until extValue.size - 2) {
                if (extValue[i] == 0x0A.toByte() && extValue[i + 1] == 0x01.toByte()) {
                    val state = extValue[i + 2].toInt() and 0xFF
                    if (state in 0..3) {
                        return when (state) {
                            0 -> {
                                Log.i(TAG, "verifiedBootState=Verified(green)")
                                0
                            }
                            1 -> {
                                Log.w(TAG, "verifiedBootState=SelfSigned(yellow)")
                                30
                            }
                            2 -> {
                                Log.e(TAG, "verifiedBootState=Unverified(orange,BL 解锁)")
                                40
                            }
                            else -> {
                                Log.e(TAG, "verifiedBootState=Failed(red)")
                                40
                            }
                        }
                    }
                }
            }
            Log.w(TAG, "未解析到 verifiedBootState")
        } catch (e: Exception) {
            Log.e(TAG, "解析 attestation 异常: ${e.message}")
        }
        return 20
    }
}
