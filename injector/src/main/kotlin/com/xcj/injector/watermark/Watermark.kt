package com.xcj.injector.watermark

import org.slf4j.LoggerFactory
import net.lingala.zip4j.ZipFile
import net.lingala.zip4j.model.ZipParameters
import java.io.File

/**
 * 注入水印(防滥用追溯,ADR 0030 §c)
 *
 * 两种模式:
 *  - SaaS 模式(embedEncrypted):调后端 /v1/watermark/generate 拿 AES-256-GCM 加密水印,
 *    写入 META-INF/xcj-watermark.enc.txt。攻击者只能看到密文,服务端可解密追溯。
 *  - 开源模式(embed,deprecated):明文写入 META-INF/xcj-watermark.txt,开发者自查用,
 *    无加密保护。SaaS 用户应优先用 embedEncrypted。
 *
 * 水印字段(明文 JSON,加密前):
 *  - version: 注入工具版本
 *  - watermarkId: 开发者标识
 *  - timestamp: 注入时间(Unix ms)
 *  - nonce: 16 字节随机数(防重放)
 */
class Watermark {
    private val logger = LoggerFactory.getLogger(Watermark::class.java)

    /**
     * 嵌入加密水印(SaaS 模式,推荐)
     *
     * @param apkFile 待嵌入的 APK
     * @param watermarkBase64 后端 /v1/watermark/generate 返回的 Base64 密文
     */
    fun embedEncrypted(apkFile: File, watermarkBase64: String) {
        if (watermarkBase64.isEmpty()) {
            throw IllegalArgumentException("watermarkBase64 must not be empty")
        }

        // watermarkBase64 是 base64( json{iv, ciphertext, tag} ),直接写入文件
        val tempWatermark = File(apkFile.parentFile, "META-INF/xcj-watermark.enc.txt")
        tempWatermark.parentFile.mkdirs()
        tempWatermark.writeText(watermarkBase64)

        val zipFile = ZipFile(apkFile)
        val params = ZipParameters().apply {
            fileNameInZip = "META-INF/xcj-watermark.enc.txt"
        }
        zipFile.addFile(tempWatermark, params)

        logger.info("加密水印已嵌入(AES-256-GCM,密钥服务端持有)")
        tempWatermark.delete()
    }

    /**
     * 嵌入明文水印(开源模式,deprecated)
     *
     * 仅用于开源自部署场景(无服务端)。SaaS 用户应使用 embedEncrypted。
     */
    @Deprecated("SaaS 用户应使用 embedEncrypted;开源模式保留明文便于自查")
    fun embed(apkFile: File, watermarkId: String) {
        val content = buildString {
            appendLine("=== 小城笺注入水印 ===")
            appendLine("version: ${InjectorConstants.VERSION}")
            appendLine("watermarkId: $watermarkId")
            appendLine("timestamp: ${System.currentTimeMillis()}")
            appendLine("injectedAt: ${java.util.Date()}")
            appendLine("=== END ===")
        }

        val tempWatermark = File(apkFile.parentFile, "META-INF/xcj-watermark.txt")
        tempWatermark.parentFile.mkdirs()
        tempWatermark.writeText(content)

        val zipFile = ZipFile(apkFile)
        val params = ZipParameters().apply {
            fileNameInZip = "META-INF/xcj-watermark.txt"
        }
        zipFile.addFile(tempWatermark, params)

        logger.info("明文水印已嵌入(开源模式,推荐改用 embedEncrypted): $watermarkId")
        tempWatermark.delete()
    }
}

object InjectorConstants {
    const val VERSION = "0.2.0"
}

