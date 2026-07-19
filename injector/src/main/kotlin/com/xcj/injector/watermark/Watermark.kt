package com.xcj.injector.watermark

import org.slf4j.LoggerFactory
import net.lingala.zip4j.ZipFile
import net.lingala.zip4j.model.ZipParameters
import java.io.File

/**
 * 注入水印(防滥用追溯,ADR 0030)
 *
 * 在 APK 内写入 watermark.txt,包含:
 *  - 注入工具版本
 *  - 开发者 ID
 *  - 注入时间戳
 *
 * 水印明文可读(让开发者自查),但无法被破解者擦除(重打包后水印仍在)
 */
class Watermark {
    private val logger = LoggerFactory.getLogger(Watermark::class.java)

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

        logger.info("水印已嵌入: $watermarkId")
        tempWatermark.delete()
    }
}

object InjectorConstants {
    const val VERSION = "0.2.0"
}
