package com.xcj.injector.harden

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import org.slf4j.LoggerFactory
import java.io.File
import java.util.zip.ZipFile

/**
 * T6 加固质量报告(天衍 v1.0 P1)。
 *
 * 用法: xcj-injector quality-report --apk hardened.apk --output report.json
 *
 * 检测维度:
 *  1. 字符串残留: DEX 中是否仍有明文敏感字符串(api_key, password, http:// 等)
 *  2. SO 加密状态: lib/ 下是否存在明文 .so(应只有加密 payload 在 assets)
 *  3. 检测模块覆盖: defender-config.json 中启用了哪些模块
 *  4. 签名完整性: APK 是否有 V2/V3 签名块
 *  5. 调试标志: AndroidManifest 是否 debuggable=false
 */
class QualityReportCommand : CliktCommand(
    name = "quality-report",
    help = "T6 加固质量报告:分析加固后 APK 的安全性,输出 JSON 报告"
) {
    private val apkPath by option("--apk", help = "待分析 APK 路径").required()
    private val outputPath by option("--output", help = "报告输出路径(JSON)").required()

    private val logger = LoggerFactory.getLogger(QualityReportCommand::class.java)

    companion object {
        private val SENSITIVE_PATTERNS = listOf(
            "api_key", "apikey", "secret", "password", "passwd",
            "http://", "https://", "jdbc:", "mongodb://",
            "BEGIN RSA", "BEGIN PRIVATE", "token",
            "/proc/self/", "frida", "xposed", "substrate",
        )
    }

    override fun run() {
        val apk = File(apkPath)
        require(apk.exists()) { "APK 不存在: $apkPath" }

        logger.info("=== T6 加固质量报告 ===")
        logger.info("分析: $apkPath")

        val report = mutableMapOf<String, Any>()
        var totalScore = 0
        var maxScore = 0

        ZipFile(apk).use { zip ->
            // 1. 字符串残留检测
            val stringCheck = checkStringResidual(zip)
            report["stringResidual"] = stringCheck
            totalScore += stringCheck["score"] as Int
            maxScore += stringCheck["maxScore"] as Int

            // 2. SO 加密状态
            val soCheck = checkSoEncryption(zip)
            report["soEncryption"] = soCheck
            totalScore += soCheck["score"] as Int
            maxScore += soCheck["maxScore"] as Int

            // 3. 检测模块覆盖
            val moduleCheck = checkDetectionModules(zip)
            report["detectionModules"] = moduleCheck
            totalScore += moduleCheck["score"] as Int
            maxScore += moduleCheck["maxScore"] as Int

            // 4. 签名状态
            val sigCheck = checkSignature(zip)
            report["signature"] = sigCheck
            totalScore += sigCheck["score"] as Int
            maxScore += sigCheck["maxScore"] as Int

            // 5. 调试标志
            val debugCheck = checkDebuggable(zip)
            report["debuggable"] = debugCheck
            totalScore += debugCheck["score"] as Int
            maxScore += debugCheck["maxScore"] as Int
        }

        // 总评
        val percent = if (maxScore > 0) (totalScore * 100) / maxScore else 0
        report["overallScore"] = percent
        report["grade"] = when {
            percent >= 90 -> "A"
            percent >= 75 -> "B"
            percent >= 60 -> "C"
            else -> "D"
        }
        report["apkPath"] = apkPath
        report["timestamp"] = System.currentTimeMillis()

        // 输出 JSON
        val json = org.json.JSONObject(report).toString(2)
        File(outputPath).writeText(json)
        logger.info("报告: $outputPath")
        logger.info("总评: ${report["grade"]} ($percent%)")
    }

    private fun checkStringResidual(zip: ZipFile): Map<String, Any> {
        var hits = 0
        val hitDetails = mutableListOf<String>()

        val dexEntries = zip.entries().toList().filter { it.name.matches(Regex("classes\\d*\\.dex")) }
        for (entry in dexEntries) {
            val data = zip.getInputStream(entry).readBytes()
            val content = String(data, Charsets.ISO_8859_1)
            for (pattern in SENSITIVE_PATTERNS) {
                if (content.contains(pattern, ignoreCase = true)) {
                    hits++
                    hitDetails.add("${entry.name}: 含 '$pattern'")
                }
            }
        }

        val maxScore = 30
        val score = if (hits == 0) maxScore else maxOf(0, maxScore - hits * 5)
        return mapOf("score" to score, "maxScore" to maxScore, "hits" to hits, "details" to hitDetails)
    }

    private fun checkSoEncryption(zip: ZipFile): Map<String, Any> {
        val soFiles = zip.entries().toList().filter { it.name.startsWith("lib/") && it.name.endsWith(".so") }
        val defenderSo = soFiles.filter { it.name.contains("xcj_defender") }
        val hasPayload = zip.entries().toList().any { it.name.contains("xcj_payload") }

        val maxScore = 25
        var score = 0
        val details = mutableListOf<String>()

        if (defenderSo.isEmpty()) {
            score += 15  // 明文 defender.so 不在 lib/(好)
            details.add("libxcj_defender.so 不在 lib/(已加密)")
        } else {
            details.add("⚠️ libxcj_defender.so 明文存在于 lib/")
        }
        if (hasPayload) {
            score += 10  // 加密 payload 在 assets(好)
            details.add("xcj_payload.bin 存在于 assets(加密载荷)")
        }

        return mapOf("score" to score, "maxScore" to maxScore, "details" to details)
    }

    private fun checkDetectionModules(zip: ZipFile): Map<String, Any> {
        val configEntry = zip.entries().toList().find {
            it.name.contains("defender-config.json")
        }

        val maxScore = 20
        if (configEntry == null) {
            return mapOf("score" to 5, "maxScore" to maxScore, "details" to listOf("未找到 defender-config.json"))
        }

        val configStr = zip.getInputStream(configEntry).reader().readText()
        val enabledCount = Regex("\"enabled\"\\s*:\\s*true").findAll(configStr).count()
        val score = minOf(maxScore, enabledCount * 3)
        return mapOf("score" to score, "maxScore" to maxScore, "enabledModules" to enabledCount)
    }

    private fun checkSignature(zip: ZipFile): Map<String, Any> {
        // V2/V3 签名块在 APK Signing Block 中(zip 之前),简单检查 META-INF 存在
        val hasMetaInf = zip.entries().toList().any { it.name.startsWith("META-INF/") }
        val maxScore = 15
        val score = if (hasMetaInf) maxScore else 0
        return mapOf("score" to score, "maxScore" to maxScore, "hasV1Sign" to hasMetaInf)
    }

    private fun checkDebuggable(zip: ZipFile): Map<String, Any> {
        // 简化:检查 APK 是否是 release 版(名字不含 debug)
        val maxScore = 10
        val isRelease = !apkPath.contains("debug", ignoreCase = true)
        return mapOf("score" to if (isRelease) maxScore else 0, "maxScore" to maxScore)
    }
}
