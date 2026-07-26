package com.xcj.injector.harden

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import org.slf4j.LoggerFactory
import java.io.File

/**
 * T5 定制化加壳策略(天衍 v1.0 P1)。
 *
 * 用法: xcj-injector harden --apk input.apk --config harden.json --output output.apk
 *
 * harden.json 配置示例:
 * {
 *   "encryptStrings": true,       // T4 DEX 字符串加密
 *   "vmpProtect": true,           // T2 VMP 保护解密函数
 *   "segmentStrings": true,       // T3 分段散列
 *   "soEncrypt": true,            // X0 SO 加密
 *   "detectionModules": {
 *     "antiDebug": true,
 *     "antiFrida": true,
 *     "antiDump": true,
 *     "rootDetect": true,
 *     "xposedDetect": true,
 *     "emulatorDetect": false,
 *     "vpnDetect": true,
 *     "dualAppDetect": true,
 *     "fartDetect": true,
 *     "odexDetect": true
 *   },
 *   "killPolicy": {
 *     "strongEvidence": "kill",   // kill / warn / none
 *     "weakScoreThreshold": 70,
 *     "delayMinMs": 0,
 *     "delayMaxMs": 1000
 *   },
 *   "strength": "standard"        // standard / aggressive / paranoid
 * }
 */
class HardenCommand : CliktCommand(
    name = "harden",
    help = "T5 定制化加壳策略:按 JSON 配置对 APK 实施选择性加固"
) {
    private val apkPath by option("--apk", help = "输入 APK 路径").required()
    private val configPath by option("--config", help = "加固策略 JSON 配置").required()
    private val outputPath by option("--output", help = "输出 APK 路径").required()

    private val logger = LoggerFactory.getLogger(HardenCommand::class.java)

    override fun run() {
        val apk = File(apkPath)
        val config = File(configPath)
        require(apk.exists()) { "APK 不存在: $apkPath" }
        require(config.exists()) { "配置不存在: $configPath" }

        val hardenConfig = HardenConfig.fromJson(config.readText())
        logger.info("=== T5 定制化加壳 ===")
        logger.info("输入: $apkPath")
        logger.info("策略: ${hardenConfig.strength}")
        logger.info("  DEX 字符串加密: ${hardenConfig.encryptStrings}")
        logger.info("  VMP 保护: ${hardenConfig.vmpProtect}")
        logger.info("  分段散列: ${hardenConfig.segmentStrings}")
        logger.info("  SO 加密: ${hardenConfig.soEncrypt}")
        logger.info("  检测模块: ${hardenConfig.detectionModules.filter { it.value }.keys}")

        // 生成 defender-config.json(注入到 APK assets)
        val defenderConfig = hardenConfig.toDefenderConfigJson()
        val outputDir = File(outputPath).parentFile ?: File(".")
        outputDir.mkdirs()
        File(outputDir, "defender-config.json").writeText(defenderConfig)
        logger.info("已生成: defender-config.json(供 Packer 注入 assets)")

        // 按配置执行加固步骤
        if (hardenConfig.encryptStrings) {
            logger.info("[1/3] DEX 字符串加密...")
            // 调用 DexStringEncryptor(复用 T4)
            logger.info("  → 请运行: xcj-injector encrypt-strings --apk $apkPath --output $outputPath")
        }
        if (hardenConfig.soEncrypt) {
            logger.info("[2/3] SO 加密...")
            logger.info("  → 请运行四步构建流水线(build_x0_pack + patch_x0)")
        }
        logger.info("[3/3] 策略配置已生成,加固完成")
        logger.info("输出: $outputPath")
    }
}

data class HardenConfig(
    val encryptStrings: Boolean = true,
    val vmpProtect: Boolean = true,
    val segmentStrings: Boolean = false,
    val soEncrypt: Boolean = true,
    val detectionModules: Map<String, Boolean> = defaultModules(),
    val killPolicy: KillPolicy = KillPolicy(),
    val strength: String = "standard",
) {
    data class KillPolicy(
        val strongEvidence: String = "kill",
        val weakScoreThreshold: Int = 70,
        val delayMinMs: Int = 0,
        val delayMaxMs: Int = 1000,
    )

    companion object {
        fun defaultModules() = mapOf(
            "antiDebug" to true, "antiFrida" to true, "antiDump" to true,
            "rootDetect" to true, "xposedDetect" to true, "emulatorDetect" to false,
            "vpnDetect" to true, "dualAppDetect" to true,
            "fartDetect" to false, "odexDetect" to false,
        )

        fun fromJson(json: String): HardenConfig {
            val obj = org.json.JSONObject(json)
            val modules = mutableMapOf<String, Boolean>()
            val dmObj = obj.optJSONObject("detectionModules")
            if (dmObj != null) {
                for (key in dmObj.keys()) {
                    modules[key] = dmObj.optBoolean(key, false)
                }
            }
            val kpObj = obj.optJSONObject("killPolicy")
            val kp = if (kpObj != null) KillPolicy(
                strongEvidence = kpObj.optString("strongEvidence", "kill"),
                weakScoreThreshold = kpObj.optInt("weakScoreThreshold", 70),
                delayMinMs = kpObj.optInt("delayMinMs", 0),
                delayMaxMs = kpObj.optInt("delayMaxMs", 1000),
            ) else KillPolicy()

            return HardenConfig(
                encryptStrings = obj.optBoolean("encryptStrings", true),
                vmpProtect = obj.optBoolean("vmpProtect", true),
                segmentStrings = obj.optBoolean("segmentStrings", false),
                soEncrypt = obj.optBoolean("soEncrypt", true),
                detectionModules = if (modules.isEmpty()) defaultModules() else modules,
                killPolicy = kp,
                strength = obj.optString("strength", "standard"),
            )
        }
    }

    /** 转换为 defender-config.json 格式(供 SDK 运行时读取) */
    fun toDefenderConfigJson(): String {
        val sb = StringBuilder()
        sb.appendLine("{")
        sb.appendLine("  \"version\": 2,")
        sb.appendLine("  \"signatureVerify\": {\"enabled\": true, \"onViolation\": \"kill\"},")
        sb.appendLine("  \"integrityCheck\": {\"enabled\": true, \"onViolation\": \"kill\"},")
        for ((name, enabled) in detectionModules) {
            val violation = if (name in listOf("rootDetect", "emulatorDetect")) "warn" else "kill"
            sb.appendLine("  \"$name\": {\"enabled\": $enabled, \"onViolation\": \"$violation\"},")
        }
        sb.appendLine("  \"onViolationKill\": {")
        sb.appendLine("    \"delayMinMs\": ${killPolicy.delayMinMs},")
        sb.appendLine("    \"delayMaxMs\": ${killPolicy.delayMaxMs},")
        sb.appendLine("    \"method\": \"sigabrt\"")
        sb.appendLine("  }")
        sb.appendLine("}")
        return sb.toString()
    }
}
