package com.xcj.defender

import org.json.JSONObject

/**
 * Defender 配置(从 assets/defender-config.json 读取)
 *
 * 详见 ADR 0088 §config
 *
 * 默认全关,仅 signatureVerify + integrityCheck 默认开
 */
data class DefenderConfig(
    val version: Int = 1,
    val serverUrl: String = "",
    val appId: String = "",
    val signatureExpectedHash: String = "",

    val signatureVerify: ModuleConfig = ModuleConfig(enabled = true, onViolation = "kill"),
    val antiDebug: ModuleConfig = ModuleConfig(enabled = false, onViolation = "kill"),
    val antiFrida: ModuleConfig = ModuleConfig(enabled = false, onViolation = "kill"),
    val antiDump: ModuleConfig = ModuleConfig(enabled = false, onViolation = "kill"),
    val rootDetect: ModuleConfig = ModuleConfig(enabled = false, onViolation = "warn"),
    val xposedDetect: XposedConfig = XposedConfig(enabled = false, onViolation = "kill", killThreshold = 70),
    val emulatorDetect: ModuleConfig = ModuleConfig(enabled = false, onViolation = "warn"),
    val integrityCheck: ModuleConfig = ModuleConfig(enabled = true, onViolation = "kill"),

    val secureScreen: SecureScreenConfig = SecureScreenConfig(enabled = false, excludeActivities = emptyList()),

    val onViolationKill: KillConfig = KillConfig(
        delayMinMs = 3000,
        delayMaxMs = 15000,
        method = "sigabrt",
        showToast = true,
        toastMessage = "检测到安全风险"
    ),

    val report: ReportConfig = ReportConfig(enabled = false, throttleMs = 300000),

    /* M6:integrity 预期表(Packer 封装时生成,供 Native 层完整性校验) */
    val integrityCrcTable: List<String> = emptyList(), // 每项 "entry名:crc32hex"
    val integrityFileList: List<String> = emptyList(), // 每项一个 entry 名
) {

    data class ModuleConfig(
        val enabled: Boolean,
        val onViolation: String, // "kill" / "warn" / "none"
    )

    data class XposedConfig(
        val enabled: Boolean,
        val onViolation: String,
        val killThreshold: Int, // 0-100,≥ threshold 触发 kill
    )

    data class SecureScreenConfig(
        val enabled: Boolean,
        val excludeActivities: List<String>,
    )

    data class KillConfig(
        val delayMinMs: Int,
        val delayMaxMs: Int,
        val method: String, // "sigabrt" / "exit"
        val showToast: Boolean,
        val toastMessage: String,
    )

    data class ReportConfig(
        val enabled: Boolean,
        val throttleMs: Int,
    )

    companion object {
        /**
         * 从 JSON 字符串解析配置
         * 缺失字段使用默认值
         */
        @Suppress("NestedBlockDepth")
        fun fromJson(json: String): DefenderConfig {
            return try {
                val obj = JSONObject(json)

                val sigObj = obj.optJSONObject("signatureVerify")
                val antiDebugObj = obj.optJSONObject("antiDebug")
                val antiFridaObj = obj.optJSONObject("antiFrida")
                val antiDumpObj = obj.optJSONObject("antiDump")
                val rootObj = obj.optJSONObject("rootDetect")
                val xposedObj = obj.optJSONObject("xposedDetect")
                val emulatorObj = obj.optJSONObject("emulatorDetect")
                val integrityObj = obj.optJSONObject("integrityCheck")
                val secureScreenObj = obj.optJSONObject("secureScreen")
                val killObj = obj.optJSONObject("onViolationKill")
                val reportObj = obj.optJSONObject("report")

                DefenderConfig(
                    version = obj.optInt("version", 1),
                    serverUrl = obj.optString("serverUrl", ""),
                    appId = obj.optString("appId", ""),
                    signatureExpectedHash = obj.optString("signatureExpectedHash", ""),

                    signatureVerify = ModuleConfig(
                        enabled = sigObj?.optBoolean("enabled", true) ?: true,
                        onViolation = sigObj?.optString("onViolation", "kill") ?: "kill",
                    ),
                    antiDebug = ModuleConfig(
                        enabled = antiDebugObj?.optBoolean("enabled", false) ?: false,
                        onViolation = antiDebugObj?.optString("onViolation", "kill") ?: "kill",
                    ),
                    antiFrida = ModuleConfig(
                        enabled = antiFridaObj?.optBoolean("enabled", false) ?: false,
                        onViolation = antiFridaObj?.optString("onViolation", "kill") ?: "kill",
                    ),
                    antiDump = ModuleConfig(
                        enabled = antiDumpObj?.optBoolean("enabled", false) ?: false,
                        onViolation = antiDumpObj?.optString("onViolation", "kill") ?: "kill",
                    ),
                    rootDetect = ModuleConfig(
                        enabled = rootObj?.optBoolean("enabled", false) ?: false,
                        onViolation = rootObj?.optString("onViolation", "warn") ?: "warn",
                    ),
                    xposedDetect = XposedConfig(
                        enabled = xposedObj?.optBoolean("enabled", false) ?: false,
                        onViolation = xposedObj?.optString("onViolation", "kill") ?: "kill",
                        killThreshold = xposedObj?.optInt("killThreshold", 70) ?: 70,
                    ),
                    emulatorDetect = ModuleConfig(
                        enabled = emulatorObj?.optBoolean("enabled", false) ?: false,
                        onViolation = emulatorObj?.optString("onViolation", "warn") ?: "warn",
                    ),
                    integrityCheck = ModuleConfig(
                        enabled = integrityObj?.optBoolean("enabled", true) ?: true,
                        onViolation = integrityObj?.optString("onViolation", "kill") ?: "kill",
                    ),
                    secureScreen = SecureScreenConfig(
                        enabled = secureScreenObj?.optBoolean("enabled", false) ?: false,
                        excludeActivities = parseStringList(secureScreenObj?.optJSONArray("excludeActivities")),
                    ),
                    onViolationKill = KillConfig(
                        delayMinMs = killObj?.optInt("delayMinMs", 3000) ?: 3000,
                        delayMaxMs = killObj?.optInt("delayMaxMs", 15000) ?: 15000,
                        method = killObj?.optString("method", "sigabrt") ?: "sigabrt",
                        showToast = killObj?.optBoolean("showToast", true) ?: true,
                        toastMessage = killObj?.optString("toastMessage", "检测到安全风险") ?: "检测到安全风险",
                    ),
                    report = ReportConfig(
                        enabled = reportObj?.optBoolean("enabled", false) ?: false,
                        throttleMs = reportObj?.optInt("throttleMs", 300000) ?: 300000,
                    ),
                    integrityCrcTable = parseStringList(obj.optJSONArray("integrityCrcTable")),
                    integrityFileList = parseStringList(obj.optJSONArray("integrityFileList")),
                )
            } catch (e: Exception) {
                // JSON 解析失败,返回全默认配置(仅 signature + integrity 开)
                DefenderConfig()
            }
        }

        private fun parseStringList(arr: org.json.JSONArray?): List<String> {
            if (arr == null) return emptyList()
            return (0 until arr.length()).mapNotNull { idx ->
                arr.optString(idx, "")
            }.filter { it.isNotEmpty() }
        }
    }
}
