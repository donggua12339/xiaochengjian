package com.xcj.defender.demo

import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.xcj.defender.DefenderNative
import com.xcj.defender.EmulatorDetector
import com.xcj.defender.KeyAttestationDetector
import com.xcj.defender.XposedDetector

/**
 * Defender Demo MainActivity
 *
 * 展示 xcj-defender-sdk 所有模块的检测结果(YES=检测到风险 / NO=安全)
 *
 * 接入真实 xcj-defender-sdk 模块(依赖 defender-sdk .aar):
 *  - Native 模块:SignatureVerifier / AntiDebug / AntiFrida / AntiDump / RootDetector / IntegrityChecker
 *  - Java 模块:XposedDetector / EmulatorDetector / WindowSecurer
 *
 * defender-config.json 配置所有模块 onViolation=none,检测只记日志不响应(避免 demo 被 kill)。
 */
class MainActivity : AppCompatActivity() {

    private val logBuilder = StringBuilder()
    private val handler = Handler(Looper.getMainLooper())

    // 检测结果
    private val results = mutableMapOf<String, Boolean>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        findViewById<Button>(R.id.btn_rescan).setOnClickListener {
            runAllChecks()
        }

        findViewById<Button>(R.id.btn_verification).setOnClickListener {
            startActivity(android.content.Intent(this, VerificationActivity::class.java))
        }

        // 启动时自动检测
        runAllChecks()
    }

    private fun runAllChecks() {
        logBuilder.clear()
        log("=== 开始检测 ${System.currentTimeMillis()} ===")

        // 在后台线程执行检测(避免阻塞 UI)
        Thread {
            // 1. SignatureVerifier(签名校验)
            val signatureResult = checkSignature()
            setResult("signature", signatureResult, "SignatureVerifier")

            // 2. AntiDebug(反调试)
            val antiDebugResult = checkAntiDebug()
            setResult("anti_debug", antiDebugResult, "AntiDebug")

            // 3. AntiFrida(防 Frida)
            val antiFridaResult = checkAntiFrida()
            setResult("anti_frida", antiFridaResult, "AntiFrida")

            // 4. AntiDump(防内存 Dump)
            val antiDumpResult = checkAntiDump()
            setResult("anti_dump", antiDumpResult, "AntiDump")

            // 5. RootDetector(Root 检测)
            val rootResult = checkRoot()
            setResult("root", rootResult, "RootDetector")

            // 6. XposedDetector(Xposed 检测)
            val xposedResult = checkXposed()
            setResult("xposed", xposedResult, "XposedDetector")

            // 7. EmulatorDetector(模拟器检测)
            val emulatorResult = checkEmulator()
            setResult("emulator", emulatorResult, "EmulatorDetector")

            // 8. IntegrityChecker(APK 完整性)
            val integrityResult = checkIntegrity()
            setResult("integrity", integrityResult, "IntegrityChecker")

            // 9. WindowSecurer(防截屏)
            val windowResult = checkWindowSecure()
            setResult("window", windowResult, "WindowSecurer")

            // 10. KeyAttestation(硬件级 root 检测,只 log 不占 UI 槽位)
            checkKeyAttestation()

            // 汇总
            handler.post {
                updateSummary()
                updateLog()
            }
        }.start()
    }

    // === 真实检测实现(调用 xcj-defender-sdk) ===

    /**
     * 1. SignatureVerifier:调用 DefenderNative.verifySignature
     * @return true=风险(校验失败) / false=安全
     */
    private fun checkSignature(): Boolean {
        return try {
            val apkPath = packageCodePath
            // demo 无预期 hash(传 null),D 层无 expected 时跳过
            val result = DefenderNative.verifySignature(apkPath, null, null, null, null)
            log("[SignatureVerifier] verifySignature 返回: $result (0=通过)")
            result != 0
        } catch (e: Exception) {
            log("[SignatureVerifier] 异常: ${e.message}")
            false
        }
    }

    /**
     * 2. AntiDebug:调用 DefenderNative.checkAntiDebug
     * @return true=被调试 / false=未调试
     */
    private fun checkAntiDebug(): Boolean {
        return try {
            val result = DefenderNative.checkAntiDebug()
            log("[AntiDebug] checkAntiDebug 返回: $result (1=被调试)")
            result == 1
        } catch (e: Exception) {
            log("[AntiDebug] 异常: ${e.message}")
            false
        }
    }

    /**
     * 3. AntiFrida:调用 DefenderNative.checkAntiFrida(同步 A+B+C)
     * @return true=检测到 Frida / false=未检测
     */
    private fun checkAntiFrida(): Boolean {
        return try {
            val result = DefenderNative.checkAntiFrida()
            log("[AntiFrida] checkAntiFrida 返回: $result (1=检测到 Frida)")
            result == 1
        } catch (e: Exception) {
            log("[AntiFrida] 异常: ${e.message}")
            false
        }
    }

    /**
     * 4. AntiDump:后台 inotify 监控,无同步检测 API
     * DefenderInitProvider 已启动后台监控(若 antiDump.enabled),此处仅说明
     */
    private fun checkAntiDump(): Boolean {
        log("[AntiDump] 后台 inotify 监控运行中(无同步检测,由 DefenderInitProvider 启动)")
        return false  // 无法同步检测,始终返回安全
    }

    /**
     * 5. RootDetector:调用 DefenderNative.checkRoot
     * @return true=检测到 root / false=未 root
     */
    private fun checkRoot(): Boolean {
        return try {
            val result = DefenderNative.checkRoot()
            log("[RootDetector] checkRoot 返回: $result (1=检测到 root)")
            result == 1
        } catch (e: Exception) {
            log("[RootDetector] 异常: ${e.message}")
            false
        }
    }

    /**
     * 6. XposedDetector:调用 XposedDetector.detect
     * @return true=检测到 Xposed(置信度 >=70) / false=未检测
     */
    private fun checkXposed(): Boolean {
        return try {
            val score = XposedDetector(this).detect()
            log("[XposedDetector] 置信度: $score (>=70 判定为 Xposed)")
            score >= 70
        } catch (e: Exception) {
            log("[XposedDetector] 异常: ${e.message}")
            false
        }
    }

    /**
     * 7. EmulatorDetector:调用 EmulatorDetector.detect
     * @return true=模拟器 / false=真机
     */
    private fun checkEmulator(): Boolean {
        return try {
            val isEmulator = EmulatorDetector(this).detect()
            log("[EmulatorDetector] 检测结果: $isEmulator")
            isEmulator
        } catch (e: Exception) {
            log("[EmulatorDetector] 异常: ${e.message}")
            false
        }
    }

    /**
     * 8. IntegrityChecker:调用 DefenderNative.checkIntegrity
     * demo 无预期表(传空 JSON),层 2/4 跳过
     * @return true=篡改 / false=安全
     */
    private fun checkIntegrity(): Boolean {
        return try {
            val apkPath = packageCodePath
            val result = DefenderNative.checkIntegrity(apkPath, "[]", "[]")
            log("[IntegrityChecker] checkIntegrity 返回: $result (0=安全, demo 无预期表跳过)")
            result != 0
        } catch (e: Exception) {
            log("[IntegrityChecker] 异常: ${e.message}")
            false
        }
    }

    /**
     * 9. WindowSecurer:检查 FLAG_SECURE 是否设置
     * @return true=有截屏风险(FLAG_SECURE 未设置) / false=防截屏生效
     */
    private fun checkWindowSecure(): Boolean {
        return try {
            val flags = window.attributes.flags
            val isSecure = (flags and android.view.WindowManager.LayoutParams.FLAG_SECURE) != 0
            log("[WindowSecurer] FLAG_SECURE 已设置: $isSecure (demo secureScreen 未启用则为 false)")
            !isSecure  // 未设置 FLAG_SECURE = 截屏风险
        } catch (e: Exception) {
            log("[WindowSecurer] 异常: ${e.message}")
            false
        }
    }

    /**
     * 10. KeyAttestation:硬件级 root 检测(2026 最强)
     * 返回置信度分数,只 log 展示(不占 UI 槽位)
     */
    private fun checkKeyAttestation() {
        try {
            val score = KeyAttestationDetector().detect()
            val verdict = when {
                score >= 60 -> "高风险(root/BL 解锁)"
                score > 0 -> "可疑"
                else -> "完整"
            }
            log("[KeyAttestation] 分数: $score ($verdict, >=60 高风险)")
        } catch (e: Exception) {
            log("[KeyAttestation] 异常: ${e.message}")
        }
    }

    // === UI 更新 ===

    private fun setResult(module: String, detected: Boolean, name: String) {
        results[module] = detected
        val resultText = if (detected) "YES" else "NO"
        val color = if (detected) Color.RED else Color.GREEN

        handler.post {
            val viewId = resources.getIdentifier("result_$module", "id", packageName)
            if (viewId != 0) {
                val tv = findViewById<TextView>(viewId)
                tv.text = resultText
                tv.setTextColor(color)
            }
        }

        log("[$name] 检测结果: $resultText")
    }

    private fun updateSummary() {
        val total = results.size
        val detected = results.values.count { it }
        val safe = total - detected

        val summaryText = "总计: $total 个模块\n检测到风险: $detected 个\n安全: $safe 个"
        val summaryColor = if (detected > 0) Color.RED else Color.GREEN

        findViewById<TextView>(R.id.result_summary).apply {
            text = summaryText
            setTextColor(summaryColor)
        }

        // 如果有风险,显示 Toast
        if (detected > 0) {
            Toast.makeText(this, "检测到 $detected 个安全风险!", Toast.LENGTH_LONG).show()
        }
    }

    private fun updateLog() {
        findViewById<TextView>(R.id.tv_log).text = logBuilder.toString()
    }

    private fun log(msg: String) {
        logBuilder.appendLine(msg)
        android.util.Log.d(DefenderTestApp.TAG, msg)
    }
}
