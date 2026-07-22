package com.xcj.defender.demo

import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import java.io.File

/**
 * Defender Demo MainActivity
 *
 * 展示 xcj-defender-sdk 所有模块的检测结果(YES=检测到风险 / NO=安全)
 *
 * 注意:本 Demo 使用占位实现,真实实现在 xcj-defender-sdk 中。
 * 占位实现模拟真实检测逻辑,用于验证 UI 和集成。
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

            // 汇总
            handler.post {
                updateSummary()
                updateLog()
            }
        }.start()
    }

    // === 占位检测实现(真实实现在 xcj-defender-sdk) ===

    /**
     * 1. SignatureVerifier:检查 APK 签名证书 hash
     * 占位实现:检查 APK 是否存在 + 签名证书 SHA-256
     */
    private fun checkSignature(): Boolean {
        return try {
            val apkPath = packageCodePath
            val apkFile = File(apkPath)
            if (!apkFile.exists()) {
                log("[SignatureVerifier] APK 文件不存在: $apkPath")
                return true  // 异常 = 风险
            }

            // 占位:检查 APK 文件是否可读
            val canRead = apkFile.canRead()
            log("[SignatureVerifier] APK 路径: $apkPath, 可读: $canRead")

            // 占位:真实实现会解析 V2/V3 签名块,提取证书 SHA-256
            // 这里只检查文件存在性
            !canRead  // 不可读 = 风险
        } catch (e: Exception) {
            log("[SignatureVerifier] 异常: ${e.message}")
            true
        }
    }

    /**
     * 2. AntiDebug:检查是否被调试
     * 占位实现:检查 /proc/self/status 的 TracerPid
     */
    private fun checkAntiDebug(): Boolean {
        return try {
            val status = File("/proc/self/status").readText()
            val tracerPid = status.lines()
                .find { it.startsWith("TracerPid:") }
                ?.substringAfter(":")
                ?.trim()
                ?.toIntOrNull() ?: 0

            log("[AntiDebug] TracerPid: $tracerPid")
            tracerPid != 0  // 非 0 = 被调试 = 风险
        } catch (e: Exception) {
            log("[AntiDebug] 异常: ${e.message}")
            false
        }
    }

    /**
     * 3. AntiFrida:检查 Frida
     * 占位实现:检查 /proc/self/maps 的 frida 特征 + 端口 27042
     */
    private fun checkAntiFrida(): Boolean {
        return try {
            // 检查 maps
            val maps = File("/proc/self/maps").readText()
            val fridaKeywords = listOf("frida", "gum-js-loop", "frida-agent", "gadget")
            val mapsDetected = fridaKeywords.any { maps.contains(it, ignoreCase = true) }
            log("[AntiFrida] maps 检测: $mapsDetected")

            // 检查端口 27042
            var portDetected = false
            try {
                val socket = java.net.Socket()
                socket.connect(java.net.InetSocketAddress("127.0.0.1", 27042), 100)
                portDetected = true
                socket.close()
            } catch (e: Exception) {
                // 连接失败 = 无 Frida
            }
            log("[AntiFrida] 端口 27042 检测: $portDetected")

            mapsDetected || portDetected
        } catch (e: Exception) {
            log("[AntiFrida] 异常: ${e.message}")
            false
        }
    }

    /**
     * 4. AntiDump:检查内存 dump
     * 占位实现:检查 /proc/self/mem 是否可读(占位,真实实现用 inotify)
     */
    private fun checkAntiDump(): Boolean {
        return try {
            val memFile = File("/proc/self/mem")
            val canRead = memFile.canRead()
            log("[AntiDump] /proc/self/mem 可读: $canRead")
            // 占位:真实实现用 inotify 监控 /proc/self/mem 的访问事件
            false  // 占位:无法检测,返回安全
        } catch (e: Exception) {
            log("[AntiDump] 异常: ${e.message}")
            false
        }
    }

    /**
     * 5. RootDetector:检查 Root
     * 占位实现:检查 su 路径 + Magisk 目录 + ro.secure
     */
    private fun checkRoot(): Boolean {
        return try {
            // 检查 su 路径
            val suPaths = listOf(
                "/system/xbin/su", "/system/bin/su", "/sbin/su",
                "/data/local/xbin/su", "/data/local/bin/su",
                "/data/adb/magisk/su"
            )
            val suDetected = suPaths.any { File(it).exists() }
            log("[RootDetector] su 路径检测: $suDetected")

            // 检查 Magisk 目录
            val magiskPaths = listOf("/sbin/.magisk", "/data/adb/magisk", "/data/adb/modules")
            val magiskDetected = magiskPaths.any { File(it).exists() }
            log("[RootDetector] Magisk 目录检测: $magiskDetected")

            // 检查 ro.secure
            var roSecure = true
            try {
                val process = Runtime.getRuntime().exec("getprop ro.secure")
                val result = process.inputStream.bufferedReader().readText().trim()
                roSecure = result != "0"
                log("[RootDetector] ro.secure: $result")
            } catch (e: Exception) {
                log("[RootDetector] getprop 异常: ${e.message}")
            }

            suDetected || magiskDetected || !roSecure
        } catch (e: Exception) {
            log("[RootDetector] 异常: ${e.message}")
            false
        }
    }

    /**
     * 6. XposedDetector:检查 Xposed/LSPosed
     * 占位实现:ClassLoader 检查 + maps 扫描 + 模块目录
     */
    private fun checkXposed(): Boolean {
        return try {
            // ClassLoader 检查
            var classLoaderDetected = false
            try {
                Class.forName("de.robv.android.xposed.XposedBridge")
                classLoaderDetected = true
            } catch (e: ClassNotFoundException) {
                // 未找到
            }
            log("[XposedDetector] ClassLoader 检测: $classLoaderDetected")

            // maps 扫描
            val maps = File("/proc/self/maps").readText()
            val xposedKeywords = listOf("XposedBridge", "edxposed", "lsposed", "lspatch", "riru", "zygisk")
            val mapsDetected = xposedKeywords.any { maps.contains(it, ignoreCase = true) }
            log("[XposedDetector] maps 检测: $mapsDetected")

            // 模块目录
            val modulesDir = File("/data/adb/modules/")
            var modulesDetected = false
            if (modulesDir.exists()) {
                val xposedModules = listOf("lsposed", "edxposed", "lspatch", "zygisk_lsposed", "riru_lsposed")
                modulesDetected = modulesDir.listFiles()?.any { file ->
                    xposedModules.any { file.name.contains(it, ignoreCase = true) }
                } ?: false
            }
            log("[XposedDetector] 模块目录检测: $modulesDetected")

            classLoaderDetected || mapsDetected || modulesDetected
        } catch (e: Exception) {
            log("[XposedDetector] 异常: ${e.message}")
            false
        }
    }

    /**
     * 7. EmulatorDetector:检查模拟器
     * 占位实现:Build 属性 + 传感器
     */
    private fun checkEmulator(): Boolean {
        return try {
            // Build 属性
            val buildProps = listOf(
                android.os.Build.FINGERPRINT,
                android.os.Build.MODEL,
                android.os.Build.MANUFACTURER,
                android.os.Build.BRAND,
                android.os.Build.DEVICE,
                android.os.Build.PRODUCT,
                android.os.Build.HARDWARE
            )
            val emulatorKeywords = listOf(
                "generic", "sdk", "google_sdk", "emulator", "virtual",
                "goldfish", "ranchu", "vbox", "nox", "bluestacks", "mumu"
            )
            val buildDetected = buildProps.any { prop ->
                emulatorKeywords.any { prop?.contains(it, ignoreCase = true) ?: false }
            }
            log("[EmulatorDetector] Build 属性检测: $buildDetected")

            // 传感器检测(模拟器通常无传感器)
            val sensorManager = getSystemService(SENSOR_SERVICE) as android.hardware.SensorManager
            val sensors = sensorManager.getSensorList(android.hardware.Sensor.TYPE_ALL)
            val noSensors = sensors.isEmpty()
            log("[EmulatorDetector] 传感器数量: ${sensors.size}, 无传感器: $noSensors")

            // 电话号码检测(模拟器通常无电话功能)
            var noPhone = false
            try {
                val telephony = getSystemService(TELEPHONY_SERVICE) as android.telephony.TelephonyManager
                noPhone = telephony.phoneType == android.telephony.TelephonyManager.PHONE_TYPE_NONE
                log("[EmulatorDetector] 电话类型: ${telephony.phoneType}, 无电话: $noPhone")
            } catch (e: Exception) {
                log("[EmulatorDetector] TelephonyManager 异常: ${e.message}")
            }

            buildDetected || noSensors || noPhone
        } catch (e: Exception) {
            log("[EmulatorDetector] 异常: ${e.message}")
            false
        }
    }

    /**
     * 8. IntegrityChecker:检查 APK 完整性
     * 占位实现:检查 APK 文件 CRC(占位,真实实现逐文件 CRC)
     */
    private fun checkIntegrity(): Boolean {
        return try {
            val apkPath = packageCodePath
            val apkFile = File(apkPath)
            if (!apkFile.exists()) {
                log("[IntegrityChecker] APK 文件不存在")
                return true
            }

            // 占位:检查 APK 文件是否可读
            val canRead = apkFile.canRead()
            log("[IntegrityChecker] APK 可读: $canRead")

            // 占位:真实实现会遍历所有 entry,算 CRC32,与预期比对
            !canRead  // 不可读 = 风险
        } catch (e: Exception) {
            log("[IntegrityChecker] 异常: ${e.message}")
            true
        }
    }

    /**
     * 9. WindowSecurer:检查防截屏
     * 占位实现:检查当前窗口是否设置了 FLAG_SECURE
     */
    private fun checkWindowSecure(): Boolean {
        return try {
            val window = window
            val flags = window.attributes.flags
            val isSecure = (flags and android.view.WindowManager.LayoutParams.FLAG_SECURE) != 0
            log("[WindowSecurer] FLAG_SECURE 已设置: $isSecure")

            // 占位:真实实现会在 DefenderInitProvider 中全局设置 FLAG_SECURE
            // 这里检查当前窗口是否已设置
            isSecure  // 已设置 = 安全(NO)
        } catch (e: Exception) {
            log("[WindowSecurer] 异常: ${e.message}")
            false
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
