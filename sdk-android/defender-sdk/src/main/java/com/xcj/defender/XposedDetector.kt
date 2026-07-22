package com.xcj.defender

import android.content.Context
import android.util.Log
import java.io.File

/**
 * Xposed 检测器(Java 层 + Native maps)
 *
 * 详见 ADR 0088 §XposedDetector
 *
 * 整改后加权置信度规则(可解释、可审计):
 *  - 加载到 XposedBridge 相关 jar/dex/so      → +40
 *  - 异常栈出现 Xposed 相关调用               → +20
 *  - ClassLoader 链异常(注入额外 ClassLoader) → +30
 *  - 模块目录(/data/adb/modules)Xposed 模块   → +20
 *  - /system 或 /vendor overlayfs 挂载        → +30
 *  - Xposed/Magisk 包名可查询(未被隐藏)       → +20
 *  - 综合置信度 ≥70 判定为 Xposed 环境
 *
 * 所有命中项记录结构化日志(检测项 + 增减 + 最终置信度)。
 */
class XposedDetector(private val context: Context) {

    companion object {
        private const val TAG = "DefenderXposed"
        private const val THRESHOLD = 70
    }

    /**
     * 加权置信度检测
     *
     * @return 置信度分数(0-100,≥70 判定为 Xposed 环境)
     */
    fun detect(): Int {
        var score = 0
        val hits = mutableListOf<String>()

        // 整改 1:XposedBridge 相关 jar/dex/so 加载(maps)→ +40
        if (checkXposedLibraries()) {
            score += 40
            hits.add("XposedBridge jar/dex/so 加载 +40")
        }

        // 整改 2:异常栈出现 Xposed 相关调用 → +20
        if (checkStackTrace()) {
            score += 20
            hits.add("异常栈 Xposed 调用 +20")
        }

        // 整改 3:ClassLoader 链异常(注入额外 ClassLoader)→ +30
        if (checkClassLoaderAnomaly()) {
            score += 30
            hits.add("ClassLoader 链异常 +30")
        }

        // 辅助:模块目录 Xposed 模块 → +20
        if (checkModules()) {
            score += 20
            hits.add("模块目录 Xposed +20")
        }

        // 辅助:/system 或 /vendor overlayfs 挂载 → +30
        if (checkMountNamespace()) {
            score += 30
            hits.add("overlayfs 挂载 +30")
        }

        // 辅助:Xposed/Magisk 包名可查询 → +20
        if (checkPackageFiltering()) {
            score += 20
            hits.add("包名可查询 +20")
        }

        val finalScore = score.coerceIn(0, 100)
        Log.i(TAG, "Xposed 检测: 置信度=$finalScore 阈值=$THRESHOLD 命中=$hits")
        return finalScore
    }

    /**
     * 整改 1:扫 /proc/self/maps 找 XposedBridge 相关 jar/dex/so
     *
     * Xposed/LSPosed 注入后会加载 XposedBridge.jar、libxposed.so 等,
     * 这些会出现在 /proc/self/maps 的映射中。
     */
    private fun checkXposedLibraries(): Boolean {
        return try {
            val maps = File("/proc/self/maps").readText()
            val keywords = listOf(
                "XposedBridge.jar", "XposedBridge", "xposedbridge",
                "libxposed", "edxposed", "lsposed", "lspatch",
                "riru", "zygisk"
            )
            val hit = keywords.any { maps.contains(it, ignoreCase = true) }
            if (hit) Log.e(TAG, "maps 检测到 Xposed 库特征")
            hit
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 整改 2:自造异常读取调用栈,检查 Xposed 相关调用
     *
     * Xposed hook 方法时,调用栈会出现 de.robv.android.xposed.XposedBridge
     * 或 LSPHooker 等类。通过 new Throwable().getStackTrace() 读取当前栈。
     */
    private fun checkStackTrace(): Boolean {
        return try {
            val stackTrace = Throwable().stackTrace
            val xposedKeywords = listOf(
                "de.robv.android.xposed.XposedBridge",
                "de.robv.android.xposed.XposedHelpers",
                "LSPHooker", "XposedHooker"
            )
            val hit = stackTrace.any { element ->
                xposedKeywords.any {
                    element.className.contains(it) || element.methodName.contains(it)
                }
            }
            if (hit) Log.e(TAG, "调用栈检测到 Xposed hook 调用")
            hit
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 整改 3:ClassLoader 链异常检测(基于 ART 内存布局特征)
     *
     * 正常 APP 的 ClassLoader 链:PathClassLoader → BootClassLoader(约 2 层)。
     * Xposed/LSPosed 注入会插入额外的 ClassLoader(如用于加载 XposedBridge.jar),
     * 导致 ClassLoader 链异常增长或出现 Xposed 相关 ClassLoader。
     *
     * 检测点:
     *  1. ClassLoader 链中出现 Xposed/Hooker 相关类名
     *  2. ClassLoader 链深度异常(> 5 层,正常约 2-3 层)
     */
    private fun checkClassLoaderAnomaly(): Boolean {
        return try {
            var classLoader = context.classLoader
            var depth = 0
            val seen = mutableSetOf<String>()
            while (classLoader != null && depth < 100) {
                val name = classLoader.javaClass.name
                if (!seen.add(name)) break  // 避免循环引用

                // ClassLoader 链中出现 Xposed 相关类名
                if (name.contains("xposed", ignoreCase = true) ||
                    name.contains("Hooker", ignoreCase = true)
                ) {
                    Log.e(TAG, "ClassLoader 链检测到 Xposed 相关: $name")
                    return true
                }
                classLoader = classLoader.parent
                depth++
            }
            // ClassLoader 链深度异常(正常 APP 约 2-3 层)
            if (depth > 5) {
                Log.e(TAG, "ClassLoader 链深度异常: $depth 层(正常约 2-3 层)")
                return true
            }
            false
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 辅助:扫 /data/adb/modules/ 找 Xposed 模块
     */
    private fun checkModules(): Boolean {
        return try {
            val dir = File("/data/adb/modules/")
            if (!dir.exists()) return false

            val xposedModules = listOf("lsposed", "edxposed", "lspatch", "zygisk_lsposed", "riru_lsposed")
            val detected = dir.listFiles()?.any { file ->
                xposedModules.any { file.name.contains(it, ignoreCase = true) }
            } ?: false

            if (detected) Log.e(TAG, "模块目录检测到 Xposed")
            detected
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 辅助:Mount namespace 检测
     * /system 或 /vendor 的 overlayfs 挂载 = Zygisk/Shamiko 注入痕迹
     */
    private fun checkMountNamespace(): Boolean {
        return try {
            val mounts = File("/proc/self/mounts").readText()
            // Android 12+ 用 overlayfs 做灰度更新,只检测 /system 或 /vendor 的 overlay
            val suspiciousOverlay = mounts.lines().any {
                it.contains("overlay") && (it.contains(" /system ") || it.contains(" /vendor "))
            }
            if (suspiciousOverlay) {
                Log.e(TAG, "检测到 /system 或 /vendor 的 overlayfs 挂载(可能 Zygisk/Shamiko)")
            }
            suspiciousOverlay
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 辅助:PackageManager 过滤检测
     * Xposed/Magisk 会隐藏自己的包名,但可通过 getPackageInfo 直接查询
     */
    private fun checkPackageFiltering(): Boolean {
        val criticalPackages = listOf(
            "com.topjohnwu.magisk",
            "org.lsposed.manager",
            "de.robv.android.xposed.installer",
        )

        for (pkg in criticalPackages) {
            try {
                context.packageManager.getPackageInfo(pkg, 0)
                Log.e(TAG, "检测到 Xposed/Magisk 包: $pkg")
                return true
            } catch (e: Exception) {
                // 包不存在,继续
            }
        }
        return false
    }
}
