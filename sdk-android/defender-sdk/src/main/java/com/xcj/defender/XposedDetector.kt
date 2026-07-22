package com.xcj.defender

import android.content.Context
import android.util.Log
import java.io.File

/**
 * Xposed 检测器(Java 层)
 *
 * 详见 ADR 0088 §XposedDetector
 *
 * 检测方式:
 *  - 传统:ClassLoader 检查 + maps 扫描 + 模块目录
 *  - 行为一致性:Mount namespace(overlayfs)+ PackageManager 过滤
 *
 * 响应:按置信度评分,≥ 70 -> kill
 */
class XposedDetector(private val context: Context) {

    companion object {
        private const val TAG = "DefenderXposed"
    }

    /**
     * 传统检测 + 行为一致性检测组合
     *
     * @return 置信度分数(0-100)
     */
    fun detect(): Int {
        var score = 0

        // === 传统检测 ===
        if (checkClassLoader()) score += 30
        if (checkMaps()) score += 30
        if (checkModules()) score += 20

        // === 行为一致性检测(2026 新增) ===
        if (checkMountNamespace()) score += 60
        if (checkPackageFiltering()) score += 20

        Log.i(TAG, "Xposed 检测置信度: $score")
        return score
    }

    /**
     * A:ClassLoader 检查
     * Xposed 会注入 de.robv.android.xposed.XposedBridge 类
     */
    private fun checkClassLoader(): Boolean {
        return try {
            Class.forName("de.robv.android.xposed.XposedBridge")
            Log.e(TAG, "ClassLoader 检测到 XposedBridge")
            true
        } catch (e: ClassNotFoundException) {
            false
        }
    }

    /**
     * B:扫 /proc/self/maps 找 Xposed 特征
     */
    private fun checkMaps(): Boolean {
        return try {
            val maps = File("/proc/self/maps").readText()
            val keywords = listOf("XposedBridge", "edxposed", "lsposed", "lspatch", "riru", "zygisk")
            val detected = keywords.any { maps.contains(it, ignoreCase = true) }
            if (detected) Log.e(TAG, "maps 检测到 Xposed 特征")
            detected
        } catch (e: Exception) {
            false
        }
    }

    /**
     * C:扫 /data/adb/modules/ 找 Xposed 模块
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
     * D:Mount namespace 检测(行为一致性)
     * overlayfs 出现 = Zygisk/Shamiko 注入痕迹
     */
    private fun checkMountNamespace(): Boolean {
        return try {
            val mounts = File("/proc/self/mounts").readText()
            val overlayCount = mounts.lines().count { it.contains("overlay") }
            if (overlayCount > 0) {
                Log.e(TAG, "检测到 overlayfs 挂载($overlayCount 个,可能 Zygisk/Shamiko)")
                true
            } else {
                false
            }
        } catch (e: Exception) {
            false
        }
    }

    /**
     * E:PackageManager 过滤检测
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
