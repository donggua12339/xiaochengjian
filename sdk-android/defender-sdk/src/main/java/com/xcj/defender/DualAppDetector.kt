package com.xcj.defender

import android.content.Context
import android.os.Process
import android.util.Log
import java.io.File

/**
 * X6 双开/分身检测(玄甲 v1.0 P1,补齐 EmulatorDetector 未覆盖项)。
 *
 * 检测维度:
 *  A. UID 异常: Process.myUid() % 100000 != 0 → 多用户/分身(user_10 = 1000000+)
 *  B. /data/user/ 下存在 user_10/user_999 等多用户目录
 *  C. 虚拟框架特征路径: /data/user/0/pkg/virtual/, /data/data/pkg/virtual/
 *  D. 已知双开应用包名检测(平行空间/双开助手等)
 *  E. dataDir 路径包含多用户标识(非 /data/user/0/)
 *
 * 响应:warn(不 kill,双开不一定是攻击)。
 */
class DualAppDetector(private val context: Context) {

    companion object {
        private const val TAG = "DefenderDualApp"

        private val DUAL_APP_PACKAGES = listOf(
            "com.lbe.parallel.intl",      // 平行空间
            "com.excelliance.dualaid",    // 双开助手
            "com.lody.virtual",           // VirtualApp
            "com.polestar.super.clone",   // Super Clone
            "com.jumobile.multiapp",      // Multi App
            "info.cloneapp.app",          // Clone App
            "com.pwrd.hzwgbjx",           // 华为分身
            "com.miui.securitycenter",    // MIUI 分身(仅标记,不判定)
        )

        private val VIRTUAL_PATHS = listOf(
            "/virtual/",
            "/parallel/",
            "/clone/",
            "/multiapp/",
        )
    }

    data class Result(
        val detected: Boolean,
        val score: Int,
        val details: List<String>,
    )

    fun detect(): Result {
        val details = mutableListOf<String>()
        var score = 0

        if (checkUidAnomaly(details)) score += 40
        if (checkMultiUserDirs(details)) score += 25
        if (checkVirtualPaths(details)) score += 35
        if (checkDualAppPackages(details)) score += 20
        if (checkDataDirAnomaly(details)) score += 30

        val detected = score >= 50
        if (detected) {
            Log.e(TAG, "双开/分身检测: score=$score")
        } else {
            Log.i(TAG, "双开检测通过(score=$score)")
        }
        return Result(detected, score, details)
    }

    /** A: UID % 100000 异常(正常 user_0 的 uid = 10000+appId) */
    private fun checkUidAnomaly(details: MutableList<String>): Boolean {
        val uid = Process.myUid()
        val userId = uid / 100000
        if (userId != 0) {
            details.add("UID 异常: myUid=$uid, userId=$userId(非 user_0)")
            return true
        }
        return false
    }

    /** B: /data/user/ 下多用户目录 */
    private fun checkMultiUserDirs(details: MutableList<String>): Boolean {
        val userDir = File("/data/user")
        if (!userDir.exists()) return false
        val users = userDir.listFiles { f -> f.isDirectory && f.name != "0" }
        if (users != null && users.isNotEmpty()) {
            // 有多用户目录不一定异常(工作资料等),但结合其他信号加权
            val pkg = context.packageName
            for (u in users) {
                if (File(u, pkg).exists()) {
                    details.add("多用户目录存在本 app: /data/user/${u.name}/$pkg")
                    return true
                }
            }
        }
        return false
    }

    /** C: 虚拟框架特征路径 */
    private fun checkVirtualPaths(details: MutableList<String>): Boolean {
        val dataDir = context.dataDir.absolutePath
        for (vp in VIRTUAL_PATHS) {
            if (dataDir.contains(vp)) {
                details.add("dataDir 含虚拟框架路径: $vp")
                return true
            }
        }
        // 检查 /data/data/pkg/ 下是否有 virtual 子目录
        val virtualDir = File(context.dataDir, "virtual")
        if (virtualDir.exists()) {
            details.add("存在 virtual/ 子目录")
            return true
        }
        return false
    }

    /** D: 已知双开应用包名 */
    private fun checkDualAppPackages(details: MutableList<String>): Boolean {
        val pm = context.packageManager
        for (pkg in DUAL_APP_PACKAGES) {
            try {
                pm.getPackageInfo(pkg, 0)
                details.add("已安装双开应用: $pkg")
                return true
            } catch (e: Exception) {
                // 未安装,继续
            }
        }
        return false
    }

    /** E: dataDir 路径不在标准 /data/user/0/ 下 */
    private fun checkDataDirAnomaly(details: MutableList<String>): Boolean {
        val dataDir = context.dataDir.absolutePath
        // 正常: /data/user/0/com.xcj.defender.demo 或 /data/data/com.xcj.defender.demo
        if (!dataDir.startsWith("/data/user/0/") && !dataDir.startsWith("/data/data/")) {
            details.add("dataDir 路径异常(非标准位置)")
            return true
        }
        return false
    }
}
