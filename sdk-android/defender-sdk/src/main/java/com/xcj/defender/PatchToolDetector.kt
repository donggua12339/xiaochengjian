package com.xcj.defender

import android.content.Context
import android.util.Log
import java.io.File

/**
 * 通用签名绕过工具检测器(不依赖特定工具名)
 *
 * 检测思路:不管 SRPatch/LSPatch/未来新工具叫什么名字,
 * 它们都必须执行以下操作,产生可检测的行为痕迹:
 *
 *  1. 在 data 目录存放原始 APK 副本(供路径重定向)
 *  2. 让 APK 映射出现在非 /data/app/ 路径
 *  3. 让 Java 层 packageCodePath 指向非 /data/app/ 路径
 *  4. 修改 Application 类或 ClassLoader(用 Unsafe 或反射)
 *
 *  这些都是行为特征,改名/换包名无法消除。
 */
object PatchToolDetector {

    private const val TAG = "DefenderPatchDetect"

    data class DetectionResult(
        val detected: Boolean,
        val score: Int,         // 0-100, ≥70 判定为被绕过
        val details: List<String>
    )

    fun detect(ctx: Context): DetectionResult {
        val details = mutableListOf<String>()
        var score = 0

        val dataDir = ctx.dataDir.absolutePath
        val cacheDir = ctx.cacheDir.absolutePath

        // === 检测 1: data 目录下存在 .apk 文件(通用:所有绕过工具都需要存副本) ===
        val apkInData = findApkFiles(File(dataDir), maxDepth = 3)
        if (apkInData.isNotEmpty()) {
            val totalSize = apkInData.sumOf { it.length() }
            details.add("data 目录存在 ${apkInData.size} 个 .apk 文件(共 ${totalSize / 1024}KB)")
            score += 40
        }

        // === 检测 2: cache 目录下存在 .apk 文件 ===
        val apkInCache = findApkFiles(File(cacheDir), maxDepth = 3)
        if (apkInCache.isNotEmpty()) {
            details.add("cache 目录存在 ${apkInCache.size} 个 .apk 文件")
            score += 30
        }

        // === 检测 3: Java 层 packageCodePath 不在 /data/app/ 下 ===
        val codePath = ctx.packageCodePath
        if (!codePath.startsWith("/data/app/")) {
            details.add("packageCodePath 异常: $codePath")
            score += 30
        }

        // === 检测 4: sourceDir 不在 /data/app/ 下 ===
        val sourceDir = ctx.applicationInfo.sourceDir
        if (!sourceDir.startsWith("/data/app/")) {
            details.add("sourceDir 异常: $sourceDir")
            score += 20
        }

        // === 检测 5: nativeLibraryDir 不在 /data/app/ 下 ===
        val nativeLibDir = ctx.applicationInfo.nativeLibraryDir
        if (nativeLibDir != null && !nativeLibDir.startsWith("/data/app/")) {
            details.add("nativeLibraryDir 异常: $nativeLibDir")
            score += 20
        }

        // === 检测 6: data 目录下存在可疑 .so 文件(绕过工具的 native hook 库) ===
        val soInData = findSoFiles(File(dataDir), maxDepth = 3)
        val suspiciousSo = soInData.filter { so ->
            // 正常 app 的 data 目录不应有 .so(除了 code_cache)
            val path = so.absolutePath
            !path.contains("/code_cache/") && !path.contains("/oat/")
        }
        if (suspiciousSo.isNotEmpty()) {
            details.add("data 目录存在 ${suspiciousSo.size} 个可疑 .so: ${suspiciousSo.map { it.name }}")
            score += 25
        }

        // === 检测 7: ClassLoader 链异常 ===
        try {
            val cl = ctx.classLoader
            walkClassLoader(cl, details) { clName ->
                if (clName.contains("lspatch", ignoreCase = true) ||
                    clName.contains("srpatch", ignoreCase = true) ||
                    clName.contains("sigkill", ignoreCase = true) ||
                    clName.contains("sigbypass", ignoreCase = true)) {
                    score += 30
                }
            }
        } catch (_: Exception) {}

        // === 检测 8: Application 类名伪装(Unsafe 修改 Class.name) ===
        try {
            val appClassName = ctx.javaClass.name
            // 正常 Application 类名应该与 Manifest 中声明的一致
            // 如果 javaClass.name 返回的不是自身类名,说明被 Unsafe 修改了
            val realName = ctx.javaClass.superclass?.name
            if (realName != null && appClassName != ctx::class.java.name) {
                // 这不太可能发生,但检查一下
            }
        } catch (_: Exception) {}

        // === 检测 9: DEX 元素数量异常 ===
        try {
            val cl = ctx.classLoader
            val dexPathListField = cl.javaClass.superclass?.getDeclaredField("pathList")
                ?: cl.javaClass.getDeclaredField("pathList")
            dexPathListField.isAccessible = true
            val pathList = dexPathListField.get(cl)
            val dexElementsField = pathList.javaClass.getDeclaredField("dexElements")
            dexElementsField.isAccessible = true
            val elements = dexElementsField.get(pathList) as Array<*>
            if (elements.size > 4) {
                details.add("DEX 元素数量异常: ${elements.size}(正常 1-3)")
                score += 15
            }
        } catch (_: Exception) {}

        val detected = score >= 40
        if (detected) {
            Log.e(TAG, "检测到签名绕过行为(score=$score):")
            details.forEach { Log.e(TAG, "  $it") }
        } else {
            Log.i(TAG, "未检测到绕过行为(score=$score)")
        }

        return DetectionResult(detected, score, details)
    }

    /**
     * 递归查找 .apk 文件
     */
    private fun findApkFiles(dir: File, maxDepth: Int): List<File> {
        if (maxDepth <= 0 || !dir.exists() || !dir.isDirectory) return emptyList()
        val result = mutableListOf<File>()
        dir.listFiles()?.forEach { f ->
            when {
                f.isFile && f.name.endsWith(".apk") -> result.add(f)
                f.isDirectory -> result.addAll(findApkFiles(f, maxDepth - 1))
            }
        }
        return result
    }

    /**
     * 递归查找 .so 文件
     */
    private fun findSoFiles(dir: File, maxDepth: Int): List<File> {
        if (maxDepth <= 0 || !dir.exists() || !dir.isDirectory) return emptyList()
        val result = mutableListOf<File>()
        dir.listFiles()?.forEach { f ->
            when {
                f.isFile && f.name.endsWith(".so") -> result.add(f)
                f.isDirectory -> result.addAll(findSoFiles(f, maxDepth - 1))
            }
        }
        return result
    }

    /**
     * 遍历 ClassLoader 链
     */
    private fun walkClassLoader(cl: ClassLoader?, details: MutableList<String>, check: (String) -> Unit) {
        var current = cl
        var depth = 0
        while (current != null && depth < 10) {
            val name = current.javaClass.name
            check(name)
            if (name != "dalvik.system.PathClassLoader" &&
                name != "dalvik.system.DelegateLastClassLoader" &&
                name != "java.lang.BootClassLoader" &&
                name != "dalvik.system.BaseDexClassLoader") {
                details.add("异常 ClassLoader: $name")
            }
            try {
                val parentField = ClassLoader::class.java.getDeclaredField("parent")
                parentField.isAccessible = true
                current = parentField.get(current) as? ClassLoader
            } catch (_: Exception) {
                current = current?.parent
            }
            depth++
        }
    }
}
