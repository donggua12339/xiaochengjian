package com.xcj.defender

/**
 * Defender JNI 桥接声明
 *
 * 对应 C 文件:defender_jni.c
 *
 * 详见 ADR 0088 §技术架构
 */
object DefenderNative {

    private var loaded = false

    /**
     * 加载 defender so
     *
     * @param libName so 文件名(从 Manifest Meta-data "xcj.defender.lib" 读取,30 池随机名)
     * @return true=加载成功 / false=加载失败
     */
    fun load(context: android.content.Context, libName: String): Boolean {
        if (loaded) return true

        return try {
            // 从 lib/ 目录加载(系统只读,防篡改)
            // nativeLibraryDir = /data/app/xxx/lib/arm64(或 armeabi-v7a)
            val nativeLibDir = context.applicationInfo.nativeLibraryDir
            val soPath = "$nativeLibDir/$libName"
            System.load(soPath)
            loaded = true
            android.util.Log.i("DefenderNative", "so 加载成功: $soPath")
            true
        } catch (e: UnsatisfiedLinkError) {
            android.util.Log.e("DefenderNative", "so 加载失败: ${e.message}")
            // fallback: 尝试 System.loadLibrary(去掉 lib 前缀和 .so 后缀)
            try {
                val name = libName.removePrefix("lib").removeSuffix(".so")
                System.loadLibrary(name)
                loaded = true
                true
            } catch (e2: UnsatisfiedLinkError) {
                android.util.Log.e("DefenderNative", "fallback 加载失败: ${e2.message}")
                false
            }
        }
    }

    // ============= Batch 1:自校验 =============

    /**
     * .so .text 段 hash 自校验
     *
     * 读取 /proc/self/maps 找到 libxxx.so 的 r-xp 段(.text),
     * 计算 SHA-256,与 .rodata 段嵌入的预期 hash 比对。
     * 不匹配 -> .text 被内存 patch -> abort()
     *
     * @return 0=校验通过 / -1=校验失败(已 abort,不会返回)/ -2=内部错误
     */
    external fun selfVerify(): Int

    /**
     * 获取 defender 版本号
     */
    external fun getVersion(): String

    // ============= Batch 2:SignatureVerifier + AntiDebug + AntiFrida(待实现) =============
    // external fun verifySignature(expectedHash: String): Int
    // external fun checkAntiDebug(): Int
    // external fun checkAntiFrida(): Int

    // ============= Batch 3:RootDetector + IntegrityChecker + AntiDump(待实现) =============
    // external fun checkRoot(): Int
    // external fun checkIntegrity(apkPath: String, expectedHash: String): Int
    // external fun startAntiDumpMonitor(): Int

    // ============= 响应策略(待实现) =============
    // external fun defenderKill(delayMinMs: Int, delayMaxMs: Int, method: String)
}
