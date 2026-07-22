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

    // ============= Batch 2:SignatureVerifier + AntiDebug + AntiFrida =============

    /**
     * 签名校验(三层:D + B + C)
     *
     * @param apkPath APK 文件路径
     * @param expectedSigHash 预期签名 hash(D 层,从服务端拉)
     * @param expectedApkHash 预期 APK 内容 hash(B 层,从 config 读)
     * @param serverSigHash 服务端签名 hash(C 层,无网传 null 跳过)
     * @param serverApkHash 服务端 APK hash(C 层,无网传 null 跳过)
     * @return 0=全通过 / 1=任一层失败 / -1=内部错误
     */
    external fun verifySignature(
        apkPath: String,
        expectedSigHash: String?,
        expectedApkHash: String?,
        serverSigHash: String?,
        serverApkHash: String?,
    ): Int

    /**
     * 反调试检测(TracerPid + wchan + inline syscall)
     *
     * @return 0=未被调试 / 1=被调试
     */
    external fun checkAntiDebug(): Int

    /**
     * 防 Frida 检测(同步:A+B+C,不含 D 后台扫描)
     *
     * @return 0=未检测到 / 1=检测到 Frida
     */
    external fun checkAntiFrida(): Int

    /**
     * 启动后台内存特征字符串扫描(D 层)
     *
     * 延迟 3-10 秒(随机),扫描 r-xp 段搜 LIBFRIDA/frida:rpc
     * 检测到 -> raise(SIGABRT)
     */
    external fun startFridaMemoryScan()

    // ============= Batch 3:RootDetector + IntegrityChecker + AntiDump =============

    /**
     * Root 检测(用户态 + BL 锁 + 内核级 + Zygisk/Shamiko)
     *
     * @return 0=未检测到 root / 1=检测到 root
     */
    external fun checkRoot(): Int

    /**
     * APK 完整性校验(层 2 CRC + 层 4 文件列表)
     *
     * @param apkPath APK 文件路径
     * @return 0=安全 / 1=kill / 2=warn / -1=内部错误
     */
    external fun checkIntegrity(apkPath: String): Int

    /**
     * 启动 AntiDump inotify 监控(后台常驻,事件驱动零开销)
     *
     * 监控 /proc/self/mem 的 IN_ACCESS 事件
     * 检测到访问 -> raise(SIGABRT)
     */
    external fun startAntiDumpMonitor()

    // ============= Batch 4:响应策略 =============

    /**
     * kill 响应:随机延迟后 SIGABRT / _exit
     *
     * @param delayMinMs 最小延迟(毫秒)
     * @param delayMaxMs 最大延迟(毫秒)
     * @param method     "sigabrt" / "exit"
     */
    external fun defenderKill(delayMinMs: Int, delayMaxMs: Int, method: String)

    /**
     * warn 限流检查
     *
     * @param violationKey 违规类型 key(如 "frida_detected")
     * @param throttleMs   限流周期(毫秒,0 = 不限流)
     * @return 1=应该上报(首次或已过限流期)/ 0=限流中跳过
     */
    external fun defenderWarn(violationKey: String, throttleMs: Int): Int
}
