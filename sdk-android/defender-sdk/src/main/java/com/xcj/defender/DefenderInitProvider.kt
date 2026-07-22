package com.xcj.defender

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.net.Uri
import android.util.Log

/**
 * Defender 初始化 Provider
 *
 * ContentProvider.onCreate() 是 APK 启动时最早执行的代码点(先于 Application.onCreate),
 * 适合做 defender 初始化:
 *
 *  1. 加载 libxxx.so(从 Manifest Meta-data 读 .so 名,30 池随机名)
 *  2. Native self_verify(.text hash 自校验,防内存 patch)
 *  3. 读取 assets/defender-config.json
 *  4. 后续模块按 config 启动(Batch 2/3/4 实现)
 *
 * 详见 ADR 0088 §初始化流程
 */
class DefenderInitProvider : ContentProvider() {

    override fun onCreate(): Boolean {
        val ctx = context ?: return false
        Log.i(TAG, "DefenderInitProvider onCreate: 开始初始化")

        try {
            // 1. 读取 .so 名(从 Manifest Meta-data,30 池随机选)
            val libName = readLibNameFromManifest(ctx)
            if (libName.isNullOrEmpty()) {
                Log.w(TAG, "未找到 xcj.defender.lib Meta-data,跳过 defender 初始化")
                return true  // 不阻断 APP 启动
            }

            // 2. 加载 so
            val loaded = DefenderNative.load(ctx, libName)
            if (!loaded) {
                Log.e(TAG, "so 加载失败,跳过 defender 初始化")
                return true
            }

            // 3. self_verify(.text hash 自校验)
            Log.i(TAG, "执行 self_verify(.text hash 自校验)")
            val verifyResult = DefenderNative.selfVerify()
            when (verifyResult) {
                0 -> Log.i(TAG, "self_verify 通过")
                -1 -> {
                    // 校验失败,abort() 已在 Native 层触发,不会走到这里
                    Log.e(TAG, "self_verify 失败(.text 被篡改)")
                }
                -2 -> Log.w(TAG, "self_verify 内部错误(非致命)")
                else -> Log.w(TAG, "self_verify 未知返回: $verifyResult")
            }

            // 4. 读取 config
            val config = readConfig(ctx)
            Log.i(TAG, "config 加载完成: appId=${config.appId}, sigVerify=${config.signatureVerify.enabled}")

            // 5. 保存 config 到 DefenderInit(供后续模块使用)
            DefenderInit.config = config
            DefenderInit.context = ctx.applicationContext
            DefenderInit.initialized = true

            // 6. Batch 2:SignatureVerifier + AntiDebug + AntiFrida
            runBatch2Modules(ctx, config)

            // 7. Batch 3:RootDetector + IntegrityChecker + AntiDump
            runBatch3Modules(ctx, config)

            // 8. Batch 4:XposedDetector + EmulatorDetector + WindowSecurer + 响应策略
            runBatch4Modules(ctx, config)

            Log.i(TAG, "Defender 初始化完成(版本: ${DefenderNative.getVersion()})")
        } catch (e: Exception) {
            Log.e(TAG, "Defender 初始化异常: ${e.message}", e)
            // 不阻断 APP 启动
        }

        return true
    }

    /**
     * 从 Manifest Meta-data 读取 .so 名
     *
     * Packer 封装时写入:
     * <meta-data android:name="xcj.defender.lib" android:value="libsec_helper.so" />
     */
    private fun readLibNameFromManifest(ctx: Context): String? {
        return try {
            val ai = ctx.packageManager.getApplicationInfo(
                ctx.packageName,
                android.content.pm.PackageManager.GET_META_DATA
            )
            ai.metaData?.getString("xcj.defender.lib")
        } catch (e: Exception) {
            Log.w(TAG, "读取 Meta-data 失败: ${e.message}")
            null
        }
    }

    /**
     * 读取 assets/defender-config.json
     */
    private fun readConfig(ctx: Context): DefenderConfig {
        return try {
            val json = ctx.assets.open("defender-config.json").bufferedReader().use { it.readText() }
            DefenderConfig.fromJson(json)
        } catch (e: Exception) {
            Log.w(TAG, "读取 defender-config.json 失败,使用默认配置: ${e.message}")
            DefenderConfig()
        }
    }

    /**
     * Batch 2 模块:SignatureVerifier + AntiDebug + AntiFrida
     *
     * 按 config 启用状态执行,检测到风险按 onViolation 响应
     */
    private fun runBatch2Modules(ctx: Context, config: DefenderConfig) {
        // AntiDebug(启动时 1 次)
        if (config.antiDebug.enabled) {
            Log.i(TAG, "[Batch 2] AntiDebug 检测中...")
            val antiDebugResult = DefenderNative.checkAntiDebug()
            if (antiDebugResult == 1) {
                Log.e(TAG, "[Batch 2] AntiDebug 检测到调试器!")
                // TODO: 按 config.antiDebug.onViolation 响应(kill/warn)
                // 由 Batch 4 的 DefenderResponse 统一处理
            } else {
                Log.i(TAG, "[Batch 2] AntiDebug 通过")
            }
        }

        // AntiFrida(同步 A+B+C)
        if (config.antiFrida.enabled) {
            Log.i(TAG, "[Batch 2] AntiFrida 检测中...")
            val antiFridaResult = DefenderNative.checkAntiFrida()
            if (antiFridaResult == 1) {
                Log.e(TAG, "[Batch 2] AntiFrida 检测到 Frida!")
                // TODO: 按 config.antiFrida.onViolation 响应
            } else {
                Log.i(TAG, "[Batch 2] AntiFrida 通过(同步)")
                // 启动 D 层后台内存扫描
                DefenderNative.startFridaMemoryScan()
            }
        }

        // SignatureVerifier(启动时 1 次)
        if (config.signatureVerify.enabled) {
            Log.i(TAG, "[Batch 2] SignatureVerifier 检测中...")
            val apkPath = ctx.packageCodePath
            // TODO: 从服务端拉 expectedSignatureHash(C 层)
            // 目前用 config 里的(可能为空,跳过 D 层)
            val sigResult = DefenderNative.verifySignature(
                apkPath,
                null,  // D 层:从服务端拉(待实现)
                null,  // B 层:从 config 读(待实现)
                null,  // C 层:服务端 hash(待实现)
                null,  // C 层:服务端 apk hash(待实现)
            )
            if (sigResult != 0) {
                Log.e(TAG, "[Batch 2] SignatureVerifier 校验失败!")
                // TODO: 按 config.signatureVerify.onViolation 响应
            } else {
                Log.i(TAG, "[Batch 2] SignatureVerifier 通过(占位,待服务端 hash 接入)")
            }
        }
    }

    /**
     * Batch 3 模块:RootDetector + IntegrityChecker + AntiDump
     */
    private fun runBatch3Modules(ctx: Context, config: DefenderConfig) {
        // RootDetector(启动时 1 次)
        if (config.rootDetect.enabled) {
            Log.i(TAG, "[Batch 3] RootDetector 检测中...")
            val rootResult = DefenderNative.checkRoot()
            if (rootResult == 1) {
                Log.e(TAG, "[Batch 3] RootDetector 检测到 Root!")
                // TODO: 按 config.rootDetect.onViolation 响应(warn)
            } else {
                Log.i(TAG, "[Batch 3] RootDetector 通过")
            }
        }

        // IntegrityChecker(启动时 1 次)
        if (config.integrityCheck.enabled) {
            Log.i(TAG, "[Batch 3] IntegrityChecker 检测中...")
            val apkPath = ctx.packageCodePath
            val integrityResult = DefenderNative.checkIntegrity(apkPath)
            when (integrityResult) {
                0 -> Log.i(TAG, "[Batch 3] IntegrityChecker 通过")
                1 -> Log.e(TAG, "[Batch 3] IntegrityChecker 检测到篡改(kill)!")
                2 -> Log.w(TAG, "[Batch 3] IntegrityChecker 检测到额外文件(warn)")
                else -> Log.w(TAG, "[Batch 3] IntegrityChecker 内部错误")
            }
        }

        // AntiDump(启动后台监控)
        if (config.antiDump.enabled) {
            Log.i(TAG, "[Batch 3] AntiDump 启动监控...")
            DefenderNative.startAntiDumpMonitor()
        }
    }

    /**
     * Batch 4 模块:XposedDetector + EmulatorDetector + WindowSecurer + 响应策略
     *
     * Java 层检测模块 + Native 响应策略(kill/warn)
     */
    private fun runBatch4Modules(ctx: Context, config: DefenderConfig) {
        // XposedDetector(置信度评分,≥ killThreshold 触发响应)
        if (config.xposedDetect.enabled) {
            Log.i(TAG, "[Batch 4] XposedDetector 检测中...")
            val xposedScore = XposedDetector(ctx).detect()
            if (xposedScore >= config.xposedDetect.killThreshold) {
                Log.e(TAG, "[Batch 4] XposedDetector 红色(置信度 $xposedScore >= ${config.xposedDetect.killThreshold})")
                when (config.xposedDetect.onViolation) {
                    "kill" -> DefenderResponse.kill(ctx, config.onViolationKill)
                    "warn" -> DefenderResponse.warn(ctx, "xposed_detected", "检测到 Xposed 框架", config.report)
                    else -> Log.w(TAG, "[Batch 4] XposedDetector onViolation=none, 跳过响应")
                }
            } else if (xposedScore > 0) {
                Log.w(TAG, "[Batch 4] XposedDetector 黄色(置信度 $xposedScore < ${config.xposedDetect.killThreshold})")
                if (config.xposedDetect.onViolation == "warn") {
                    DefenderResponse.warn(ctx, "xposed_suspected", "疑似 Xposed 框架", config.report)
                }
            } else {
                Log.i(TAG, "[Batch 4] XposedDetector 通过")
            }
        }

        // EmulatorDetector(布尔检测,warn 为主)
        if (config.emulatorDetect.enabled) {
            Log.i(TAG, "[Batch 4] EmulatorDetector 检测中...")
            val isEmulator = EmulatorDetector(ctx).detect()
            if (isEmulator) {
                Log.e(TAG, "[Batch 4] EmulatorDetector 检测到模拟器")
                when (config.emulatorDetect.onViolation) {
                    "warn" -> DefenderResponse.warn(ctx, "emulator_detected", "检测到模拟器环境", config.report)
                    "kill" -> DefenderResponse.kill(ctx, config.onViolationKill)
                    else -> Log.w(TAG, "[Batch 4] EmulatorDetector onViolation=none, 跳过响应")
                }
            } else {
                Log.i(TAG, "[Batch 4] EmulatorDetector 通过")
            }
        }

        // WindowSecurer(全局 FLAG_SECURE,静默防护)
        if (config.secureScreen.enabled) {
            Log.i(TAG, "[Batch 4] WindowSecurer 启动...")
            try {
                val app = ctx.applicationContext as android.app.Application
                WindowSecurer(app).start(config.secureScreen.excludeActivities)
            } catch (e: Exception) {
                Log.w(TAG, "[Batch 4] WindowSecurer 启动失败: ${e.message}")
            }
        }
    }

    // ============= ContentProvider 必需方法(本 Provider 不提供数据,全返回空) =============

    override fun query(
        uri: Uri,
        projection: Array<String>?,
        selection: String?,
        selectionArgs: Array<String>?,
        sortOrder: String?
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<String>?): Int = 0

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<String>?
    ): Int = 0

    companion object {
        private const val TAG = "DefenderInit"
    }
}
