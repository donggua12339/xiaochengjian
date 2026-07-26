package com.xcj.defender.demo

import android.app.Application
import android.content.Context
import android.util.Log

/**
 * Defender Demo Application
 *
 * 测试 xcj-defender-sdk 所有模块的检测结果
 */
class DefenderTestApp : Application() {

    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(base)
        /* X0:加载 stub libxcj_loader.so,bootstrap 从 APK 定位加密外壳 → RC4 解密 →
         * memfd 加载 → 手动调外壳 JNI_OnLoad 注册 DefenderNative。
         * 明文外壳 libxcj_defender.so 打包时已从 lib/ 排除(防静态提取),仅以密文存于 assets。
         * attachBaseContext 早于 ContentProvider(DefenderInitProvider),确保 native 先就绪。 */
        try {
            System.loadLibrary("xcj_loader")
            val rc = com.xcj.defender.DefenderX0Test.bootstrap(packageCodePath)
            Log.i(TAG, "[X0] bootstrap rc=$rc(0=外壳经 stub 加密加载成功)")
        } catch (e: UnsatisfiedLinkError) {
            // 不用字符串字面量(attachBaseContext 阶段 XcjObfStr 尚未注册)
            Log.w(TAG, e.toString())
        }
    }

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "DefenderTestApp onCreate")

        /* X3 生命周期劫持检测(硬门禁,命中即 kill) */
        try {
            val x3 = com.xcj.defender.X3LifecycleGuard.check(
                this, "com.xcj.defender.demo.DefenderTestApp"
            )
            if (x3.hijacked) {
                Log.e(TAG, "[X3] 生命周期劫持检测: ${x3.reasons}")
                android.os.Process.killProcess(android.os.Process.myPid())
                return
            }
            Log.i(TAG, "[X3] 生命周期完整性校验通过")
        } catch (e: Throwable) {
            Log.e(TAG, "[X3] 检测异常(非致命): ${e.message}")
        }

        /* X0 验证:外壳经 stub 加密加载后,DefenderNative 应已注册可用 */
        try {
            val ver = com.xcj.defender.DefenderNative.getVersion()
            Log.i(TAG, "[X0] DefenderNative.getVersion() = $ver(外壳经 stub 加载并注册成功)")
        } catch (e: Throwable) {
            Log.e(TAG, "[X0] DefenderNative 调用失败: ${e.message}", e)
        }

        /* X4 响应链初始化:启动守护线程 + 三通道决策(强证据/有效分/存在感)
         *
         * 传 null config_path → 走 native 默认 config(enabled=true, onViolation=KILL,
         * dryRun=false, strong_switches 全 true)。这意味着:
         *   - 强证据 5 条任一命中 → 即时 kill(真杀进程,SIGABRT)
         *   - 有效分超 70 → kill
         *   - 守护线程每 3-15s 随机触发一轮
         *
         * expected_hash 传空 → 强证据 ①(签名 hash)不校验,其他 4 条可测。
         * 强证据 ① 的验证由 patch_x0.py 注入 expected_hash 后单独测。 */
        try {
            com.xcj.defender.X4Native.x4Init(
                /* configPath = */ null,
                /* selfPkg    = */ packageName,
                /* apkPath    = */ packageCodePath,
                /* expectedHash = */ ""
            )
            Log.i(TAG, "[X4] 响应链已启动,守护线程运行中(dryRun=false=enforce)")
        } catch (e: Throwable) {
            Log.e(TAG, "[X4] x4Init 失败: ${e.message}", e)
        }

        /* 以下各检测器仅用于诊断打印单点分数;真正 kill 决策已在 x4Init 启动的
         * 守护线程里走三通道响应链。保留这些调用方便观测单层 score。 */
        try {
            val nativeScore = com.xcj.defender.X4Native.antiInjectCheck()
            val javaScore = com.xcj.defender.X4InjectionDetector.check(
                this, "com.xcj.defender.demo.DefenderTestApp")
            Log.i(TAG, "[X4-1] L1 反注入: native=$nativeScore java=$javaScore(0=干净)")
        } catch (e: Throwable) {
            Log.e(TAG, "[X4-1] 检测失败: ${e.message}", e)
        }
        try {
            val l2Score = com.xcj.defender.X4Native.antiDebugCheck()
            Log.i(TAG, "[X4-3] L2 反调试: score=$l2Score(0=干净)")
        } catch (e: Throwable) {
            Log.e(TAG, "[X4-3] 检测失败: ${e.message}", e)
        }
        try {
            com.xcj.defender.X4Native.antiDumpInit()
            val l3Score = com.xcj.defender.X4Native.antiDumpCheck()
            Log.i(TAG, "[X4-4] L3 反dump: score=$l3Score(0=干净)")
        } catch (e: Throwable) {
            Log.e(TAG, "[X4-4] 检测失败: ${e.message}", e)
        }
        try {
            val st = com.xcj.defender.X4Native.smcSelftest()
            val sum = com.xcj.defender.X4Native.smcAdd(30, 12)
            val wiped = com.xcj.defender.X4Native.smcWiped()
            Log.i(TAG, "[X4-5] L5 SMC: selftest=$st(0=pass) smcAdd(30,12)=$sum wiped=$wiped")
        } catch (e: Throwable) {
            Log.e(TAG, "[X4-5] SMC 失败: ${e.message}", e)
        }
        try {
            com.xcj.defender.X4Native.integrityInit(packageCodePath)
            val l4Score = com.xcj.defender.X4Native.integrityCheck(packageCodePath)
            Log.i(TAG, "[X4-2] L4 完整性: score=$l4Score(0=干净)")
        } catch (e: Throwable) {
            Log.e(TAG, "[X4-2] 检测失败: ${e.message}", e)
        }

        /* X5 VPN/代理检测 */
        try {
            val x5 = com.xcj.defender.VpnProxyDetector(this).detect()
            Log.i(TAG, "[X5] VPN/代理: score=${x5.score} detected=${x5.detected}")
        } catch (e: Throwable) {
            Log.e(TAG, "[X5] 检测失败: ${e.message}", e)
        }

        /* X6 双开/分身检测 */
        try {
            val x6 = com.xcj.defender.DualAppDetector(this).detect()
            Log.i(TAG, "[X6] 双开/分身: score=${x6.score} detected=${x6.detected}")
        } catch (e: Throwable) {
            Log.e(TAG, "[X6] 检测失败: ${e.message}", e)
        }

        /* X8 FART 脱壳扫描 */
        try {
            com.xcj.defender.X4Native.antiFartInit(packageName)
            val x8 = com.xcj.defender.X4Native.antiFartCheck()
            Log.i(TAG, "[X8] FART 扫描: score=$x8(0=干净)")
        } catch (e: Throwable) {
            Log.e(TAG, "[X8] 检测失败: ${e.message}", e)
        }

        /* X9 ODEX 修补检测 */
        try {
            com.xcj.defender.X4Native.odexInit(packageCodePath)
            val x9 = com.xcj.defender.X4Native.odexCheck()
            Log.i(TAG, "[X9] ODEX 检测: score=$x9(0=干净)")
        } catch (e: Throwable) {
            Log.e(TAG, "[X9] 检测失败: ${e.message}", e)
        }
    }

    companion object {
        const val TAG = "DefenderDemo"
    }
}
