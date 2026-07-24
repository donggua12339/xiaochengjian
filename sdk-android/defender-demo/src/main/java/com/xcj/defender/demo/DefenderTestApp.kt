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
            Log.w(TAG, "[X0] 加载失败(可能已加载): ${e.message}")
        }
    }

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "DefenderTestApp onCreate")
        /* X0 验证:外壳经 stub 加密加载后,DefenderNative 应已注册可用 */
        try {
            val ver = com.xcj.defender.DefenderNative.getVersion()
            Log.i(TAG, "[X0] DefenderNative.getVersion() = $ver(外壳经 stub 加载并注册成功)")
        } catch (e: Throwable) {
            Log.e(TAG, "[X0] DefenderNative 调用失败: ${e.message}", e)
        }
        /* X4-1 L1 反注入验证(native + Java 交叉) */
        try {
            val nativeScore = com.xcj.defender.X4Native.antiInjectCheck()
            val javaScore = com.xcj.defender.X4InjectionDetector.check(
                this, "com.xcj.defender.demo.DefenderTestApp")
            Log.i(TAG, "[X4-1] L1 反注入: native=$nativeScore java=$javaScore(0=干净)")
        } catch (e: Throwable) {
            Log.e(TAG, "[X4-1] 检测失败: ${e.message}", e)
        }
    }

    companion object {
        const val TAG = "DefenderDemo"
    }
}
