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
        /* 在 ContentProvider 之前加载 defender .so(防 LSPatch 替换 ContentProvider 导致 .so 不加载)
         * attachBaseContext 是 Application 生命周期最早的可执行点,
         * LSPatch 的 AppComponentFactory 虽可替换组件,但仍需委托原始 Application 生命周期 */
        try {
            System.loadLibrary("xcj_defender")
            Log.i(TAG, "defender .so 在 attachBaseContext 中加载成功")
        } catch (e: UnsatisfiedLinkError) {
            Log.w(TAG, "attachBaseContext 加载 .so 失败(可能已加载): ${e.message}")
        }
    }

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "DefenderTestApp onCreate")
    }

    companion object {
        const val TAG = "DefenderDemo"
    }
}
