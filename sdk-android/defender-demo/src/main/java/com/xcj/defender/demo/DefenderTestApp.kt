package com.xcj.defender.demo

import android.app.Application
import android.util.Log

/**
 * Defender Demo Application
 *
 * 测试 xcj-defender-sdk 所有模块的检测结果
 */
class DefenderTestApp : Application() {

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "DefenderTestApp onCreate")
    }

    companion object {
        const val TAG = "DefenderDemo"
    }
}
