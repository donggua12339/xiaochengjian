package com.xcj.defender

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.util.Log
import android.view.WindowManager

/**
 * 屏幕安全器(防截屏 / 防录屏)
 *
 * 详见 ADR 0088 §WindowSecurer
 *
 * 原理:
 *  给每个 Activity 的 Window 设置 FLAG_SECURE,
 *  系统级禁止截屏 / 录屏(SurfaceFlinger 拒绝向 SCREENSHOT 服务提供 buffer)。
 *
 * 实现:
 *  Application.registerActivityLifecycleCallbacks 全局拦截,
 *  onActivityCreated + onActivityResumed 时加 FLAG_SECURE(防 recreate 后 flag 丢失)。
 *  excludeActivities 中的 Activity 不加(如登录扫码页需允许截屏分享)。
 *
 * 响应:静默防护(无 Toast、无 kill)
 */
class WindowSecurer(private val application: Application) {

    companion object {
        private const val TAG = "DefenderWindow"
    }

    private val excludeSet: MutableSet<String> = mutableSetOf()

    /**
     * 启动全局 FLAG_SECURE 拦截
     *
     * @param excludeActivities 排除列表(Activity 全限定名)
     */
    fun start(excludeActivities: List<String>) {
        excludeSet.clear()
        excludeSet.addAll(excludeActivities)
        application.registerActivityLifecycleCallbacks(callbacks)
        Log.i(TAG, "WindowSecurer 已启动(排除 ${excludeSet.size} 个 Activity)")
    }

    private val callbacks = object : Application.ActivityLifecycleCallbacks {
        override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
            applySecureFlag(activity)
        }

        override fun onActivityStarted(activity: Activity) {}

        override fun onActivityResumed(activity: Activity) {
            // resume 时再确保一次(防 Activity recreate 后 flag 丢失)
            applySecureFlag(activity)
        }

        override fun onActivityPaused(activity: Activity) {}

        override fun onActivityStopped(activity: Activity) {}

        override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}

        override fun onActivityDestroyed(activity: Activity) {}
    }

    private fun applySecureFlag(activity: Activity) {
        val activityName = activity.javaClass.name
        if (excludeSet.contains(activityName)) {
            return
        }

        try {
            activity.window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE
            )
        } catch (e: Exception) {
            Log.w(TAG, "FLAG_SECURE 设置失败: $activityName - ${e.message}")
        }
    }
}
