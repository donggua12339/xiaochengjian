package com.xcj.defender

import android.app.Application
import android.content.pm.PackageManager
import android.os.Build

/**
 * X3 生命周期劫持检测(玄甲 P0)。
 *
 * 对抗场景:LSPatch/SRPatch/虚拟框架通过替换 Application 实例、注入 AppComponentFactory、
 * 或篡改 LoadedApk.mApplication 来劫持应用生命周期,使宿主代码在攻击者控制的上下文中运行。
 *
 * 设计原则(ADR 0095 铁律):不依赖"代码自己跑出来的标志",而是交叉比对系统级注册信息
 * (PackageManager 声明)与运行时实际状态。
 *
 * 调用时机:Application.attachBaseContext 或 onCreate 最早期。命中即视为致命,调用方应 kill。
 */
object X3LifecycleGuard {

    data class Result(
        val hijacked: Boolean,
        val reasons: List<String>,
    )

    /**
     * 综合检测。
     *
     * @param app 当前 Application 实例
     * @param expectedClassName 开发者在 Manifest 中声明的 Application 完整类名
     * @return Result(hijacked=true 表示检测到劫持)
     */
    fun check(app: Application, expectedClassName: String): Result {
        val reasons = mutableListOf<String>()

        if (detectClassNameMismatch(app, expectedClassName)) {
            reasons.add("app_class_mismatch")
        }

        if (Build.VERSION.SDK_INT >= 28 && detectComponentFactoryHijack()) {
            reasons.add("component_factory_hijack")
        }

        if (detectLoadedApkMismatch(app)) {
            reasons.add("loaded_apk_mismatch")
        }

        return Result(hijacked = reasons.isNotEmpty(), reasons = reasons)
    }

    /**
     * 检测 1:运行时 Application 类名 ≠ Manifest 声明。
     */
    private fun detectClassNameMismatch(app: Application, expectedClassName: String): Boolean {
        val actualName = app.javaClass.name
        if (actualName != expectedClassName) return true

        return try {
            val appInfo = app.packageManager.getApplicationInfo(app.packageName, 0)
            var declaredName = appInfo.className ?: return false
            // Manifest 中 .ClassName 是相对名,需拼接包名
            if (declaredName.startsWith(".")) {
                declaredName = app.packageName + declaredName
            }
            declaredName != actualName
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
    }

    /**
     * 检测 2:AppComponentFactory 被替换(API 28+)。
     *
     * 通过反射读取 ActivityThread.mAppComponentFactory(hidden API)。
     * 系统默认为 android.app.AppComponentFactory;LSPatch 等会替换为自定义实现。
     */
    private fun detectComponentFactoryHijack(): Boolean {
        return try {
            val at = currentActivityThread() ?: return false
            val field = at.javaClass.getDeclaredField("mAppComponentFactory")
            field.isAccessible = true
            val factory = field.get(at) ?: return false
            factory.javaClass.name != "android.app.AppComponentFactory"
        } catch (e: Throwable) {
            false
        }
    }

    /**
     * 检测 3:LoadedApk.mApplication 实例与当前 app 不一致。
     *
     * 通过反射链:ActivityThread.mBoundApplication.info.mApplication(hidden API)。
     */
    private fun detectLoadedApkMismatch(app: Application): Boolean {
        return try {
            val at = currentActivityThread() ?: return false
            val boundField = at.javaClass.getDeclaredField("mBoundApplication")
            boundField.isAccessible = true
            val bound = boundField.get(at) ?: return false
            val infoField = bound.javaClass.getDeclaredField("info")
            infoField.isAccessible = true
            val loadedApk = infoField.get(bound) ?: return false

            val appField = loadedApk.javaClass.getDeclaredField("mApplication")
            appField.isAccessible = true
            val storedApp = appField.get(loadedApk)

            storedApp != null && storedApp !== app
        } catch (e: Throwable) {
            false
        }
    }

    /** 反射获取 ActivityThread.currentActivityThread()(hidden API) */
    private fun currentActivityThread(): Any? {
        return try {
            val clz = Class.forName("android.app.ActivityThread")
            val method = clz.getDeclaredMethod("currentActivityThread")
            method.isAccessible = true
            method.invoke(null)
        } catch (e: Throwable) {
            null
        }
    }
}
