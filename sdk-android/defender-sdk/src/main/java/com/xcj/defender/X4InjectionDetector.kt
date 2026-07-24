package com.xcj.defender

import android.app.Application
import android.content.pm.PackageInfo
import android.content.pm.PackageManager

/**
 * X4-1 L1 反注入 - Java 侧检测(ADR 0093)。
 *
 * 对抗 MT killPM(现代=PackageInfo.CREATOR 替换 / 旧=mPM 代理)与 Application 替换
 * (PmsHookApplication/HookApplication)。检测设计来源:docs/x4/X4-IMPLEMENTATION-PLAN.md
 * L1(调研 M3《安卓签名校验-探讨》/ M7 how-to-check-sign)。
 *
 * 与 native [X4Native.antiInjectCheck] 结果交叉绑定(单点不可信,交叉才可信)。
 */
object X4InjectionDetector {

    /**
     * L1-1/L1-2:PackageInfo.CREATOR 检测(对抗现代 MT/LSPatch 的 CREATOR 替换)。
     * 系统 CREATOR 由 BootClassLoader 加载(classLoader==null)且类名含 "PackageInfo$";
     * 被替换的代理 Creator 由应用 PathClassLoader 加载、类名为匿名类。
     * 法一(ClassLoader)+ 法二(类名)双检测,LSPatch 可绕法一故需法二兜底。
     * @return true=疑似被替换
     */
    fun detectCreatorHook(): Boolean {
        return try {
            val field = PackageInfo::class.java.getField("CREATOR")
            val creator = field.get(null) ?: return false
            val creatorClass = creator.javaClass
            val cl = creatorClass.classLoader
            // 法一:ClassLoader 比对——系统 CREATOR 的 classLoader 为 null 或 BootClassLoader
            // (注意 BootClassLoader 是非 null 实例);被替换的代理 Creator 由应用 PathClassLoader 加载
            if (cl != null && cl.javaClass.name != "java.lang.BootClassLoader") return true
            // 法二:类名比对(系统为 PackageInfo$1 之类,代理为匿名类;LSPatch 可绕法一故需此兜底)
            if (!creatorClass.name.contains("PackageInfo")) return true
            false
        } catch (e: Throwable) {
            false
        }
    }

    /**
     * L1-3:IPackageManager(mPM)类名检测(对抗旧版 MT 的 PMS 动态代理)。
     * 正常 mPM 类名 == "android.content.pm.IPackageManager$Stub$Proxy";代理后变 "$ProxyN"。
     * @return true=疑似被代理;字段不存在(API 差异)保守返回 false
     */
    fun detectPmsProxy(pm: PackageManager): Boolean {
        return try {
            val mpmField = pm.javaClass.getDeclaredField("mPM")
            mpmField.isAccessible = true
            val mpm = mpmField.get(pm) ?: return false
            val legit = mpm.javaClass.name == "android.content.pm.IPackageManager\$Stub\$Proxy"
            !legit
        } catch (e: Throwable) {
            false
        }
    }

    /**
     * L1-4:Application 类名检测(对抗 PmsHookApplication/HookApplication 继承替换)。
     * @param expectedClassName 预期的 Application 完整类名(开发者自有,如 com.x.demo.App)
     * @return true=疑似被替换
     */
    fun detectApplicationHook(app: Application, expectedClassName: String): Boolean {
        return app.javaClass.name != expectedClassName
    }

    /**
     * L1 综合(Java 侧):返回可疑计数(0=干净)。
     * @param expectedAppClassName 开发者自有 Application 完整类名
     */
    fun check(app: Application, expectedAppClassName: String): Int {
        var score = 0
        if (detectCreatorHook()) score++
        try {
            if (detectPmsProxy(app.packageManager)) score++
        } catch (e: Throwable) {
            /* ignore */
        }
        if (detectApplicationHook(app, expectedAppClassName)) score++
        return score
    }
}
