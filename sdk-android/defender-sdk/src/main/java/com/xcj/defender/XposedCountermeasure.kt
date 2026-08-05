package com.xcj.defender

import android.util.Log

/**
 * XposedCountermeasure - 检出后降级反制(ADR 0098 P0-B,Virbox sub_29474C 反哺)
 *
 * 理念:崩=信号,红方知道被看见、立刻针对性绕;降级=静默,红方的 hook 失效却难归因。
 * 检出 Xposed/LSPosed 时,不立即 kill,而是反射置 XposedBridge.disableHooks=true,
 * 静默关闭对方全部 hook,把崩溃留给"屡犯/高危"档。
 *
 * 对抗参考:深思数盾 Virbox sub_295054 检出 XposedBridge/XposedHelpers 后不崩,
 * 调 sub_29474C 反射置 XposedBridge.disableHooks=true 直接关掉对方所有 hook。
 *
 * 实现原则:
 *  - 全程 try/catch,任何失败只返回 false,绝不抛异常/崩溃(反制本身不能成为崩溃源)。
 *  - 多路径尝试(不同框架字段名/类名变体),命中其一即视为成功。
 *  - 静默:不 Toast、不弹窗,只 log + 可选上报。
 */
object XposedCountermeasure {
    private const val TAG = "XposedCountermeasure"

    // 已知可置位的"总开关"字段:类名 → 字段名(均为 static boolean)
    private val DISABLE_TARGETS =
        listOf(
            "de.robv.android.xposed.XposedBridge" to "disableHooks",
        )

    /**
     * 尝试静默关闭 Xposed/LSPosed 全部 hook。
     *
     * @return true=至少一条反制路径成功(对方 hook 已被置为禁用)/ false=全部失败
     */
    fun attemptSilentDisable(): Boolean {
        for ((className, fieldName) in DISABLE_TARGETS) {
            if (tryDisableField(className, fieldName)) {
                Log.w(TAG, "silent countermeasure applied")
                return true
            }
        }
        return false
    }

    /**
     * 反射置 static boolean 字段为 true。
     * 失败原因:类未加载(非 Xposed 环境)/ 字段改名(框架变体)/ SecurityManager。
     */
    private fun tryDisableField(
        className: String,
        fieldName: String,
    ): Boolean {
        return try {
            val clz = loadClassSilently(className) ?: return false
            val field = clz.getDeclaredField(fieldName)
            field.isAccessible = true
            field.setBoolean(null, true)
            // 回读确认写入生效(防 setter 被对方 hook 成 no-op)
            field.getBoolean(null)
        } catch (t: Throwable) {
            false
        }
    }

    /**
     * 静默加载类:优先已加载查询,避免触发类加载留痕。
     * 依次尝试应用 ClassLoader 与系统 ClassLoader。
     */
    private fun loadClassSilently(className: String): Class<*>? {
        val loaders =
            listOfNotNull(
                XposedCountermeasure::class.java.classLoader,
                ClassLoader.getSystemClassLoader(),
            )
        for (loader in loaders) {
            try {
                return Class.forName(className, false, loader)
            } catch (t: Throwable) {
                // 尝试下一个 loader
            }
        }
        return null
    }
}
