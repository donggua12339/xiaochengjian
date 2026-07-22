package com.xcj.defender

import android.content.Context

/**
 * Defender 全局状态
 *
 * 由 DefenderInitProvider.onCreate() 初始化,供后续模块访问 config + context
 */
object DefenderInit {

    @Volatile
    var initialized: Boolean = false
        internal set

    @Volatile
    var config: DefenderConfig = DefenderConfig()
        internal set

    @Volatile
    var context: Context? = null
        internal set

    /**
     * 检查是否已初始化
     */
    fun ensureInitialized(): Boolean {
        if (!initialized) {
            android.util.Log.w("DefenderInit", "Defender 未初始化(DefenderInitProvider 未执行)")
            return false
        }
        return true
    }
}
