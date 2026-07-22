package com.xcj.defender

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.widget.Toast

/**
 * Defender 响应策略(Java 层封装)
 *
 * 详见 ADR 0088 §响应策略
 *
 * kill:
 *  1. Toast(主线程,显示 toastMessage)
 *  2. 后台线程:DefenderNative.defenderKill(delay, method)
 *     - 随机延迟 [delayMinMs, delayMaxMs] 防逆向定位
 *     - SIGABRT 产生 tombstone / _exit(1) 兜底
 *
 * warn:
 *  1. DefenderNative.defenderWarn(key, throttleMs) 限流检查
 *  2. 如果返回 1(应该上报):Toast + HTTP 上报(待服务端接口实现)
 */
object DefenderResponse {

    private const val TAG = "DefenderResponse"
    private val mainHandler = Handler(Looper.getMainLooper())

    /**
     * kill 响应
     *
     * @param context Context(用于 Toast)
     * @param config  kill 配置
     */
    fun kill(context: Context, config: DefenderConfig.KillConfig) {
        // 1. Toast(主线程)
        if (config.showToast) {
            mainHandler.post {
                Toast.makeText(context, config.toastMessage, Toast.LENGTH_LONG).show()
            }
        }

        // 2. 后台线程 kill(防阻塞主线程,延迟在 native 层 usleep)
        Thread {
            // 等待 Toast 显示(主线程 post 需要时间,防止 _exit 前 Toast 未显示)
            if (config.showToast) {
                Thread.sleep(500)
            }
            Log.e(
                TAG,
                "kill 响应触发: method=${config.method}, delay=[${config.delayMinMs}, ${config.delayMaxMs}] ms"
            )
            DefenderNative.defenderKill(config.delayMinMs, config.delayMaxMs, config.method)
        }.start()
    }

    /**
     * warn 响应
     *
     * @param context       Context(用于 Toast)
     * @param violationKey  违规 key(限流用)
     * @param message       Toast 消息
     * @param reportConfig  上报配置(enabled=false 时仅 Toast,不 HTTP 上报)
     */
    fun warn(
        context: Context,
        violationKey: String,
        message: String,
        reportConfig: DefenderConfig.ReportConfig
    ) {
        // 1. 限流检查(enabled=false 时 throttleMs=0,但仍走 native 记录首次时间戳)
        val throttleMs = if (reportConfig.enabled) reportConfig.throttleMs else 0
        val shouldReport = DefenderNative.defenderWarn(violationKey, throttleMs)
        if (shouldReport != 1) return

        // 2. Toast(主线程)
        mainHandler.post {
            Toast.makeText(context, message, Toast.LENGTH_LONG).show()
        }

        // 3. HTTP 上报(待服务端接口实现)
        if (reportConfig.enabled) {
            Log.i(TAG, "warn 上报(待实现): key=$violationKey, msg=$message")
            // TODO: HTTP POST 到 DefenderInit.config.serverUrl + appId
        }
    }
}
