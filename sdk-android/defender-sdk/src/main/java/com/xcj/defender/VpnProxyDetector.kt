package com.xcj.defender

import android.content.Context
import android.util.Log
import java.io.File
import java.net.NetworkInterface

/**
 * X5 VPN / 代理检测(玄甲 v1.0 P1)。
 *
 * 检测维度:
 *  A. NetworkInterface 列表中出现 tun0/ppp0/wg0 等隧道接口 → VPN
 *  B. System.getProperty("http.proxyHost") 非空 → 全局 HTTP 代理
 *  C. /proc/net/tcp 中出现非常规代理端口(8080/8888/1080/3128) → 抓包代理
 *  D. Settings.Global 中 http_proxy 非空 → 系统代理设置
 *
 * 响应:warn(不 kill,因为 VPN 不一定是攻击;但抓包代理 + VPN 组合加权)。
 */
class VpnProxyDetector(private val context: Context) {

    companion object {
        private const val TAG = "DefenderVpnProxy"

        private val VPN_INTERFACES = listOf("tun0", "ppp0", "wg0", "tap0", "utun")
        private val PROXY_PORTS = listOf(8080, 8888, 1080, 3128, 9090, 10808, 10809)
    }

    data class Result(
        val detected: Boolean,
        val score: Int,
        val details: List<String>,
    )

    fun detect(): Result {
        val details = mutableListOf<String>()
        var score = 0

        // A: NetworkInterface 隧道检测
        if (checkVpnInterfaces(details)) score += 30

        // B: 全局 HTTP 代理
        if (checkHttpProxy(details)) score += 25

        // C: /proc/net/tcp 代理端口
        if (checkProxyPorts(details)) score += 30

        // D: Settings.Global http_proxy
        if (checkSettingsProxy(details)) score += 15

        val detected = score >= 40
        if (detected) {
            Log.e(TAG, "VPN/代理环境检测: score=$score")
        } else {
            Log.i(TAG, "VPN/代理检测通过(score=$score)")
        }
        return Result(detected, score, details)
    }

    private fun checkVpnInterfaces(details: MutableList<String>): Boolean {
        return try {
            val interfaces = NetworkInterface.getNetworkInterfaces() ?: return false
            for (nif in interfaces) {
                val name = nif.name.lowercase()
                for (vpn in VPN_INTERFACES) {
                    if (name == vpn || name.startsWith(vpn)) {
                        details.add("VPN 接口: ${nif.name}")
                        return true
                    }
                }
            }
            false
        } catch (e: Throwable) {
            false
        }
    }

    private fun checkHttpProxy(details: MutableList<String>): Boolean {
        val proxyHost = System.getProperty("http.proxyHost")
        val proxyPort = System.getProperty("http.proxyPort")
        if (!proxyHost.isNullOrEmpty()) {
            details.add("HTTP 代理: $proxyHost:$proxyPort")
            return true
        }
        return false
    }

    private fun checkProxyPorts(details: MutableList<String>): Boolean {
        return try {
            val tcpFiles = listOf("/proc/net/tcp", "/proc/net/tcp6")
            for (tcpFile in tcpFiles) {
                val content = File(tcpFile).readText()
                for (port in PROXY_PORTS) {
                    val hexPort = String.format("%04X", port)
                    // /proc/net/tcp 格式: local_address:port (大写 hex)
                    if (content.contains(":$hexPort ") || content.contains(":${hexPort.lowercase()} ")) {
                        details.add("代理端口 $port 在 $tcpFile 中 LISTEN")
                        return true
                    }
                }
            }
            false
        } catch (e: Throwable) {
            false
        }
    }

    private fun checkSettingsProxy(details: MutableList<String>): Boolean {
        return try {
            val proxy = android.provider.Settings.Global.getString(
                context.contentResolver, android.provider.Settings.Global.HTTP_PROXY
            )
            if (!proxy.isNullOrEmpty() && proxy != ":0") {
                details.add("系统代理设置: $proxy")
                return true
            }
            false
        } catch (e: Throwable) {
            false
        }
    }
}
