package com.xcj.defender.demo

import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.xcj.defender.DefenderNative
import org.json.JSONObject

/**
 * 签名校验详细结果页(类似 sigCheck 截图)
 *
 * 逐条展示每个检测项的结果:绿色=通过 / 红色=失败
 */
class VerificationActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val scroll = ScrollView(this).apply {
            setBackgroundColor(Color.WHITE)
        }

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
        }

        // 标题
        addTitle(container, "defender-sdk 校验详情")
        addSpacer(container, 24)

        // 运行详细校验
        val apkPath = packageCodePath
        val jsonStr = try {
            DefenderNative.detailedCheck(apkPath)
        } catch (e: Exception) {
            "{\"error\":\"${e.message}\"}"
        }

        val json = try { JSONObject(jsonStr) } catch (_: Exception) { JSONObject() }

        // 校验项列表
        val checks = listOf(
            "soPathValid" to ".so 加载路径合法(防SRP/LSP)",
            "selfIntegrityCrc" to "方案B .text CRC 校验",
            "signatureHashMatch" to "方案A APK Hash 匹配",
            "dexIntegrity" to "方案B DEX 完整性",
            "cachedFdValid" to "缓存 fd 有效(防SVC hook)",
            "allPass" to "综合校验结果",
        )

        for ((key, label) in checks) {
            val value = json.optInt(key, -1)
            val passed = value == 1
            val skipped = value == -1
            addCheckRow(container, label, passed, skipped)
            addSpacer(container, 16)
        }

        // 通用绕过检测(Java 行为特征 + Native maps/dl/fd 交叉验证)
        addSpacer(container, 16)
        addTitle(container, "通用绕过检测")
        addSpacer(container, 12)
        val javaPatch = com.xcj.defender.PatchToolDetector.detect(this)
        val nativeScore = json.optInt("nativePatchScore", 0)
        val totalScore = javaPatch.score + nativeScore

        addCheckRow(container, "Java 行为特征(score=${javaPatch.score})", !javaPatch.detected, false)
        addSpacer(container, 8)
        addCheckRow(container, "Native maps/dl/fd(score=$nativeScore)", nativeScore < 40, false)
        addSpacer(container, 8)
        addCheckRow(container, "综合风险分数=$totalScore", totalScore < 40, false)
        addSpacer(container, 8)

        if (javaPatch.details.isNotEmpty()) {
            for (detail in javaPatch.details) {
                addInfoRow(container, "  [Java]", detail)
            }
        }
        // Native 详情
        val nativeDetail = json.optJSONObject("nativePatchDetail")
        if (nativeDetail != null) {
            if (nativeDetail.optInt("mapsApkAnomaly", 0) == 1)
                addInfoRow(container, "  [Native]", "maps 异常 .apk: ${nativeDetail.optString("mapsApkPath")}")
            if (nativeDetail.optInt("dlApkAnomaly", 0) == 1)
                addInfoRow(container, "  [Native]", "dl_iterate_phdr 异常 .apk")
            if (nativeDetail.optInt("fdApkAnomaly", 0) == 1)
                addInfoRow(container, "  [Native]", "/proc/self/fd 异常: ${nativeDetail.optString("fdApkPath")}")
            val suspCount = nativeDetail.optInt("suspiciousSoCount", 0)
            if (suspCount > 0)
                addInfoRow(container, "  [Native]", "可疑 .so: $suspCount 个")
        }

        addSpacer(container, 24)

        // 环境信息
        addTitle(container, "环境信息")
        addSpacer(container, 12)
        addInfoRow(container, "APK 路径", apkPath)
        addInfoRow(container, ".so 加载路径", json.optString("soPath", "未知"))
        addInfoRow(container, ".so 路径合法", if (json.optInt("soPathValid", 0) == 1) "是(/data/app/)" else "否(重定向!)")
        addInfoRow(container, "maps 中 APK", json.optJSONObject("nativePatchDetail")?.optString("mapsApkPath", "未知") ?: "未知")
        addInfoRow(container, "fd 中 APK", json.optJSONObject("nativePatchDetail")?.optString("fdApkPath", "未知") ?: "未知")
        addInfoRow(container, "缓存 fd 状态", if (json.optInt("cachedFdValid", 0) == 1) "有效" else "无效")
        addInfoRow(container, ".so 加载时机", "attachBaseContext(早于ContentProvider)")

        scroll.addView(container)
        setContentView(scroll)
    }

    private fun addTitle(parent: LinearLayout, text: String) {
        parent.addView(TextView(this).apply {
            this.text = text
            setTextColor(Color.parseColor("#4A148C"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 20f)
            typeface = Typeface.DEFAULT_BOLD
        })
    }

    private fun addCheckRow(parent: LinearLayout, label: String, passed: Boolean, skipped: Boolean) {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        row.addView(TextView(this).apply {
            this.text = "$label:"
            setTextColor(Color.parseColor("#1A237E"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
            typeface = Typeface.DEFAULT_BOLD
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        })

        val statusText = when {
            skipped -> "跳过"
            passed -> "true"
            else -> "false"
        }
        val statusColor = when {
            skipped -> Color.GRAY
            passed -> Color.parseColor("#1B5E20")
            else -> Color.parseColor("#B71C1C")
        }

        row.addView(TextView(this).apply {
            text = statusText
            setTextColor(statusColor)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
            typeface = Typeface.DEFAULT_BOLD
        })

        parent.addView(row)
    }

    private fun addInfoRow(parent: LinearLayout, label: String, value: String) {
        val tv = TextView(this).apply {
            text = "$label: $value"
            setTextColor(Color.parseColor("#37474F"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
        }
        parent.addView(tv)
    }

    private fun addSpacer(parent: LinearLayout, dp: Int) {
        parent.addView(android.view.View(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, dp.toFloat(), resources.displayMetrics).toInt()
            )
        })
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }
}
