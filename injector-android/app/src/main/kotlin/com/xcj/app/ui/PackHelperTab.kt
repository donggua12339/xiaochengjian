package com.xcj.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ClipboardManager
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp

/**
 * 打包辅助 Tab
 *
 * v2 重构:原 APK 注入 Tab 移除(合规红线:不提供重打包能力),
 * 改为引导开发者主动集成 SDK 的向导:
 *  1. 加 gradle 依赖
 *  2. 初始化代码模板
 *  3. 调用验证 API 的示例
 *
 * 不执行任何字节码修改,只是文档展示 + 复制到剪贴板。
 */
@Composable
fun PackHelperTab() {
    val clipboard: ClipboardManager = LocalClipboardManager.current

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("打包辅助", style = MaterialTheme.typography.headlineSmall)
        Text(
            "v2 不再提供 APK 重打包能力。请按以下步骤在自己的源码里集成 SDK。",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        StepCard(
            stepNo = 1,
            title = "添加 gradle 依赖",
            code = """// app/build.gradle.kts
dependencies {
    implementation("com.xiaochengjian.sdk:sdk-android:0.2.0")
    // 如使用离线缓存模块,需额外引入 native 库
    implementation("com.xiaochengjian.sdk:sdk-android-jni:0.2.0")
}""",
            onCopy = { clipboard.setText(AnnotatedString("dependencies { ... }")) },
        )

        StepCard(
            stepNo = 2,
            title = "在 Application.onCreate 初始化",
            code = """class MyApp : Application() {
    override fun onCreate() {
        super.onCreate()
        XiaochengjianSDK.Builder()
            .appId("your-app-id")
            .appSecret("your-app-secret")  // 从 Web 后台获取
            .serverUrl("https://your-saas-domain.com")
            .build()
            .init(this)
    }
}""",
            onCopy = { clipboard.setText(AnnotatedString("class MyApp ...")) },
        )

        StepCard(
            stepNo = 3,
            title = "激活与验证",
            code = """// 用户输入卡密后调用
XiaochengjianSDK.activate(
    cardKey = "XXXX-XXXX-XXXX-XXXX",
    machineId = deviceId,
    fingerprintHash = fingerprint,
) { result ->
    if (result.success) {
        // 验证通过,解锁功能
    } else {
        // 验证失败,提示用户
    }
}

// 周期性调用(如启动时)
XiaochengjianSDK.validate(...)
""",
            onCopy = { clipboard.setText(AnnotatedString("activate / validate")) },
        )

        Spacer(Modifier.height(8.dp))
        Text(
            "注:SDK 实现请参考 sdk-android/ 模块。本 APP 不提供重打包他人 APK 的能力,这是合规红线。",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
        )
    }
}

@Composable
private fun StepCard(
    stepNo: Int,
    title: String,
    code: String,
    onCopy: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("步骤 $stepNo · $title", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            Text(
                code,
                style = MaterialTheme.typography.bodySmall,
            )
            Spacer(Modifier.height(8.dp))
            androidx.compose.material3.TextButton(onClick = onCopy) {
                Text("复制到剪贴板")
            }
        }
    }
}
