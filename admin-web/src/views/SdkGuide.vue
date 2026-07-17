<script setup lang="ts">
import { NCard, NSteps, NStep, NCode, NSpace, NText, NAlert } from 'naive-ui';

defineOptions({ name: 'SdkGuideView' });

const gradleSnippet = `dependencies {
    implementation("com.xcj:sdk-android:0.2.0")
}`;

const manifestSnippet = `<application
    android:name=".XcjApplication"
    ...>
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
</application>`;

const applicationSnippet = `package com.yourpackage;

import android.app.Application;
import com.xcj.sdk.XiaochengjianSDK;
import com.xcj.sdk.SdkConfig;

class XcjApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        val config = SdkConfig(
            appId = "your-app-id",
            serverUrl = "https://xcj.winmelon.cn",
            appSecret = BuildConfig.XCJ_APP_SECRET,
        )
        XiaochengjianSDK.init(this, config)
    }
}`;

const buildConfigSnippet = `android {
    defaultConfig {
        buildConfigField("String", "XCJ_APP_SECRET", "\\"your-app-secret\\"")
    }
    buildFeatures {
        buildConfig = true
    }
}`;

const activateSnippet = `val result = XiaochengjianSDK.activate(
    cardKey = "XXXX-XXXX-XXXX-XXXX",
    machineId = getMachineId(this),
)
if (result.success) {
    // 激活成功,放行业务
} else {
    when (result.reason) {
        "CARD_NOT_FOUND" -> showError("卡密不存在")
        "CARD_DISABLED" -> showError("卡密已禁用")
        "CARD_EXPIRED" -> showError("卡密已过期")
        "CARD_ALREADY_BOUND_TO_OTHER_DEVICE" -> showError("卡密已绑定其他设备")
        "MAX_DEVICES_REACHED" -> showError("已达最大设备数")
    }
}`;
</script>

<template>
  <NSpace vertical size="large">
    <NCard title="SDK 集成指南">
      <NText depth="2">
        本指南指导开发者将小城笺 SDK 集成到自有著作权的 Android 应用中,实现卡密验证功能。
      </NText>
    </NCard>

    <NAlert type="warning" title="合规边界">
      <ul style="margin: 0; padding-left: 20px;">
        <li><b>允许</b>:集成到你自有著作权的 Android 应用</li>
        <li><b>禁止</b>:重打包他人 APK(即使单次)</li>
        <li><b>禁止</b>:绕过其他验证系统 / 为外挂破解提供支持</li>
      </ul>
    </NAlert>

    <NCard title="集成步骤">
      <NSpace vertical size="large">
        <NSteps vertical>
          <NStep title="在 Web 后台创建应用" description="登录后进入「应用管理」创建应用,获得 appId + appSecret(appSecret 仅显示一次,务必保存)" />
          <NStep title="用 injector CLI 生成集成模板" description="java -jar xcj-injector-all.jar init --output ./xcj-integration --app-id your-app-id --server-url https://xcj.winmelon.cn" />
          <NStep title="添加 gradle 依赖" description="复制到 app/build.gradle.kts 的 dependencies 块" />
          <NStep title="创建 Application 类" description="复制模板到项目,改包名" />
          <NStep title="配置 AndroidManifest" description="注册 Application + 添加网络权限" />
          <NStep title="配置 BuildConfig" description="在 build.gradle.kts 配置 appSecret" />
          <NStep title="调用卡密验证" description="在业务入口调用 activate / validate" />
        </NSteps>
      </NSpace>
    </NCard>

    <NCard title="1. Gradle 依赖">
      <NCode :code="gradleSnippet" language="kotlin" />
    </NCard>

    <NCard title="2. AndroidManifest.xml">
      <NCode :code="manifestSnippet" language="xml" />
    </NCard>

    <NCard title="3. Application 初始化">
      <NCode :code="applicationSnippet" language="kotlin" />
    </NCard>

    <NCard title="4. BuildConfig 配置">
      <NCode :code="buildConfigSnippet" language="kotlin" />
    </NCard>

    <NCard title="5. 调用卡密验证">
      <NCode :code="activateSnippet" language="kotlin" />
    </NCard>

    <NCard title="错误码说明">
      <NSpace vertical>
        <div><NText code>INVALID_CARD_KEY_FORMAT</NText> - 卡密格式错误</div>
        <div><NText code>CARD_NOT_FOUND</NText> - 卡密不存在</div>
        <div><NText code>CARD_DISABLED</NText> - 卡密已禁用</div>
        <div><NText code>CARD_EXPIRED</NText> - 卡密已过期</div>
        <div><NText code>CARD_ALREADY_BOUND_TO_OTHER_DEVICE</NText> - 已绑其他设备(FIRST_BIND)</div>
        <div><NText code>MAX_DEVICES_REACHED</NText> - 超过设备数上限(N_DEVICES)</div>
        <div><NText code>TRIAL_ALREADY_CLAIMED_BY_OTHER_DEVICE</NText> - 试用卡已被认领</div>
        <div><NText code>DEVICE_NOT_BOUND</NText> - 设备未绑定</div>
      </NSpace>
    </NCard>

    <NCard title="安全设计">
      <NSpace vertical>
        <div>✅ HTTPS 传输 + 应用层 AES-256-GCM 加密</div>
        <div>✅ HMAC-SHA256 签名 + nonce + 时间戳防重放</div>
        <div>✅ 卡密服务端只存 SHA-256 hash(不存明文)</div>
        <div>✅ 多租户 PostgreSQL RLS 隔离</div>
        <div>✅ 离线缓存加密(密钥由服务端下发)</div>
      </NSpace>
    </NCard>
  </NSpace>
</template>
