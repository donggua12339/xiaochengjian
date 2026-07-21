# ADR 0080 · SDK 源码级集成(零字节码修改,ADR 0081 回退方案)

- 状态:accepted
- 日期:2026-07-21
- 决策者:小城笺项目
- 层次:功能 / 合规

## 背景

ADR 0076 方案 B 将项目定位为"独立开发者的私有应用攻防与遗产维护工具"。核心卡密鉴权能力通过 SDK 源码级集成实现:开发者在自己的 Android 项目源码中引入 xcj-auth-sdk,编译时自动集成,无需修改已编译的 APK。

ADR 0081 提议 APK 级封装(修改已编译 APK 的字节码),法律风险较高。本 ADR 作为 ADR 0081 的**回退方案**:若律师评估 APK 级封装风险不可控,则回退至本 ADR 的源码级集成方案。

## 决策

**SDK 源码级集成是卡密鉴权的默认且推荐方式。**

### 集成方式

开发者在自己的 Android 项目中:

1. 添加 gradle 依赖:
   ```kotlin
   implementation("com.xcj:xcj-auth-sdk:0.2.0")
   ```

2. 在 Application 中初始化:
   ```kotlin
   class MyApp : Application() {
       override fun onCreate() {
           super.onCreate()
           XiaochengjianSDK.init(this, SdkConfig(
               appId = "your-app-id",
               serverUrl = "https://xcj.winmelon.cn",
           ))
       }
   }
   ```

3. 在需要鉴权的入口调用:
   ```kotlin
   val result = XiaochengjianSDK.activate(cardKey)
   if (result.success) { /* 放行业务 */ }
   ```

### 优势(对比 APK 级封装)

| 维度 | 源码级集成(本 ADR) | APK 级封装(ADR 0081) |
|---|---|---|
| 字节码修改 | ❌ 无 | ✅ 改 superclass + 注入 dex |
| 重打包 | ❌ 无 | ✅ 需要 |
| 法律风险 | 低(标准 SDK 集成) | 高(需律师确认) |
| 适用场景 | 有源码 + Android Studio | 无源码 / 遗产 APK |
| MultiDex 兼容 | 自动(gradle 处理) | 需手动检测 |
| 签名 | 开发者正常编译签名 | 需自备 Keystore 重签 |

### 适用场景

- ✅ 有 Android 项目源码的开发者(推荐)
- ✅ 新项目集成卡密鉴权
- ✅ 有 Android Studio 环境的开发者

### 不适用场景(需 ADR 0081 补充)

- ❌ 无源码的遗产 APK(只有编译好的 .apk 文件)
- ❌ 无 Android Studio 环境的开发者
- ❌ 无法重新编译的第三方 SDK 依赖

## 备选方案

| 方案 | 说明 | 不选原因 |
|---|---|---|
| A. 仅源码级集成(本方案) | 默认推荐 | 无法覆盖无源码场景 |
| B. APK 级封装(ADR 0081) | 修改已编译 APK | 法律风险高,需律师前置 |
| C. 两者并存 | 源码级为主,APK 级为补充 | 本方案 + ADR 0081 的组合 |

## 影响

- 正面:零字节码修改,法律风险最低,与 ADR 0076 方案 B 完全兼容
- 负面:无法覆盖无源码的遗产 APK 场景(需 ADR 0081 补充)

## 关联

- 关联 ADR:0076(项目定位)、0077(自有 APK 诊断)、0081(APK 级封装,本 ADR 是其回退方案)
- 关联代码:`sdk-android/`(SDK 源码)、`docs/sdk-integration.md`(集成指南)
