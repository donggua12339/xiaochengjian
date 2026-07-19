# 小城笺 SDK 集成指南

本文档指导开发者将小城笺 SDK 集成到**自有著作权**的 Android 应用中,实现卡密验证功能。

## 合规边界(先读)

**允许**:
- 集成到**你自有著作权**的 Android 应用
- 在你自己开发的 APP 里调用 SDK 做卡密验证

**禁止**(CLAUDE.md 红线):
- 绕过其他验证系统

小城笺 v2 主要为开发者主动集成模式。`injector/` CLI 仅提供:
- `init` 子命令:生成 SDK 集成代码模板
- `sign` 子命令:对开发者自有 APK 做签名 + 水印(可选)

## 集成步骤

### 1. 在 Web 后台创建应用

登录 https://xcj.winmelon.cn 注册开发者账号,创建应用,获得:
- `appId`:应用 ID
- `appSecret`:应用密钥(仅创建时显示一次,务必保存)

### 2. 用 injector CLI 生成集成模板

```bash
java -jar xcj-injector-all.jar init \
  --output ./xcj-integration \
  --app-id your-app-id \
  --server-url https://xcj.winmelon.cn
```

生成 3 个文件:
- `xcj-dependency.gradle.kts` - gradle 依赖片段
- `XcjApplication.kt` - Application 初始化模板
- `README.md` - 集成步骤说明

### 3. 集成到项目

**步骤 1**:把 `xcj-dependency.gradle.kts` 的依赖复制到 `app/build.gradle.kts`:

```kotlin
dependencies {
    implementation("com.xcj:sdk-android:0.2.0")
}
```

**步骤 2**:把 `XcjApplication.kt` 复制到你的项目,改包名,在 `AndroidManifest.xml` 设置:

```xml
<application
    android:name=".XcjApplication"
    ...>
```

**步骤 3**:在 `build.gradle.kts` 的 `defaultConfig` 配置 appSecret:

```kotlin
android {
    defaultConfig {
        buildConfigField("String", "XCJ_APP_SECRET", "\"your-app-secret\"")
    }
    buildFeatures {
        buildConfig = true
    }
}
```

### 4. 调用卡密验证

```kotlin
import com.xcj.sdk.XiaochengjianSDK
import com.xcj.sdk.SdkConfig

// Application.onCreate 已初始化 SDK,业务代码直接调用

// 激活卡密(用户输入卡密后调用)
val result = XiaochengjianSDK.activate(
    cardKey = "XXXX-XXXX-XXXX-XXXX",
    machineId = getMachineId(this), // 你的设备唯一标识
)
if (result.success) {
    // 激活成功,放行业务
    // result.expiresAt - 卡密过期时间
    // result.cacheKey - 离线缓存密钥(由 SDK 内部管理,业务无需关心)
} else {
    // 激活失败
    when (result.reason) {
        "CARD_NOT_FOUND" -> showError("卡密不存在")
        "CARD_DISABLED" -> showError("卡密已禁用")
        "CARD_EXPIRED" -> showError("卡密已过期")
        "CARD_ALREADY_BOUND_TO_OTHER_DEVICE" -> showError("卡密已绑定其他设备")
        "MAX_DEVICES_REACHED" -> showError("已达最大设备数")
        "TRIAL_ALREADY_CLAIMED_BY_OTHER_DEVICE" -> showError("试用卡已被其他设备认领")
    }
}

// 验证卡密(每次启动 APP 时调用,刷新 cacheKey)
val validateResult = XiaochengjianSDK.validate(
    cardKey = "XXXX-XXXX-XXXX-XXXX",
    machineId = getMachineId(this),
)
if (validateResult.valid) {
    // 验证通过,放行业务
} else {
    // 验证失败,可能是离线缓存过期或卡密被禁用
    when (validateResult.reason) {
        "CARD_DISABLED" -> showDisabled()
        "CARD_EXPIRED" -> showExpired()
        "DEVICE_NOT_BOUND" -> showRebind()
    }
}
```

## 错误码说明

| 错误码 | 含义 | 用户提示 |
|---|---|---|
| `INVALID_CARD_KEY_FORMAT` | 卡密格式错误 | 卡密格式不正确 |
| `CARD_NOT_FOUND` | 卡密不存在 | 卡密不存在 |
| `CARD_DISABLED` | 卡密已禁用 | 卡密已禁用,请联系客服 |
| `CARD_EXPIRED` | 卡密已过期 | 卡密已过期 |
| `CARD_ALREADY_BOUND_TO_OTHER_DEVICE` | 已绑其他设备(FIRST_BIND) | 卡密已绑定其他设备 |
| `MAX_DEVICES_REACHED` | 超过设备数上限(N_DEVICES) | 已达最大设备数 |
| `TRIAL_ALREADY_CLAIMED_BY_OTHER_DEVICE` | 试用卡已被认领 | 试用卡已被其他设备认领 |
| `DEVICE_NOT_BOUND` | 设备未绑定 | 设备未绑定,请重新激活 |

## SDK 端点(供高级用户参考)

SDK 内部调用以下后端端点(通常业务无需关心):

| 端点 | 用途 |
|---|---|
| `POST /v1/sdk/handshake` | RSA 协商 AES-256 密钥,返回 sessionId |
| `POST /v1/sdk/activate` | 激活卡密(需签名 + 加密) |
| `POST /v1/sdk/validate` | 验证卡密(需签名 + 加密) |
| `POST /v1/sdk/heartbeat` | 会话保活 + 密钥轮换 |
| `GET /v1/sdk/time` | 服务器时间(时间同步) |
| `GET /v1/sdk/integrity` | 完整性校验值(签名白名单) |

所有 `activate` / `validate` / `heartbeat` 请求需要:
- `x-session-id` - handshake 返回的 sessionId
- `x-timestamp` - 时间戳(偏差 > 60s 拒绝)
- `x-nonce` - 随机 nonce(5 分钟内不可重复)
- `x-signature` - HMAC-SHA256 签名
- `encryptedBody` - AES-256-GCM 加密的请求体

## 安全设计

- **HTTPS 传输**:所有通信走 HTTPS
- **应用层加密**:RSA 协商 AES-256-GCM 密钥,请求体加密
- **HMAC 签名**:防篡改 + 防重放(nonce + 时间戳)
- **卡密不明文存储**:服务端只存 SHA-256 hash + salt
- **多租户隔离**:PostgreSQL RLS 强制隔离
- **离线缓存加密**:由服务端下发密钥,SDK 内部管理

## 故障排查

### SDK 初始化失败

检查 `XcjApplication.kt` 是否在 `AndroidManifest.xml` 正确注册:
```xml
<application android:name=".XcjApplication">
```

### 激活返回 `INVALID_SIGNATURE`

SDK 内部签名错误,通常是 `appSecret` 配置错误。检查 `buildConfigField("XCJ_APP_SECRET")` 是否和 Web 后台一致。

### 激活返回 `CARD_NOT_FOUND` 但卡密看起来正确

- 确认卡密没有多余空格
- 确认 `appId` 和 Web 后台创建的应用 ID 一致
- 确认服务器时间正确(`GET /v1/sdk/time` 对比)

### 离线验证不工作

- 检查 APP 的离线缓存天数设置(Web 后台应用配置)
- SDK 会在缓存有效期内允许离线验证,过期后必须在线验证

## 限制

- SDK 需要 Android API 24+(Android 7.0)
- 需要网络权限(`<uses-permission android:name="android.permission.INTERNET" />`)
- 离线缓存由 SDK 内部管理,业务层无需关心

## 参考

- [ADR 0013](../adr/0013-card-key-types.md) - 卡密类型
- [ADR 0014](../adr/0014-card-key-format.md) - 卡密格式与生成
- [ADR 0015](../adr/0015-device-binding.md) - 设备绑定
- [ADR 0020](../adr/0020-communication-encryption.md) - 通信加密
- [ADR 0021](../adr/0021-request-signature.md) - 请求签名与防重放
- [CLAUDE.md](../../CLAUDE.md) - 项目章程与合规红线
