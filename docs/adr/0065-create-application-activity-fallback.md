# ADR 0065 · 无自定义 Application:创建 XcjApplication + Activity 兜底

- 状态:accepted
- 日期:2026-07-14
- 层次:注入工具

## 背景

约 30% APK 无自定义 Application(用默认 android.app.Application)。

## 决策

**创建 XcjApplication + 注册 Manifest + Activity 兜底**

- 创建 `com.xcj.sdk.XcjApplication extends android.app.Application`,dex 新增类
- 修改 AndroidManifest.xml(`<application android:name="...">`),用 AXMLPrinter2(ADR 0066)
- 改 Manifest 失败时,降级到第一个 Activity 的 onCreate 兜底

## 备选方案

| 方案 | 处理 | 不选原因 |
|---|---|---|
| 拒绝注入 | 提示注册 Application | 用户不友好 |
| 创建 XcjApplication(本方案) | + 注册 Manifest | 合理 |
| 注入默认 Application | 系统类不可改 | 不可行 |
| 仅 Activity 兜底 | 不创建 Application | 错过 Application 时机 |

## 影响

- 正面:覆盖无自定义 Application 的 APK
- 负面:改 AXML 复杂,可能失败
- 兜底:Activity onCreate 注入
- 开发量:3 天

## 关联

- 关联 ADR:0064(注入点)、0066(AXML 解析)
