# ADR 0064 · 注入点:Application.onCreate + attachBaseContext

- 状态:**superseded by 0068**(v2 重构撤除 dex 注入,无注入点概念)
- 日期:2026-07-14
- 层次:注入工具

> **本 ADR 已被 [ADR 0068](0068-v2-injector-architecture-sdk-integration-only.md) 取代**(2026-07-19)。
> v2 改为开发者主动集成 SDK,在自有 Application.onCreate 调用 XiaochengjianSDK.init(this),无需注入工具操作注入点。
> 本文档保留作为决策追溯,不再有效。

## 背景

ADR E2 定了 Application.onCreate 主 + MainActivity 兜底,需细化。

## 决策

**Application.onCreate 主 + attachBaseContext 兜底**

- onCreate:标准入口,99% APK 必经
- attachBaseContext:早于 onCreate,部分加固接管 onCreate 时兜底
- 双注入:SDK init 内部幂等(多次调用安全)

## 备选方案

| 方案 | 注入点 | 不选原因 |
|---|---|---|
| 仅 onCreate | 标准 | 加固接管失效 |
| onCreate + attachBaseContext(本方案) | 双 | 合理 |
| + <clinit> | 类加载 | 太早,Context 未就绪 |
| + ContentProvider | 早于 Application | ADR E2 排除 |

## 影响

- 正面:双注入兜底,覆盖加固 APK
- 负面:SDK init 需幂等
- 开发量:2 天

## 关联

- 关联 ADR:E2(注入点)、0063(ImmutableDexFile)
