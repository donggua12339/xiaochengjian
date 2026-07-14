# ADR 0064 · 注入点:Application.onCreate + attachBaseContext

- 状态:accepted
- 日期:2026-07-14
- 层次:注入工具

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
