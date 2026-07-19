# ADR 0066 · AXML 解析:AXMLPrinter2

- 状态:**superseded by 0068**(v2 重构撤除 dex 注入,无需自动改 Manifest)
- 日期:2026-07-14
- 层次:注入工具

> **本 ADR 已被 [ADR 0068](0068-v2-injector-architecture-sdk-integration-only.md) 取代**(2026-07-19)。
> v2 改为开发者主动集成 SDK,Manifest 注册由开发者手动完成(`injector init` 生成的 README 含步骤说明)。
> 本文档保留作为决策追溯,不再有效。

## 背景

AndroidManifest.xml 是二进制 AXML 格式,需解析找 application name + 修改注册新 Application。

## 决策

**AXMLPrinter2 / AXMLEditor**

- 解析:找 `<application android:name="...">`
- 编辑:注册 XcjApplication(ADR 0065)
- Alibaba 开源,既能解析又能编辑

## 备选方案

| 方案 | 解析 | 不选原因 |
|---|---|---|
| 自己解析 | 理解 AXML chunk | 1 周起 |
| AXMLPrinter2(本方案) | 开源库 | 合理 |
| apktool | 慢 | ADR E3 备用 |
| 粗暴扫描 | UTF-16 字符串 | 不可靠(当前简化版) |

## 影响

- 正面:开源库,2 天集成
- 负面:AXMLPrinter2 维护不活跃,可能需 fork
- 开发量:2 天

## 关联

- 关联 ADR:0065(创建 Application)、0063(ImmutableDexFile)
