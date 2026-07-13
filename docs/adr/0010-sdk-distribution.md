# ADR 0010 · SDK 分发:AAR + 私有 Maven

- 状态:accepted
- 日期:2026-07-13
- 决策者:小城笺项目
- 层次:技术栈

## 背景

SDK 需要分发给开发者集成。分发方式影响版本管理、VIP 等级控制、破解难度。

## 决策

### 分发形态:AAR via 私有 Maven
- **格式**:AAR(Android Archive),含 Kotlin dex + Rust so + 资源
- **仓库**:私有 Maven 仓库(SaaS 用户凭 token 拉取)
- **集成**:开发者 `build.gradle.kts` 一行 `implementation` 引入

### 版本控制
- SDK 版本号与注入工具版本号独立
- SDK 每月发布 MINOR 版本
- LTS 版本每 6 个月一个,维护 1 年

### VIP 等级控制
- 免费 SDK:基础功能,带"小城笺"水印
- VIP SDK:无水印,高级功能(API 高调用上限、多应用支持、自定义 UI)
- 通过 Maven 仓库 token 鉴权控制访问不同 SDK 版本

### 防破解考虑
- **不发布到 Maven Central**:公开发布会让破解者轻易拿到所有版本对比 diff
- 私有 Maven 仅授权开发者可访问
- SDK 内置 license 校验,运行时验证开发者 token

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| AAR(本方案) | Android 标准 | - | 行业惯例 |
| JAR + so | 灵活 | 集成麻烦 | 体验差 |
| Maven Central 公开 | 易分发 | 破解者易获取 | 安全风险 |

## 影响

- 正面:开发者集成简单,VIP 分级清晰
- 负面:需维护私有 Maven 仓库(可用 Nexus / JFrog)
- 风险:私有 Maven 单点故障会导致 SDK 无法拉取,需有备份方案

## 关联

- 关联 ADR:0009(Kotlin + Rust)、0002(双模式)
- 关联代码:`sdk-android/kotlin/build.gradle.kts`
