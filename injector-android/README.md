# 小城笺 · 安卓端 APP(注入工具 + 管理)

> Jetpack Compose,开发者手机端使用

## 范围

- **注入工具**:上传 APK 到 SaaS 服务器处理,下载注入后 APK
- **管理 APP**:查看卡密 / 禁用 / 解绑、统计概览

## 状态

- M0:文档骨架(当前)
- M3:与 CLI 注入工具、部署并行(待启动)

## 关键 ADR

- [ADR 0028 · 注入工具架构](../docs/adr/0028-injector-architecture.md)
- [ADR 0008 · 管理后台(同功能移动端)](../docs/adr/0008-admin-vue3-naive-ui.md)

## 法律风险声明

⚠️ 上传他人 APK 进行注入属于侵权行为,详见[用户协议第 2 条](../docs/compliance/user-agreement.md)。
服务器**不持久化原始 APK**,注入完成后立即删除。
