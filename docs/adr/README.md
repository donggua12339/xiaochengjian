# Architecture Decision Records (ADR)

本目录记录小城笺项目的所有架构决策。每个 ADR 是一个不可变文档,决策变更写新 ADR 标记旧 ADR 为 superseded。

## ADR 列表

### 战略与产品

- [ADR 0001 · 项目定位与合规红线](0001-project-positioning-and-compliance.md)
- [ADR 0002 · 部署形态与商业模式](0002-deployment-and-business-model.md)
- [ADR 0003 · 里程碑规划](0003-milestone-planning.md)
- [ADR 0004 · 协作模式与开源治理](0004-collaboration-and-open-source-governance.md)

### 技术栈

- [ADR 0005 · 后端技术栈:NestJS](0005-backend-tech-stack.md)
- [ADR 0006 · 数据库:PostgreSQL 16](0006-database-postgresql.md)
- [ADR 0007 · 缓存:Redis 单机起步](0007-cache-redis.md)
- [ADR 0008 · 管理后台:Vue3 + Naive UI](0008-admin-vue3-naive-ui.md)
- [ADR 0009 · Android SDK:Kotlin + Rust JNI](0009-sdk-kotlin-rust-jni.md)
- [ADR 0010 · SDK 分发:AAR + 私有 Maven](0010-sdk-distribution.md)
- [ADR 0011 · APK 注入方案:Smali + dex](0011-injection-smali-dex.md)
- [ADR 0012 · 部署:Docker Compose + K8s](0012-deployment-compose-k8s.md)

### 核心功能

- [ADR 0013 · 卡密类型与生命周期](0013-card-key-types.md)
- [ADR 0014 · 卡密格式与生成策略](0014-card-key-format.md)
- [ADR 0015 · 设备绑定策略](0015-device-binding.md)
- [ADR 0016 · 机器码生成算法](0016-machine-id-algorithm.md)
- [ADR 0017 · 离线验证策略](0017-offline-validation.md)
- [ADR 0018 · 多应用与多租户](0018-multi-app-multi-tenant.md)

### 安全设计

- [ADR 0019 · 安全设计哲学](0019-security-philosophy.md)
- [ADR 0020 · 通信加密方案](0020-communication-encryption.md)
- [ADR 0021 · 请求签名与防重放](0021-request-signing.md)
- [ADR 0022 · 服务端防爆破](0022-anti-brute-force.md)
- [ADR 0023 · Rust 核心模块设计](0023-rust-core-design.md)
- [ADR 0024 · 反调试与 VM 检测](0024-anti-debug-vm-detection.md)
- [ADR 0025 · 完整性校验与防重打包](0025-integrity-check.md)
- [ADR 0026 · 离线缓存加密](0026-offline-cache-encryption.md)
- [ADR 0027 · 服务端安全基线](0027-server-security-baseline.md)

### 注入工具

- [ADR 0028 · 注入工具架构](0028-injector-architecture.md)
- [ADR 0029 · 加固 APK 兼容性](0029-hardened-apk-compatibility.md)
- [ADR 0030 · 防滥用机制](0030-anti-abuse.md)

### 运维与发布

- [ADR 0031 · SaaS 部署架构](0031-saas-deployment.md)
- [ADR 0032 · 监控告警与日志](0032-monitoring-logging.md)
- [ADR 0033 · 数据备份与灾备](0033-backup-dr.md)
- [ADR 0034 · CI/CD 流水线](0034-cicd-pipeline.md)
- [ADR 0035 · 版本发布与 i18n](0035-release-i18n.md)

### 工程规范

- [ADR 0036 · Monorepo 结构](0036-monorepo-structure.md)
- [ADR 0037 · 代码规范](0037-code-standards.md)
- [ADR 0038 · 测试策略](0038-testing-strategy.md)
- [ADR 0039 · 文档规范](0039-documentation-standards.md)

## 模板

新 ADR 使用 [0000-template.md](0000-template.md) 模板。
