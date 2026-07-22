# Architecture Decision Records (ADR)

本目录记录小城笺项目的所有架构决策。每个 ADR 是一个不可变文档,决策变更写新 ADR 标记旧 ADR 为 superseded。

## ADR 列表

### 战略与产品

- [ADR 0001 · 项目定位与合规红线](0001-project-positioning-and-compliance.md) · ⚠️ **superseded by 0076**
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
- [ADR 0011 · APK 注入方案:Smali + dex](0011-injection-smali-dex.md) · ⚠️ **superseded by 0068**
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
- [ADR 0023 · Rust 核心模块设计](0023-rust-core-design.md) · ⚠️ **superseded by 0071**
- [ADR 0024 · 反调试与 VM 检测](0024-anti-debug-vm-detection.md)
- [ADR 0025 · 完整性校验与防重打](0025-integrity-check.md)
- [ADR 0026 · 离线缓存加密](0026-offline-cache-encryption.md)
- [ADR 0027 · 服务端安全基线](0027-server-security-baseline.md)

### 注入工具

- [ADR 0028 · 注入工具架构](0028-injector-architecture.md) · ⚠️ **superseded by 0068**
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

### SaaS 上线 + 开源 + 安全 + dex 深化(grill-me 第二轮,2026-07-14)

#### 根决策(跨主题)

- [ADR 0040 · 开源发布时机:SaaS 上线后开源](0040-open-source-timing-after-saas.md)
- [ADR 0041 · SaaS 与开源版边界:SaaS 增值](0041-saas-open-source-boundary.md)
- [ADR 0042 · 安全设计公开边界:架构公开,实现保留](0042-security-disclosure-boundary.md)
- [ADR 0043 · 商业化定价:订阅制](0043-pricing-subscription.md)

#### A 层 SaaS 上线

- [ADR 0044 · 支付对接:发卡网 + 会员激活码](0044-payment-faka-wm.md)
- [ADR 0045 · 域名 + 备案:国内域名 + 海外服务器](0045-domain-overseas-server.md)
- [ADR 0046 · 服务器选型:雨云 1C2G](0046-server-rainyun-1c2g.md)
- [ADR 0047 · 定价档位:免费 + 基础 + VIP](0047-pricing-tiers.md)
- [ADR 0048 · 注册方式:邮箱 + GitHub + QQ OAuth](0048-auth-email-github-qq.md)
- [ADR 0049 · SLA + 退款政策](0049-sla-refund-policy.md)
- [ADR 0050 · 服务器内存调优](0050-server-memory-tuning.md)
- [ADR 0051 · WM 发卡不稳定兜底](0051-wm-fallback-manual.md)
- [ADR 0052 · 退款法律条款:数字商品不适用 7 天无理由](0052-refund-legal-clause.md)

#### E 层 开源发布

- [ADR 0053 · 仓库结构:单仓库 + GitHub Pages](0053-repo-monorepo-pages.md)
- [ADR 0054 · README 深度:标准 + docs/ 链接](0054-readme-standard-depth.md)
- [ADR 0055 · CLA 流程:cla-assistant.io](0055-cla-cla-assistant.md)
- [ADR 0056 · 版本管理:GitHub Actions + 手动 tag](0056-release-manual-tag.md)
- [ADR 0057 · 安全披露:邮箱 + GitHub Security Advisory](0057-security-disclosure.md)

#### F 层 安全加固深化

- [ADR 0058 · Rust so 自校验:编译时嵌入 + 服务端下发](0058-rust-self-verify.md) · ⚠️ **superseded by 0069**
- [ADR 0059 · 反调试深化:Frida 高级 + Xposed 检测](0059-anti-debug-frida-xposed.md)
- [ADR 0060 · 通信密钥轮换:每 20 分钟](0060-key-rotation-20min.md)
- [ADR 0061 · 混淆策略:字符串 + 控制流](0061-obfuscation-string-control-flow.md)
- [ADR 0062 · 防重打包:直接读 APK + 服务端下发](0062-anti-repackage-apk-hash.md) · ⚠️ **superseded by 0070**

#### B 层 dex 指令插入深化

- [ADR 0063 · dex 指令插入:ImmutableDexFile 重建](0063-dex-immutable-rebuild.md) · ⚠️ **superseded by 0068**
- [ADR 0064 · 注入点:onCreate + attachBaseContext](0064-injection-point-oncreate-attachbase.md) · ⚠️ **superseded by 0068**
- [ADR 0065 · 无自定义 Application:创建 XcjApplication + Activity 兜底](0065-create-application-activity-fallback.md) · ⚠️ **superseded by 0068**
- [ADR 0066 · AXML 解析:AXMLPrinter2](0066-axml-axmlprinter2.md) · ⚠️ **superseded by 0068**
- [ADR 0067 · 加固 APK 兼容:MVP 不支持](0067-hardened-apk-mvp-skip.md) · ⚠️ **"自动脱壳推 v3"条款被 ADR 0079 部分取代(仅梆梆自检场景)**

### v2 重构决策追溯(2026-07-19,补齐上任工程师未完成的 ADR 合规)

- [ADR 0068 · v2 注入工具架构:仅 SDK 集成辅助](0068-v2-injector-architecture-sdk-integration-only.md) - 取代 0011/0028/0063/0064/0065/0066
- [ADR 0069 · Rust so 自校验撤除:服务端验证权威](0069-rust-self-verify-removal.md) - 取代 0058
- [ADR 0070 · APK 签名 hash 简化实现:整文件 hash + 服务端白名单兜底](0070-apk-signature-hash-simplified.md) - 取代 0062
- [ADR 0071 · Rust 核心设计修订:语义化 JNI + 撤除反逆向设施](0071-rust-core-design-revision.md) - 取代 0023
- [ADR 0072 · MVP 备份简化:本地 + 7 天滚动 + gpg AES-256](0072-mvp-backup-simplified.md) - ADR 0033 分阶段落地

### P3-P5 扩展(2026-07-19)

- [ADR 0073 · SDK 控制流平坦化设计(未来工作)](0073-sdk-control-flow-flattening-design.md) - proposed
- [ADR 0074 · 第三方 OAuth 集成:GitHub + QQ(代码框架)](0074-oauth-github-qq.md) - proposed,待 OAuth app 配置
- [ADR 0075 · WM 发卡网 API 对接设计](0075-wm-faka-api-integration.md) - proposed,待 WM API 文档

### 项目定位修订评估(2026-07-19)

- [ADR 0076 · 项目定位修订评估:攻防工作台](0076-project-positioning-revision-assessment.md) - **accepted**(方案 B,自有 APK 诊断),取代 ADR 0001
- [ADR 0077 · 自有 APK 诊断功能(含技术兜底)](0077-self-apk-audit.md) - accepted(2026-07-20 修订加例外 A 签名回填 + 例外 B 梆梆适配器),功能级 ADR,三重校验(包名白名单 + 签名比对 + 目录隔离)
- [ADR 0078 · 梆梆加固自检适配器(自有 APK 诊断例外 B 的实现)](0078-bangcle-hardener-self-audit-adapter.md) - **accepted**(律师意见已落地,2026-07-20),3 把锁(仅梆梆 / EULA / 仅完整性报告),Supersedes ADR 0067 partial
- [ADR 0079 · 部分取代 ADR 0067(仅"自动脱壳推 v3"条款,梆梆自检场景)](0079-partial-supersede-0067-bangcle-only.md) - **accepted**(律师意见已落地,2026-07-20),最小取代范围,3 个限定(仅梆梆 / 仅 integrity / 不解未知)
- [ADR 0080 · SDK 源码级集成(零字节码修改,ADR 0081 回退方案)](0080-sdk-source-integration.md) - **accepted**,默认推荐集成方式,无源码场景需 ADR 0081 补充
- [ADR 0081 · 自有 APK 的 xcj-auth-sdk 封装器(Packer 模块)](0081-self-apk-sdk-packer.md) - **accepted**(律师预审通过,2026-07-21,🟡 中低风险),七锁架构(含客户端签名自检),回退方案 ADR 0080
- [ADR 0082-A · 360 加固保自检适配器(V1.5b)](0082-a-360-jiagu-self-audit-adapter.md) - **proposed**(合规核查已通过,2026-07-21),libjiagu.so 检测,360 EULA 第 4.1 条"本软件"指加固助手本身不指 APK
- [ADR 0082-B · 腾讯乐固自检适配器(V1.5a,优先实现)](0082-b-tencent-legu-self-audit-adapter.md) - **proposed**(合规核查已通过,2026-07-21),libshell.so 检测,协议环境宽松
- [ADR 0082-C · 爱加密自检适配器(V2 评估)](0082-c-ijiami-self-audit-adapter.md) - **draft**(暂不开发),V2 评估
- [ADR 0085 · 加固 APK 与 xcj-auth-sdk 的兼容性边界分析](0085-hardened-apk-sdk-compatibility-boundary.md) - **accepted**(边界分析,无代码实现),技术死锁形式化证明 + 4 条合规替代路径

## 模板

新 ADR 使用 [0000-template.md](0000-template.md) 模板。
