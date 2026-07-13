# 小城笺 · Xiaochengjian

> 开源 + SaaS 双模式的 Android 卡密验证系统,保障创作者权益,杜绝付费应用盗版。

## 项目定位

| 维度 | 内容 |
|---|---|
| 形态 | 开源 + SaaS 双模式 |
| 目标用户 | 个人 Android 应用开发者(MVP 仅 Android) |
| 价值主张 | 保障创作者权益,杜绝付费应用盗版 |
| 商业模式 | 开发者订阅(月度 + 终身 + VIP 解锁功能) |

## 合规红线(极其重要)

本项目仅用于**开发者对自己开发的付费应用做版权保护**。禁止用于:

- ❌ 外挂、私服、破解工具
- ❌ 规避反作弊系统
- ❌ 赌博、诈骗
- ❌ 主动提供"绕过其他验证系统"的功能
- ❌ 注入他人 APK 用于商业转售(注入工具仅限开发者自有 APK)

用户在使用前必须阅读并同意[用户协议](docs/compliance/user-agreement.md)。发现滥用行为将封号并配合司法调查。

## 仓库结构

```
xiaochengjian/
├── backend/              # NestJS 后端(TS 严格模式)
├── admin-web/            # Vue3 + Naive UI 管理后台
├── sdk-android/          # Android SDK(Kotlin + Rust JNI)
│   ├── kotlin/           # AAR 模块
│   └── rust/             # so 核心安全模块
├── injector/             # 注入工具 CLI(Kotlin + dexlib2)
├── injector-android/     # 安卓端注入工具 + 管理 APP
├── deploy/               # docker-compose / Helm
├── docs/                 # 文档与 ADR
├── .github/workflows/    # CI
├── CLAUDE.md             # 项目章程与编码规范
└── README.md
```

## 技术栈

| 层 | 技术 |
|---|---|
| 后端 | Node.js 20 + NestJS 10 + TypeScript 5(strict) |
| 数据库 | PostgreSQL 16(RLS 多租户隔离) |
| 缓存 | Redis 7(单机起步) |
| 后台 | Vue 3 + Naive UI + Vite + Pinia + TypeScript |
| Android SDK | Kotlin 2.0 + Rust(stable)+ JNI |
| 注入工具 | Kotlin + dexlib2 + apksigner |
| 部署 | Docker Compose(开源版)/ K8s(SaaS 版) |
| 监控 | Prometheus + Grafana + Loki |
| CI | GitHub Actions |

## 开发指南

- [架构总览](docs/architecture.md)
- [SDK 集成指南](docs/sdk-guide.md)
- [注入工具指南](docs/injector-guide.md)
- [部署指南](docs/deploy.md)
- [安全白皮书](docs/security.md)
- [架构决策记录(ADR)](docs/adr/README.md)

## 里程碑

| 里程碑 | 范围 | 状态 |
|---|---|---|
| M0 | 基建 + 文档骨架 + ADR | 进行中 |
| M1 | 后端 + 管理后台 | 待启动 |
| M2 | Android SDK + Rust 核心 | 待启动 |
| M3 | 注入工具 + 部署 + 监控 | 待启动 |

## 贡献

- 欢迎 issue 与 PR,但**核心 Rust 安全模块**仅接受 issue,不接受外部 PR
- 提交 PR 前请签署 [CLA](docs/cla.md)
- 遵循 [Conventional Commits](https://www.conventionalcommits.org/)

## License

Apache License 2.0
