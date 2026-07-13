# ADR 0036 · Monorepo 结构

- 状态:accepted
- 日期:2026-07-13
- 决策者:小城笺项目
- 层次:工程规范

## 背景

卡密验证系统子项目耦合紧密(SDK 与后端 API 契约、注入工具与 SDK 版本同步),需统一管理。

## 决策

### 仓库结构:Monorepo
- **pnpm workspace**(前端 + 后端 + 注入工具)
- **Cargo workspace**(Rust 核心)
- **Gradle**(Android SDK + 安卓注入工具)
- **Git submodule**(仅文档,可选)

### 目录结构
```
xiaochengjian/
├── backend/              # NestJS 后端(TS)
├── admin-web/            # Vue3 + Naive UI 管理后台(TS)
├── sdk-android/          # Android SDK
│   ├── kotlin/           # AAR 模块(Kotlin + Gradle)
│   └── rust/             # so 核心安全模块(Cargo workspace)
├── injector/             # 注入工具 CLI(Kotlin + dexlib2)
├── injector-android/     # 安卓端注入工具 + 管理 APP(Compose)
├── deploy/               # docker-compose / Helm
│   ├── docker-compose.yml
│   └── helm/
├── docs/                 # 文档与 ADR
│   ├── adr/
│   ├── architecture.md
│   ├── sdk-guide.md
│   ├── injector-guide.md
│   ├── deploy.md
│   ├── security.md
│   ├── cla.md
│   └── compliance/
├── .github/
│   ├── workflows/
│   └── ISSUE_TEMPLATE/
├── CLAUDE.md
├── README.md
├── LICENSE
├── package.json          # pnpm workspace 根
├── pnpm-workspace.yaml
├── commitlint.config.cjs
└── .gitignore
```

### 跨项目共享
- **shared-types** 包:TypeScript 类型定义,NestJS 与 Vue 共享
- OpenAPI 自动生成 TypeScript 客户端
- Rust 核心 so 编译产物供 Android SDK 引用

### 分支策略
- `main`:受保护,对应生产
- `dev`:开发分支
- `feat/xxx`、`fix/xxx`、`docs/xxx`:功能分支

### SaaS 独有功能隔离
- 同一仓库
- SaaS 独有功能用 feature flag(`ENABLE_SAAS` 编译时变量)控制
- 编译开源版时排除 SaaS 模块

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| Polyrepo | 隔离清晰 | 跨改难 | 耦合紧密 |
| Monorepo(本方案) | 跨改方便 | 仓库大 | 合理 |
| 混合(核心 Monorepo + 工具单独) | 折中 | 边界模糊 | 不必要 |

## 影响

- 正面:跨项目改动原子提交,版本同步简单
- 负面:仓库体积大,CI 需按路径触发
- 风险:子项目耦合度过高时重构困难

## 关联

- 关联 ADR:0002(双模式)、0034(CI/CD)、0037(代码规范)
- 关联代码:仓库根目录
