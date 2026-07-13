# ADR 0034 · CI/CD 流水线

- 状态:accepted
- 日期:2026-07-13
- 决策者:小城笺项目
- 层次:运维

## 背景

多语言(Monorepo:TS + Rust + Kotlin)需要统一 CI 流水线,卡点清晰。

## 决策

### CI/CD:GitHub Actions 单流水线,分阶段并行

### 阶段

| 阶段 | 工具 | 触发 | 卡点 |
|---|---|---|---|
| 代码检查 | ESLint + Prettier + Rustfmt + Clippy + ktlint | PR | 必须 |
| 单测 | Jest + Vitest + Cargo Test + JUnit | PR | 必须 |
| 构建 | Docker buildx 多架构(amd64/arm64) | main | 必须 |
| 集成测试 | docker-compose 起依赖 + 跑 e2e | main | 必须 |
| 安全扫描 | Trivy + npm audit + cargo audit | 每日 + main | 必须 |
| 发布 | GitHub Release + Maven + Docker Hub | tag | - |
| 部署 | SaaS: K8s 滚动 / 开源版: compose | tag | 人工确认 |

### PR 阶段(< 5 分钟)
- lint
- 单测
- 覆盖率卡点(Rust ≥ 90% / NestJS ≥ 80%)

### main 分支(< 15 分钟)
- 构建
- 集成测试
- 安全扫描

### tag 触发发布
- 镜像推 Docker Hub
- AAR 推私有 Maven
- 注入工具推 GitHub Release
- **不自动部署到 SaaS 生产**:tag 触发构建镜像,人工确认后手动 `kubectl apply`

### 多架构构建
- amd64:服务器
- arm64:树莓派 / 苹果 M 芯片开发者

### Secrets 管理
- 所有 secrets 走 GitHub Actions secrets
- 不进代码仓库
- 定期轮换

### 缓存策略
- pnpm cache
- Cargo cache
- Gradle cache
- Docker layer cache

### 并行优化
- lint / test-rust / test-backend / test-admin-web 并行
- build-sdk 独立(慢)
- integration-test 依赖 test-backend

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| GitLab CI | 自托管 | 维护成本 | 项目开源用 GitHub |
| Jenkins | 灵活 | 重 | 过度设计 |
| GitHub Actions(本方案) | 免费 2000 分钟/月 | 私有仓库收费 | 合理 |

## 影响

- 正面:开源项目免费 CI,流水线清晰
- 负面:GitHub Actions 限额 2000 分钟/月,需优化
- 风险:Rust 编译慢,需 cargo cache

## 关联

- 关联 ADR:0036(Monorepo)、0038(测试策略)、0035(发布)
- 关联代码:`.github/workflows/ci.yml`
