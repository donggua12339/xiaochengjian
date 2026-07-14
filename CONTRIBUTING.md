# 贡献指南

感谢你对小城笺项目的兴趣!欢迎提交 issue 和 PR。

## 提交前准备

1. **签署 CLA**:首次 PR 需签署 [贡献者协议](docs/cla.md)。cla-assistant.io 会自动提示。
2. **阅读 ADR**:了解项目决策,特别是 [合规红线](README.md#合规红线)。
3. **开发环境**:Node.js 22+ / pnpm 9+ / Rust stable / Android SDK 35。

## 开发流程

### 1. Fork + Clone

```bash
git clone https://github.com/your-username/xiaochengjian.git
cd xiaochengjian
pnpm install  # backend + admin-web 依赖
```

### 2. 创建分支

```bash
git checkout -b feat/your-feature
# 或 fix/your-bugfix
```

### 3. 开发 + 测试

```bash
# 后端
cd backend
pnpm test         # 单测
pnpm test:e2e     # e2e

# 前端
cd admin-web
pnpm build

# SDK
cd sdk-android/rust
cargo test

# 注入工具
cd injector
./gradlew jar
```

### 4. Commit(Conventional Commits)

```bash
git commit -m "feat(backend): 加 XYZ 接口"
# feat / fix / docs / chore / refactor / test
```

### 5. Push + PR

```bash
git push origin feat/your-feature
```

在 GitHub 创建 PR,填写模板(变更说明 + 影响范围 + 测试方式)。

## 代码规范

| 语言 | 工具 | 要求 |
|---|---|---|
| TypeScript | ESLint + Prettier | strict 模式,禁 any |
| Rust | rustfmt + clippy | `#![deny(warnings)]` |
| Kotlin | ktlint + detekt | 官方风格 |

CI 会自动检查,不通过不让合并。

## 测试要求

| 模块 | 覆盖率 |
|---|---|
| Rust 核心 | ≥ 90% |
| NestJS 后端 | ≥ 80% |
| Vue 前端 | ≥ 60% |

## 核心模块限制

**Rust 安全核心**(`sdk-android/rust/xcj-core/`)不接受外部 PR,只接受 issue(ADR 0004)。原因:安全模块需要内部审计,社区贡献难以验证安全性。

其他模块(backend / admin-web / injector / docs)欢迎 PR。

## Issue 模板

- **Bug**:复现步骤 + 期望 + 实际 + 版本
- **Feature**:用例 + 方案建议 + 影响范围
- **Security**:见 [SECURITY.md](SECURITY.md),不要公开 issue

## 行为准则

保持友善,尊重不同观点。技术讨论对事不对人。
