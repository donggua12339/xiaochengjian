# ADR 0037 · 代码规范

- 状态:accepted
- 日期:2026-07-13
- 决策者:小城笺项目
- 层次:工程规范

## 背景

多语言项目需要统一代码规范,避免风格冲突,保证代码质量。

## 决策

### TypeScript(NestJS + Vue)
- **工具**:ESLint + Prettier
- **规则**:
  - `strict: true`、`noImplicitAny: true`、`strictNullChecks: true`
  - 禁 `any`、禁 `console.log`(用 Logger)、禁 `@ts-ignore`
- **命名**:
  - 文件:kebab-case(`card-key.service.ts`)
  - 类:PascalCase(`CardKeyService`)
  - 接口:PascalCase(不加 I 前缀)
  - 变量:camelCase

### Rust
- **工具**:rustfmt + clippy
- **规则**:
  - `#![deny(warnings)]`
  - 禁 `unsafe`(除非有 `// SAFETY:` 注释说明)
  - 公共函数必须有 doc comment
- **命名**:
  - 模块:snake_case
  - 类型:UpperCamelCase
  - 常量:SCREAMING_SNAKE_CASE

### Kotlin
- **工具**:ktlint + detekt
- **规则**:
  - 官方风格
  - 禁强制 `!!`(用 `requireNotNull` 或显式处理)
  - 禁 `println`(用 Timber 或自定义 Logger)
- **命名**:
  - 类:PascalCase
  - 函数:camelCase
  - 包:全小写

### SQL
- **工具**:sqlfluff
- **规则**:
  - 关键字大写,标识符小写
  - 所有查询必须参数化(禁字符串拼接)
  - 多租户表必须有 `tenant_id` 列 + RLS 策略

### Commit
- **工具**:commitlint + Conventional Commits
- **格式**:`type(scope): subject`
- **type**:`feat / fix / docs / chore / refactor / test / perf / ci / build / revert`
- **scope**:`backend / admin / sdk / injector / injector-android / deploy / docs / ci / root`
- **subject**:≤ 72 字符

### PR
- 模板:必填变更说明 + 影响范围 + 测试方式
- 标签:`feature / bug / docs / refactor / security`
- reviewer 必须批准

### 预提交钩子
- **Husky + lint-staged**
- 提交前自动 fix + 格式化
- commitlint 校验 commit message

### CI 卡点
- lint 不过 PR 不让合
- 覆盖率不达标 PR 不让合

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| 宽松规范 | 开发快 | 风格混乱 | 不可接受 |
| 严格规范 + Husky(本方案) | 质量高 | 学习成本 | 合理 |

## 影响

- 正面:代码质量有保障,风格统一
- 负面:开发者需适应规范
- 风险:无

## 关联

- 关联 ADR:0036(Monorepo)、0038(测试)、0034(CI/CD)
- 关联代码:`CLAUDE.md`、`commitlint.config.cjs`、`.github/workflows/ci.yml`
