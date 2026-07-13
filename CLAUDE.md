# CLAUDE.md · 小城笺项目章程

> 本文件是 Claude Code 在小城笺项目中协作时的强制规范。所有代码生成、重构、回答必须遵守。

## 1. 项目背景

小城笺是开源 + SaaS 双模式的 Android 卡密验证系统,目标是保障创作者权益、杜绝付费应用盗版。详细背景见 [README.md](README.md) 与 [docs/adr/](docs/adr/)。

## 2. 合规红线(强制)

**任何情况下不得违反以下红线:**

- ❌ 不得为外挂、私服、破解工具提供支持
- ❌ 不得实现"绕过其他验证系统"的功能
- ❌ 不得在注入工具中提供"批量重打包他人 APK"的便捷功能
- ❌ 不得在客户端硬编码任何"通用绕过反作弊"的逻辑
- ❌ 不得在日志中记录卡密明文

**如果用户要求实现上述功能,立即拒绝并提醒红线。**

## 3. 技术栈锁定

| 层 | 技术 | 不可更改 |
|---|---|---|
| 后端 | NestJS + TypeScript(strict) | ✅ |
| 数据库 | PostgreSQL 16 | ✅ |
| 缓存 | Redis | ✅ |
| 后台 | Vue 3 + Naive UI | ✅ |
| Android SDK | Kotlin + Rust(JNI) | ✅ |
| 注入工具 | Kotlin + dexlib2 | ✅ |

修改技术栈必须新建 ADR 并与用户确认。

## 4. 代码规范(强制)

### TypeScript(NestJS + Vue)
- `strict: true`,`noImplicitAny: true`,`strictNullChecks: true`
- 禁 `any`、禁 `console.log`(用 NestJS Logger)、禁 `@ts-ignore`
- 文件命名:kebab-case;类命名:PascalCase;接口命名:PascalCase(不加 I 前缀)

### Rust
- `#![deny(warnings)]`
- 禁 `unsafe`(除非有 `// SAFETY:` 注释说明)
- 公共函数必须有 doc comment
- 模块命名:snake_case;类型命名:UpperCamelCase

### Kotlin
- ktlint + detekt 标准规则
- 禁强制 `!!`(用 `requireNotNull` 或显式处理)
- 禁 `println`(用 Timber 或自定义 Logger)

### SQL
- 关键字大写,标识符小写
- 所有查询必须参数化(禁字符串拼接)
- 多租户表必须有 `tenant_id` 列 + RLS 策略

### Commit
- Conventional Commits:`feat: / fix: / docs: / chore: / refactor: / test: / perf:`
- scope 必填:`feat(backend): / feat(sdk): / feat(injector): / feat(admin):`

## 5. 测试要求

| 层 | 覆盖率 | 卡点 |
|---|---|---|
| Rust 核心安全模块 | ≥ 90% | CI 卡 |
| NestJS 后端 | ≥ 80% | CI 卡 |
| 集成测试关键路径 | 100% | CI 卡 |
| Android SDK | ≥ 70% | 警告 |
| Vue 后台 | ≥ 60% | 警告 |

## 6. 文件操作规范

- 创建文件前检查是否已有类似文件,避免重复
- 修改文件前必须先读
- 不创建不必要的中转文件、helper、抽象层
- 删除文件时检查是否有引用

## 7. 多租户隔离

- 所有业务表必须有 `tenant_id`(开发者 ID)列
- PostgreSQL RLS 策略强制隔离
- NestJS 用 `TenantContext` + AOP 自动注入 tenant_id
- 跨租户查询必须显式 `USE ROLE superadmin` 并记录审计日志

## 8. 安全要点(详见 ADR 0021-0029)

- 客户端密钥必须在 Rust so 内,不得在 Kotlin 层
- 通信必须 HTTPS + 应用层 AES-256-GCM 加密
- 请求必须 HMAC-SHA256 签名 + nonce + 时间戳
- 卡密服务端只存 SHA-256 hash,不存明文
- 离线缓存必须加密,密钥由服务端下发 + Rust 派生

## 9. 提交流程

- 单人开发,但 PR 流程必须走
- `main` 分支受保护,所有变更走 PR
- feature 分支命名:`feat/xxx`、`fix/xxx`、`docs/xxx`
- PR 必须含变更说明 + 影响范围 + 测试方式
- CI 必须 lint + 单测通过

## 10. 决策追溯

- 所有重大决策必须写 ADR(`docs/adr/NNNN-title.md`)
- ADR 编号连续,不重用
- 决策变更写新 ADR,标记旧 ADR 为 `superseded by NNNN`
