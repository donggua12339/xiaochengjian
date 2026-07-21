# CLAUDE.md · 小城笺项目章程

> 本文件是 Claude Code 在小城笺项目中协作时的强制规范。所有代码生成、重构、回答必须遵守。

## 1. 项目背景

小城笺是「独立开发者的私有应用攻防与遗产维护工具」,开源 + SaaS 双模式。

- **核心定位**(ADR 0076 accept 方案 B,2026-07-19):
  - 蓝方能力(防):卡密验证、加固、防二次打包 -- 保障创作者权益
  - 红方能力(攻):**自有 APK 诊断**(JADX 反编译查看 + 签名信息 + SDK 后门扫描)-- 仅限开发者拥有合法著作权的自有 APK
  - 红方功能严格限定为"仅处理用户本地拥有的、具有合法著作权的 APK 文件",三重校验强制(包名白名单 + 签名比对 + 目录隔离,详见 ADR 0077)
  - 彻底切割与盗版/黑产/通用脱壳/通用去签的关联

- **不允许的红方能力**(红线):
  - 通用脱壳(任意 APK 脱壳,FRIDA-DEXDump 类)
  - 通用去签名校验(任意 APK 去签)
  - 字节码修改 / 重打包他人 APK

详细背景见 [README.md](README.md) 与 [docs/adr/](docs/adr/)。

## 2. 合规红线(强制)

**任何情况下不得违反以下红线:**

- ❌ 不得实现"绕过其他验证系统"的功能(通用脱壳 / 通用去签 / 通用绕过反作弊)
- ❌ 不得在客户端硬编码任何"通用绕过反作弊"的逻辑
- ❌ 不得在日志中记录卡密明文
- ❌ 不得对他人 APK 进行重打包、注入、修改字节码(注入工具仅限开发者自有 APK,详见 ADR 0068)
- ❌ **红方功能(自有 APK 诊断)仅限处理用户拥有合法著作权的自有 APK,三重校验强制不得跳过**(详见 ADR 0077):
  - 校验 1:包名白名单(APK 包名必须在 admin-web 注册)
  - 校验 2:签名 hash 比对(APK 签名必须与开发者配置的预期 hash 匹配)
  - 校验 3:本地私有目录隔离(/tmp/audit/<taskId>/,处理后立即删除)
  - 任一校验失败即拒绝,不提供跳过开关

**如果用户要求实现上述功能,立即拒绝并提醒红线。**

**例外(允许)**:
- ✅ 自有 APK 诊断(ADR 0077):仅限开发者拥有合法著作权的自有 APK,三重校验强制
- ✅ 开发者对自有应用做卡密验证、加固、防二次打包
- ✅ SDK 集成辅助工具(init 生成模板 + sign 签名加水印,详见 ADR 0068)
- ✅ **自有 APK 签名回填**(ADR 0077 例外 A,2026-07-20 修订):仅限 META-INF only + 自有 keystore + V1+V2+V3 + hash 入白名单,**禁止全量签名替换 / 通用签名剥离 / keystore 共享**
- ✅ **自有梆梆加固 APK 自检**(ADR 0077 例外 B + ADR 0078,2026-07-20 律师意见已落地,状态 accepted):仅限梆梆一家(锁 A)+ EULA 前置(锁 B)+ 仅完整性报告不输出源码(锁 C);V1.5 扩展至腾讯乐固(ADR 0082-B)+ 360 加固保(ADR 0082-A),爱加密 V2 评估(ADR 0082-C);其他加固厂商明确不支持;代码已开发完成并部署
- ✅ **腾讯乐固自检适配器**(ADR 0082-B,2026-07-21 合规核查已通过,状态 proposed):复用 ADR 0078 六锁架构;libshell.so 检测;EULA 核心条款"本人为 APK 著作权人,本次自检系对自有资产的安全审计";V1.5a 优先实现
- ✅ **360 加固保自检适配器**(ADR 0082-A,2026-07-21 合规核查已通过,状态 proposed):复用 ADR 0078 六锁架构;libjiagu.so 检测;360 EULA 第 4.1 条"本软件"指 360 加固助手本身,不指代开发者自有 APK;V1.5b 并行实现
- ✅ **自有 APK 的 xcj-auth-sdk 封装**(ADR 0077 例外 C + ADR 0081,2026-07-21 律师预审通过,状态 accepted):七锁架构(对象/内容/入口/签名/权限/数据/客户端签名自检);仅注入固定 classes-xcj.dex,**禁止扩展为自定义 smali 或非 SDK 注入**(红线,后续 PR 不准悄悄扩);Manifest 修改仅限 Application 委托;强制自备 Keystore V1+V2+V3 重签;**锁 7 客户端签名自检**(SDK 初始化时校验 APK 签名 hash,不一致拒启 PACKAGE_TAMPERED);会员获利规模控制在"情节不严重"档(< 5 万/年);风险熔断:若律师正式意见书驳回,回退 ADR 0080(源码级集成)

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
