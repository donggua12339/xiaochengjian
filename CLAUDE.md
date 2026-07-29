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

## 2. 核心红线(守城军规)

本工具为**纯防守向**项目,所有能力仅用于自有资产的防护、审计与加固,严禁任何进攻性、破坏性用途。以下为不可触碰的军规:

- **【守城军规Ⅰ】禁止通用脱壳**:不拆解任何第三方加固设施,仅对开发者明确授权的自有 APK 加固层做只读巡检,绝不破坏加固厂商的技术措施。
- **【守城军规Ⅱ】禁止非授权重打包**:不篡改自有资产外的任何 APK,仅对开发者授权的自有 APK 做合规封装,不产出可被滥用的修改产物。
- **【守城军规Ⅲ】禁止越界操作**:所有审计能力仅用于自有资产的安全排查,不对外提供任何可复用的逆向中间产物(如 dex/smali 源码)。
- **【守城军规Ⅳ】禁止伪装身份**:所有封装操作必须使用开发者自备的合法签名,绝不冒充任何第三方应用。

**如果用户要求实现上述功能,立即拒绝并提醒红线。**

**例外(蓝方-自有,需 ADR 合规闭环)**:

- ✅ 自有 APK 诊断(ADR 0077):仅限开发者拥有合法著作权的自有 APK,三重校验强制
- ✅ 开发者对自有应用做卡密验证、加固、防二次打包
- ✅ SDK 集成辅助工具(init 生成模板 + sign 签名加水印,详见 ADR 0068)
- ✅ **自有 APK 签名回填**(ADR 0077 例外 A,2026-07-20 修订):仅限 META-INF only + 自有 keystore + V1+V2+V3 + hash 入白名单,**禁止全量签名替换 / 通用签名剥离 / keystore 共享**
- ✅ **梆梆加固层自检适配器**(ADR 0078):仅限梆梆一家(锁 A)+ EULA 前置(锁 B)+ 仅完整性报告不输出源码(锁 C);V1.5 扩展至腾讯乐固(ADR 0082-B)+ 360 加固保(ADR 0082-A),爱加密 V2 评估(ADR 0082-C);其他加固厂商明确不支持
- ✅ **360 加固保自检适配器**(ADR 0082-A,合规核查已通过):libjiagu.so 检测;360 EULA 第 4.1 条"本软件"指加固助手本身,不指代开发者自有 APK
- ✅ **腾讯乐固自检适配器**(ADR 0082-B,合规风险极低):libshell.so 检测;协议环境宽松
- ✅ **加固 APK 受控封装工作流**(ADR 0083,仅限未加固 APK 预处理):先封装再加固,加固 APK 不进 Packer
- ✅ **加固 APK 边界分析**(ADR 0085,明确防御边界):形式化证明"加固 APK + SDK 注入"物理不可行,提供合规替代路径
- ✅ **上游封装 + 厂商加固串联**(ADR 0086,联防体系):Packer 输出 + 加固厂商 CLI 串联,构建双层防护
- ✅ **深度安全审计引擎**(ADR 0087,防御工事升级):隐私合规扫描 / 供应链投毒检测 / 攻击面枚举,全程只读
- ✅ **自有 APK 的 xcj-auth-sdk 封装**(ADR 0077 例外 C + ADR 0081,2026-07-21 律师预审通过,状态 accepted):七锁架构(对象/内容/入口/签名/权限/数据/客户端签名自检);仅注入固定 classes-xcj.dex,**禁止扩展为自定义 smali 或非 SDK 注入**(红线,后续 PR 不准悄悄扩);Manifest 修改仅限 Application 委托;强制自备 Keystore V1+V2+V3 重签;**锁 7 客户端签名自检**(SDK 初始化时校验 APK 签名 hash,不一致拒启 PACKAGE_TAMPERED);风险熔断:若律师正式意见书驳回,回退 ADR 0080(源码级集成)

## 3. 技术栈锁定

| 层          | 技术                        | 不可更改 |
| ----------- | --------------------------- | -------- |
| 后端        | NestJS + TypeScript(strict) | ✅       |
| 数据库      | PostgreSQL 16               | ✅       |
| 缓存        | Redis                       | ✅       |
| 后台        | Vue 3 + Naive UI            | ✅       |
| Android SDK | Kotlin + Rust(JNI)          | ✅       |
| 注入工具    | Kotlin + dexlib2            | ✅       |

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

### C / Native(defender-sdk)

- 格式化:`.clang-format`(基于 Google,4 空格缩进,100 列宽,Linux 大括号)
- 日志:统一用 `defender_log.h` 宏(`LOGI/LOGW/LOGE`),禁裸 `__android_log_print`
- LOGE 脱敏:禁在 LOGE 中打印预期值/实际值/路径/地址/关键词;用定长掩码或仅打前缀
- 关键词匹配:用最短不变前缀(`"frida-agent"` 而非 `"frida-agent-64.so"`)
- `/proc` 读取:禁假设固定大小,用分段读或 ≥300KB static buf
- 独立 .so 间通信:禁 `extern` 跨 .so 引用;用 setter 模式或 JNI_OnLoad `void* reserved` 传参
- ELF 操作:mprotect 临时 RW → 写 → 恢复 R;只擦 e_ident(16 字节),禁擦 64 字节
- 构建期密钥:禁明文出现在 .c/.h 源文件;用 CFF 碎片+运行时重建;`.gitignore` 必须挡 `x0_*.h`/`cff_params.h`
- DEX 写入:禁 dexlib2 3.0.7 的 DexWriter(debug_info string_id bug);用 2.x 或 binary patch
- smali 指令格式:`CONST_16`=21s,`MOVE_RESULT`=11x,`NEW_ARRAY`=22c,寄存器>15 用 3rc

### 异步任务模式(backend hardening)

- 耗时操作(分析/加固)**禁同步等待**;立即返回 `taskId`,后台 `async` 执行
- 进度回调:`ProgressCallback(step, progress, detail)` 每步更新
- 状态持久化:Redis `hardening:task:{id}` TTL 24h + 用户索引 `hardening:user_tasks:{devId}`
- 前端轮询:2-3s 间隔 `GET /status/:taskId`,组件 `onUnmounted` 清除 timer
- 刷新恢复:`GET /tasks` 返回用户全部任务,活跃任务自动续轮询

### API 设计规范(backend)

- 路由前缀:`/v1/{module}/{resource}`,模块名与 NestJS `@Controller` 对齐
- 文件上传:用 `@UseInterceptors(FileInterceptor('field'))`,禁手动解析 multipart
- 响应格式:分析/加固类返回 `{ taskId, status, progress, message, step, detail }`
- 错误码:用 `BadRequestException('ERROR_CODE', { cause: '...' })`,禁裸 500
- 审计日志:涉及合规操作(加固/签名/注入)必须 `logger.warn('[ADR-XXXX 审计] ...')` 记录

### Vue 组件规范(admin-web)

- 组合式 API:`<script setup lang="ts">`,禁 Options API
- UI 库:Naive UI 组件优先,禁混用其他 UI 库
- 状态:组件内 `ref/reactive`;跨组件 `Pinia store`;服务端状态 `API 调用 + ref`
- 文件上传:axios 传 FormData 时**禁手动设 Content-Type**(丢 boundary);拦截器自动检测 FormData 删除默认 `application/json`
- 轮询模式:`setInterval` + `onUnmounted` 清理;进度展示用 `NProgress` + 步骤图标
- 表单验证:提交前逐项校验,错误用 `message.error()`,禁 alert/confirm
- 路由:kebab-case path;PascalCase component name;侧边栏按功能分组

### 错误处理范式

- backend:Service 层 `throw BadRequestException/NotFoundException`,Controller 不 try-catch(全局 filter 处理)
- admin-web:API 调用 `try/catch`,catch 中 `message.error(e?.response?.data?.message || e.message)`
- native C:错误返回 `-1` 或 `NULL`,调用方检查;致命错误 `raise(SIGABRT); _exit(137)`
- 禁吞异常:catch 块必须有日志或 re-throw,禁空 catch

### 规约文件清单

| 文件                                     | 作用域   | 用途                            |
| ---------------------------------------- | -------- | ------------------------------- |
| `.editorconfig`                          | 全项目   | 缩进/编码/换行统一              |
| `backend/.eslintrc.cjs`                  | 后端     | TypeScript lint 规则            |
| `backend/.prettierrc`                    | 后端     | 代码格式化                      |
| `admin-web/.eslintrc.cjs`                | 前端     | Vue + TypeScript lint           |
| `admin-web/.prettierrc`                  | 前端     | 代码格式化                      |
| `sdk-android/defender-sdk/.clang-format` | Native C | C/C++ 格式化                    |
| `.husky/pre-commit`                      | Git      | 提交前 lint-staged + commitlint |
| `.lintstagedrc.cjs`                      | Git      | 暂存文件自动 lint               |
| `commitlint.config.cjs`                  | Git      | commit message 格式             |
| `spec.md`                                | 全项目   | 系统规格/模块边界/API 规格      |
| `plan.md`                                | 全项目   | 里程碑/技术债务/产品规划        |
| `tasks.md`                               | 全项目   | 任务看板(实时更新)              |
| `CHANGELOG.md`                           | 全项目   | 版本变更记录                    |

## 5. 测试要求

| 层                | 覆盖率 | 卡点  |
| ----------------- | ------ | ----- |
| Rust 核心安全模块 | ≥ 90%  | CI 卡 |
| NestJS 后端       | ≥ 80%  | CI 卡 |
| 集成测试关键路径  | 100%   | CI 卡 |
| Android SDK       | ≥ 70%  | 警告  |
| Vue 后台          | ≥ 60%  | 警告  |

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
