# ADR 0005 · 后端技术栈:NestJS

- 状态:accepted
- 日期:2026-07-13
- 决策者:小城笺项目
- 层次:技术栈

## 背景

后端需要支撑多租户、高并发验证请求、复杂权限、审计日志。可选 Spring Boot / Go / Node.js / Rust 等。

## 决策

### 后端技术栈
- **语言**:Node.js 20 + TypeScript 5(strict 模式)
- **框架**:NestJS 10
- **ORM**:Prisma 5(类型安全、迁移工具强)
- **API 文档**:OpenAPI 3.0 via `@nestjs/swagger`
- **验证**:class-validator + class-transformer
- **日志**:NestJS 内置 Logger(结构化 JSON)
- **测试**:Jest

### 关键约束
- `strict: true`、`noImplicitAny: true`、`strictNullChecks: true`
- 禁 `any`、禁 `console.log`(用 Logger)、禁 `@ts-ignore`
- 所有 API 必须有 OpenAPI 注解
- 多租户用 `TenantContext` + AOP 拦截器自动注入

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| Spring Boot 3 | 生态最全、参考项目多 | 启动慢、JAR 部署重 | 用户选 NestJS |
| Go + Gin | 单二进制、并发强 | 参考项目少、需造轮子 | 用户选 NestJS |
| NestJS(本方案) | TS 贯通前后端、开发快 | CPU 密集弱 | 用户选择 |
| Rust + Axum | 性能最强 | 学习曲线高 | 招人难 |

用户在 grill-me 中明确选择 NestJS,理由是 TS 前后端贯通、开发效率高。

## 影响

- 正面:前后端类型可共享(`shared-types` 包),Vue 与 NestJS 接口契约一致
- 负面:Node.js 单线程,CPU 密集场景(如加密)需用 worker thread
- 风险:NestJS 生态比 Spring 弱,部分场景需自己实现

## 关联

- 关联 ADR:0006(PostgreSQL)、0007(Redis)、0036(Monorepo)
- 关联代码:`backend/`
