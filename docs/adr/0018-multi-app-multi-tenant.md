# ADR 0018 · 多应用与多租户

- 状态:accepted
- 日期:2026-07-13
- 决策者:小城笺项目
- 层次:功能

## 背景

开发者通常有多个应用,需在同一账号下管理。SaaS 多租户需强制隔离。

## 决策

### 多应用支持
- **一账号多应用,独立卡密池**
- 每个应用独立的 `appId + appSecret`
- 卡密**不互通**(防滥用,不同应用价格/权益不同)
- SDK 初始化时传入 `appId + appSecret`

### 多租户隔离(SaaS)
- **租户 = 开发者账号**
- 所有业务表含 `tenant_id` 列
- **PostgreSQL RLS** 行级安全策略强制隔离
- RLS 策略:`current_setting('app.tenant_id') = tenant_id`
- NestJS 通过 `SET LOCAL app.tenant_id` 设置当前租户
- 跨租户查询必须显式 `USE ROLE superadmin` 并记录审计日志

### 多租户隔离层级
| 层 | 机制 |
|---|---|
| 数据库 | PostgreSQL RLS |
| 应用 | NestJS TenantContext + AOP 拦截器 |
| API | JWT 含 tenant_id,自动注入 |
| 缓存 | key 含 tenant_id 前缀 |
| 日志 | 强制含 tenant_id 字段 |

### 配额共享
- 多应用共享开发者账号配额
- VIP 等级、API 调用次数上限按账号计
- 单应用不可超账号总配额

### 开发者账号体系
- 邮箱注册 + 邮箱验证
- 2FA(TOTP)强制开启(ADR 0027)
- JWT access token(15min)+ refresh token(7day)
- 单账号最多 5 个应用(MVP 阶段限制,VIP 可解锁更多)

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| 一账号一应用 | 简单 | 多应用要注册多账号 | 体验差 |
| 一账号多应用独立池(本方案) | 灵活 | - | 合理 |
| 一账号多应用卡密互通 | 方便 | schema 复杂 | 场景少 |

## 影响

- 正面:开发者多应用统一管理,数据隔离严格
- 负面:RLS 策略 bug 会导致数据泄露,需严格测试
- 风险:跨租户查询审计日志必须完整

## 关联

- 关联 ADR:0006(PostgreSQL RLS)、0005(NestJS)、0027(安全基线)
- 关联代码:`backend/src/tenant/`、`backend/prisma/schema.prisma`
