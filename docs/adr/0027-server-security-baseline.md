# ADR 0027 · 服务端安全基线

- 状态:accepted
- 日期:2026-07-13
- 决策者:小城笺项目
- 层次:安全

## 背景

开源版用户自己部署服务端,不能假设他们懂安全。需强制安全基线,避免开源版出事拖累品牌。

## 决策

### 强制安全基线(10 项)

| 项 | 必需 | 说明 |
|---|---|---|
| HTTPS 强制 | ✅ | 不允许 HTTP,启动检查 |
| 数据库密码强度 | ✅ | 启动时校验,弱密码拒绝启动 |
| 管理后台 2FA | ✅ | 开发者账号必须开 2FA(TOTP) |
| JWT 过期时间 | ✅ | access 15min + refresh 7day |
| SQL 注入防护 | ✅ | Prisma 参数化查询,禁字符串拼接 |
| XSS 防护 | ✅ | Vue 自动转义 + CSP 头 |
| CSRF 防护 | ✅ | SameSite Cookie + CSRF token |
| 速率限制 | ✅ | 见 ADR 0022 |
| 日志脱敏 | ✅ | 卡密只记 hash 前 4 位 |
| 备份加密 | ✅ | 数据库备份 AES 加密 |

### 启动检查机制
- NestJS 启动时跑 `SecurityCheckService`
- 逐项检查,不达标**拒绝启动**并提示修复方法
- **不提供跳过开关**(否则等于没检查)

### 开发模式豁免
- `NODE_ENV=development` 时跳过部分检查(密码强度、HTTPS)
- 生产模式强制全检
- 部署文档明确禁止生产用 dev 模式

### 2FA 实现
- TOTP(Time-based One-Time Password)
- 兼容 Google Authenticator / Microsoft Authenticator
- 备份码(10 个一次性使用)
- 首次登录强制开启

### JWT 设计
- **access token**:15 分钟过期,存内存
- **refresh token**:7 天过期,存 Redis(可撤销)
- **算法**:HS256
- **payload**:`{ developerId, tenantId, role, exp, iat }`
- **不存敏感信息**:邮箱/手机号不进 token

### 日志脱敏中间件
- 强制 `cardKey` 字段输出 `***`
- 强制 `password` 字段输出 `***`
- 强制 `secret` / `token` 字段输出 `***`
- 在 NestJS 全局拦截器实现

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| 全强制(本方案) | 安全 | 部署门槛高 | 合理 |
| 提供跳过开关 | 灵活 | 等于没检查 | 不安全 |
| 仅 SaaS 强制 | SaaS 安全 | 开源版出事拖累品牌 | 不可接受 |

## 影响

- 正面:开源版基线安全有保障
- 负面:部署门槛略高,需文档详细指导
- 风险:开发者可能用 dev 模式跑生产,需文档警告

## 关联

- 关联 ADR:0006(PostgreSQL)、0005(NestJS)、0018(多租户)
- 关联代码:`backend/src/security/security-check.service.ts`
