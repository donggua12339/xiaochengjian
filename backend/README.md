# 小城笺 · 后端(NestJS)

> NestJS + TypeScript strict + PostgreSQL 16 + Redis 7

## 范围

- 卡密核心(生成 / 激活 / 验证 / 禁用 / 解绑)
- 多租户隔离(RLS)
- 2FA / JWT 认证
- 限流 / 风控
- 审计日志
- 注入服务(SaaS 独占)

详见 [架构总览](../docs/architecture.md) 与 [ADR](../docs/adr/README.md)。

## 状态

- M0:文档骨架(当前)
- M1:核心 API + 多租户 + 2FA + 限流(待启动)

## 关键 ADR

- [ADR 0005 · 后端技术栈](../docs/adr/0005-backend-tech-stack.md)
- [ADR 0006 · PostgreSQL](../docs/adr/0006-database-postgresql.md)
- [ADR 0007 · Redis](../docs/adr/0007-cache-redis.md)
- [ADR 0018 · 多租户](../docs/adr/0018-multi-app-multi-tenant.md)
- [ADR 0027 · 服务端安全基线](../docs/adr/0027-server-security-baseline.md)
