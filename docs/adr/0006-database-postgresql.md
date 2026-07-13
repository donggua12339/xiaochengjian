# ADR 0006 · 数据库:PostgreSQL 16

- 状态:accepted
- 日期:2026-07-13
- 决策者:小城笺项目
- 层次:技术栈

## 背景

卡密验证系统需要存储开发者、应用、卡密、设备、日志等结构化数据,SaaS 多租户场景要求强隔离。

## 决策

### 数据库:PostgreSQL 16
- **多租户隔离**:RLS(Row Level Security)行级安全,数据库层强制
- **JSONB**:存卡密扩展属性、设备指纹元数据
- **分区表**:验证日志按月分区,提升查询性能
- **连接池**:PgBouncer
- **扩展**:`pgcrypto`(加密)、`pg_partman`(分区管理)

### 多租户策略
- **字段隔离**:`tenant_id` 列 + RLS 策略(非 schema 隔离、非库隔离)
- 所有业务表必须有 `tenant_id` 列
- RLS 策略强制:`current_setting('app.tenant_id') = tenant_id`
- NestJS 通过 `SET LOCAL app.tenant_id` 设置当前租户

### 关键表预览
- `developer`(开发者)
- `application`(应用)
- `card_key`(卡密,只存 hash)
- `device_binding`(设备绑定)
- `validation_log`(验证日志,分区表)
- `audit_log`(审计日志)

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| MySQL 8 | 生态主流 | 无 RLS、多租户靠应用层 | 隔离弱 |
| PostgreSQL 16(本方案) | RLS、JSONB、分区 | 运维复杂度略高 | 多租户必需 |
| MongoDB | 灵活 schema | 事务弱 | 卡密需要强一致 |

## 影响

- 正面:RLS 是多租户杀手级特性,数据库层强制隔离
- 负面:PostgreSQL 运维比 MySQL 略复杂,需培训
- 风险:RLS 策略 bug 会导致数据泄露,需严格测试

## 关联

- 关联 ADR:0005(NestJS)、0018(多租户)、0033(备份)
- 关联代码:`backend/prisma/schema.prisma`、`backend/prisma/migrations/`
