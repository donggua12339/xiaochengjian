# ADR 0046 · 服务器选型:雨云 1C2G

- 状态:accepted
- 日期:2026-07-14
- 层次:运维

## 背景

SaaS 需要跑 NestJS + PostgreSQL + Redis + Nginx,预算 ¥50-80/月。

## 决策

**雨云 1C2G,¥80/月,调优 PG 内存**

- 配置:1C2G,海外节点
- PG 调优:shared_buffers=128MB(默认 256MB)
- Redis 调优:maxmemory=64MB
- 上量后(>50 租户)升 2C4G

## 备选方案

| 方案 | 配置 | 月费 | 不选原因 |
|---|---|---|---|
| 雨云 1C1G | 1G | ¥30-50 | 跑不动(PG OOM) |
| 雨云 1C2G(本方案) | 2G | ¥80 | 合理 |
| 阿里云 ECS | 2C4G | ¥150+ | 超预算 |
| 1C1G + SQLite | 1G | ¥50 | 失去 RLS |

## 内存预算(2G)

| 服务 | 内存 |
|---|---|
| NestJS | 200MB |
| PostgreSQL(shared_buffers=128MB) | 300MB |
| Redis(maxmemory=64MB) | 100MB |
| Nginx | 20MB |
| 系统 | 300MB |
| 预留 | 1080MB |

## 影响

- 正面:¥80/月可控,2G 内存够跑
- 负面:1C CPU 上量后瓶颈
- 风险:PG 调优不当会 OOM,需监控

## 关联

- 关联 ADR:0045(海外服务器)、0048(SLA)
