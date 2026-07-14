# ADR 0050 · 服务器内存调优

- 状态:accepted
- 日期:2026-07-14
- 层次:运维

## 背景

雨云 1C2G(ADR 0046)内存有限,需调优 PG + Redis 参数防 OOM。

## 决策

**PostgreSQL + Redis 内存调优**

| 服务 | 参数 | 值 | 默认值 |
|---|---|---|---|
| PG | shared_buffers | 128MB | 256MB |
| PG | effective_cache_size | 512MB | 4GB |
| PG | work_mem | 4MB | 4MB |
| PG | maintenance_work_mem | 64MB | 64MB |
| Redis | maxmemory | 64MB | 无限 |
| Redis | maxmemory-policy | allkeys-lru | noeviction |

## 备选方案

| 方案 | PG shared_buffers | Redis maxmemory | 不选原因 |
|---|---|---|---|
| 默认 | 256MB | 无限 | 2G 内存会 OOM |
| 调优(本方案) | 128MB | 64MB | 合理 |
| 极限省内存 | 64MB | 32MB | 性能差 |

## 内存预算(2G)

| 组件 | 内存 |
|---|---|
| 系统 | 300MB |
| NestJS | 200MB |
| PG(shared_buffers=128MB + 连接 + 临时) | 400MB |
| Redis(maxmemory=64MB + 开销) | 100MB |
| Nginx | 20MB |
| 预留 | 980MB |

## 影响

- 正面:2G 内存稳定运行,无 OOM
- 负意:PG shared_buffers 小,查询性能略降(可接受)
- 监控:Prometheus 监控 PG/Redis 内存使用,>80% 报警

## 关联

- 关联 ADR:0046(服务器)、0032(监控)
