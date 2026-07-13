# ADR 0012 · 部署:Docker Compose + K8s

- 状态:accepted
- 日期:2026-07-13
- 决策者:小城笺项目
- 层次:技术栈

## 背景

开源版用户自部署,SaaS 版需高可用。同一套镜像不同编排,降低维护成本。

## 决策

### 双模式部署
- **开源版**:Docker Compose(单机一键拉起)
- **SaaS 版**:Kubernetes(Helm Chart 部署)
- **同一套镜像**,不同编排

### Docker Compose 配置(开源版)
- `nginx`(反向代理 + HTTPS)
- `backend`(NestJS)
- `postgres:16`
- `redis:7`
- `prometheus` + `grafana` + `loki` + `promtail`(可选,默认启用)
- 所有配置走 `.env`,单机/集群切换不改代码

### K8s 配置(SaaS 版)
- Helm Chart
- Deployment(无状态 backend,HPA 自动扩缩)
- StatefulSet(PostgreSQL 主从)
- StatefulSet(Redis 哨兵)
- Ingress(nginx-ingress + cert-manager 自动 HTTPS)
- ConfigMap / Secret(配置分离)

### MVP 阶段
- 仅提供 Docker Compose
- K8s Helm Chart 放 M3 后

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| 裸机部署 | 简单 | 运维难 | 不现代化 |
| 仅 Compose | 简单 | SaaS 上量不够用 | 不支持扩展 |
| 仅 K8s | 强大 | 开源版用户门槛高 | 自部署难 |
| Compose + K8s(本方案) | 兼顾 | 双编排维护 | 合理 |

## 影响

- 正面:开源版易部署,SaaS 版可扩展
- 负面:需维护两套编排文件
- 风险:Compose 与 K8s 配置漂移,需 CI 校验

## 关联

- 关联 ADR:0031(SaaS 部署架构)、0034(CI/CD)
- 关联代码:`deploy/docker-compose.yml`、`deploy/helm/`
