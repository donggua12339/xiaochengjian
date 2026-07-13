# 小城笺 · 部署

> Docker Compose(开源版)/ K8s Helm(SaaS 版),同一套镜像不同编排

## 范围

- `docker-compose.yml`:开源版一键部署
- `helm/`:SaaS 版 K8s 编排
- `backup/`:备份脚本
- `monitoring/`:Prometheus + Grafana + Loki 配置

## 状态

- M0:文档骨架(当前)
- M3:与注入工具并行(待启动)

## 关键 ADR

- [ADR 0012 · Compose + K8s](../docs/adr/0012-deployment-compose-k8s.md)
- [ADR 0031 · SaaS 部署架构](../docs/adr/0031-saas-deployment.md)
- [ADR 0032 · 监控告警](../docs/adr/0032-monitoring-logging.md)
- [ADR 0033 · 备份灾备](../docs/adr/0033-backup-dr.md)
