# 小城笺 · Docker Compose 部署指南(开源版)

> 详见 ADR 0012(Docker Compose + K8s 双模式)

## 前置要求

- Docker 24+
- Docker Compose v2+
- 1 核 2G 内存(最小配置)

## 部署步骤

### 1. 准备配置

```bash
cd deploy
cp .env.example .env
# 编辑 .env,必须修改:
#   - POSTGRES_PASSWORD(数据库密码)
#   - REDIS_PASSWORD(Redis 密码)
#   - JWT_ACCESS_SECRET(32+ 字符随机串)
#   - JWT_REFRESH_SECRET(32+ 字符随机串)
#   - GRAFANA_PASSWORD(Grafana 管理员密码)
```

生成 JWT 密钥:
```bash
openssl rand -hex 32  # 生成 JWT_ACCESS_SECRET
openssl rand -hex 32  # 生成 JWT_REFRESH_SECRET
```

### 2. 生成 RSA 密钥对(SDK 通信加密用)

```bash
mkdir -p ../backend/keys
openssl genrsa -out ../backend/keys/private.pem 2048
openssl rsa -in ../backend/keys/private.pem -pubout -out ../backend/keys/public.pem
```

### 3. 启动服务

```bash
docker compose up -d
```

### 4. 验证

```bash
# 健康检查
curl http://localhost/health
# 期望:{"status":"ok","db":"ok","timestamp":"..."}

# API 文档:http://localhost/docs
# 管理后台:http://localhost
# Grafana:http://localhost:3001(账号 admin / .env 里的 GRAFANA_PASSWORD)
```

## 服务清单

| 服务 | 端口 | 用途 |
|---|---|---|
| nginx | 80 | 反向代理(API + 前端) |
| backend | 3000(内部) | NestJS API |
| admin-web | 80(内部) | Vue3 管理后台 |
| postgres | 5432(内部) | PostgreSQL 17 |
| redis | 6379(内部) | Redis 7 |
| prometheus | 9090 | 指标采集 |
| grafana | 3001 | 仪表盘 |
| loki | 3100 | 日志聚合 |

## 常用命令

```bash
docker compose logs -f backend      # 查看日志
docker compose restart backend      # 重启服务
docker compose down                 # 停止全部
docker compose down -v              # 停止并删除数据卷(数据丢失)
docker compose build --no-cache backend  # 重新构建镜像
```

## 数据备份

```bash
# PostgreSQL 备份
docker exec xcj-postgres pg_dump -U xcj_admin xiaochengjian > backup.sql

# PostgreSQL 恢复
docker exec -i xcj-postgres psql -U xcj_admin xiaochengjian < backup.sql
```

## HTTPS 配置(生产环境)

1. 将证书放到 `deploy/nginx/certs/`(fullchain.pem + privkey.pem)
2. 编辑 `deploy/nginx/nginx.conf`,启用 443 端口 server
3. 启用 docker-compose.yml 的 443 端口映射
4. `docker compose up -d nginx`

## 故障排查

| 问题 | 排查 |
|---|---|
| backend 启动失败 | `docker compose logs backend` 看 Prisma 迁移错误 |
| 健康检查 db: error | 检查 postgres 容器是否健康 |
| 502 Bad Gateway | backend 未就绪,等 30 秒或查日志 |
| Grafana 无数据 | 检查 Prometheus targets http://localhost:9090/targets |

## K8s 部署(SaaS 版)

SaaS 版用 Helm Chart 部署到 K8s,详见 `deploy/helm/`(后续补充)。

## 关键 ADR

- [ADR 0012 · Compose + K8s](../docs/adr/0012-deployment-compose-k8s.md)
- [ADR 0031 · SaaS 部署架构](../docs/adr/0031-saas-deployment.md)
- [ADR 0032 · 监控告警](../docs/adr/0032-monitoring-logging.md)
- [ADR 0033 · 备份灾备](../docs/adr/0033-backup-dr.md)
