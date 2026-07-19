# 小城笺 · 部署指南

> 本文档是小城笺部署的**顶层入口**,整合各部署场景的详细文档。
> 详见 [ADR 0012](adr/0012-deployment-compose-k8s.md) · Docker Compose + K8s 双模式。

**最后更新**:2026-07-19

## 1. 部署形态选择

| 形态 | 编排 | 适用 | 文档 |
|---|---|---|---|
| 开源版自部署 | Docker Compose | 个人/小团队 | [deploy/README.md](../deploy/README.md) |
| SaaS MVP | Docker Compose 单机 | 用户 < 1000 | [deploy/SAAS-CHECKLIST.md](../deploy/SAAS-CHECKLIST.md) |
| SaaS 中规模 | K8s + PG 主从 | 用户 1000-10000 | 待补 Helm Chart |
| SaaS 大规模 | K8s 多区域 | 用户 > 10000 | 未来工作 |

详见 [ADR 0031](adr/0031-saas-deployment.md) · SaaS 部署架构(分阶段)。

## 2. 前置要求

| 项 | 开源版 | SaaS MVP |
|---|---|---|
| 服务器 | 1C2G(ADR 0046) | 1C2G 海外(ADR 0045/0046) |
| Docker | 24+ | 24+ |
| Docker Compose | v2+ | v2+ |
| 域名 | 可选(localhost 可用) | 必需(国内注册 + 海外服务器,ADR 0045) |
| HTTPS 证书 | 可选(自签) | 必需(Let's Encrypt 或 Cloudflare,ADR 0045) |
| 雨云账号 | 不需要 | 必需(ADR 0046) |

## 3. 快速开始(开源版自部署)

```bash
# 1. 克隆代码
git clone https://github.com/your-fork/xiaochengjian.git
cd xiaochengjian/deploy

# 2. 配置环境变量
cp .env.example .env
vi .env  # 必改:POSTGRES_PASSWORD / REDIS_PASSWORD / JWT_*_SECRET / GRAFANA_PASSWORD

# 3. 生成 RSA 密钥对(SDK 通信加密)
mkdir -p ../backend/keys
openssl genrsa -out ../backend/keys/private.pem 2048
openssl rsa -in ../backend/keys/private.pem -pubout -out ../backend/keys/public.pem

# 4. 启动
docker compose up -d

# 5. 验证
curl http://localhost/health
# 期望:{"status":"ok","db":"ok","timestamp":"..."}
```

详细步骤见 [deploy/README.md](../deploy/README.md)。

## 4. SaaS 上线(完整流程)

SaaS 上线涉及服务器购买 / 域名 / HTTPS / 发卡网 / 告警 / 备份等多个环节,详见:

**[deploy/SAAS-CHECKLIST.md](../deploy/SAAS-CHECKLIST.md)** - 完整上线检查清单

关键步骤:
1. 服务器(雨云 1C2G 海外,ADR 0046)
2. 域名(国内注册 + 海外服务器,ADR 0045)
3. RSA 密钥对(SDK 通信加密,ADR 0020)
4. JWT 密钥(32+ 字符,ADR 0027)
5. WM 发卡网(ADR 0044/0051)
6. 飞书告警 webhook(ADR 0032)
7. HTTPS 配置(Cloudflare + 通配符证书,见 deploy/HTTPS.md)
8. 管理员账号创建 + role=ADMIN
9. 首批会员激活码生成
10. 数据备份(crontab + pg_dump,见 deploy/backup/README.md)

## 5. 安全基线(ADR 0027,强制)

**生产环境必须满足以下 10 项安全基线,NestJS 启动时强制检查,不达标拒绝启动:**

| # | 项 | 要求 | 验证 |
|---|---|---|---|
| 1 | HTTPS 强制 | 不允许 HTTP | 启动检查,生产模式 HTTP 拒绝启动 |
| 2 | 数据库密码强度 | ≥ 12 字符 + 大小写 + 数字 + 特殊字符 | 启动校验,弱密码拒绝启动 |
| 3 | 管理后台 2FA | TOTP 强制开启 | 首次登录强制开启 |
| 4 | JWT 过期时间 | access 15min + refresh 7day | 配置固定,不可改 |
| 5 | SQL 注入防护 | Prisma 参数化查询 | 代码层强制 |
| 6 | XSS 防护 | Vue 自动转义 + CSP 头 | 框架保证 + nginx 配置 |
| 7 | CSRF 防护 | SameSite Cookie + CSRF token | 框架保证 |
| 8 | 速率限制 | IP 60/min + 设备 30/min | ADR 0022 |
| 9 | 日志脱敏 | cardKey/password/secret 强制 *** | 拦截器强制 |
| 10 | 备份加密 | gpg AES-256 | ADR 0072 |

**⚠️ 不提供跳过开关**(否则等于没检查)。

**开发模式豁免**:`NODE_ENV=development` 时跳过部分检查(密码强度、HTTPS),生产模式强制全检。**禁止生产用 dev 模式**。

## 6. 环境变量说明

详见 [deploy/.env.example](../deploy/.env.example),关键项:

| 变量 | 说明 | 示例 |
|---|---|---|
| `POSTGRES_USER` | PG 用户名 | `xcj_dba`(生产实际,模板默认 xcj_admin) |
| `POSTGRES_PASSWORD` | PG 密码(≥ 12 字符强密码) | `StrongPass!2026` |
| `POSTGRES_DB` | PG 数据库名 | `xiaochengjian` |
| `REDIS_PASSWORD` | Redis 密码 | `StrongRedisPass!` |
| `JWT_ACCESS_SECRET` | JWT access 密钥(32+ 字符) | `openssl rand -hex 32` |
| `JWT_REFRESH_SECRET` | JWT refresh 密钥(32+ 字符) | `openssl rand -hex 32` |
| `GRAFANA_PASSWORD` | Grafana 管理员密码 | `StrongGrafanaPass!` |
| `CORS_ORIGINS` | 允许的 CORS 源 | `https://your-domain.com` |
| `ADMIN_WEB_URL` | 管理后台 URL | `https://your-domain.com` |
| `FEISHU_WEBHOOK_URL` | 飞书告警 webhook | `https://open.feishu.cn/...` |

**⚠️ .env 文件权限必须 600**(P1.15 已修复服务器上的):

```bash
chmod 600 .env
```

## 7. 数据备份

详见 [ADR 0072](adr/0072-mvp-backup-simplified.md) + [deploy/backup/README.md](../deploy/backup/README.md)。

**MVP 方案:**

| 项 | 方案 |
|---|---|
| 频率 | 每日凌晨 3:00 CST 全量 pg_dump |
| 加密 | gpg AES-256 对称加密 |
| 保留 | 7 天滚动 |
| 存储 | 服务器本地 |

**部署步骤**见 `deploy/backup/README.md`,核心:

```bash
# 1. 生成密钥
openssl rand -base64 32 > /etc/xcj-backup.key  # 或 ~/.config/xcj-backup.key
chmod 600 /etc/xcj-backup.key

# 2. 配置
cp deploy/backup/backup.env.example /etc/xcj-backup.env  # 或 ~/.config/
chmod 600 /etc/xcj-backup.env
vi /etc/xcj-backup.env

# 3. 手动验证
deploy/backup/backup.sh
deploy/backup/restore-test.sh /path/to/backup.gpg

# 4. crontab
echo "0 3 * * * /path/to/backup.sh" | crontab -
```

## 8. 监控告警

详见 [ADR 0032](adr/0032-monitoring-logging.md)。

**监控栈:**

| 服务 | 端口 | 用途 |
|---|---|---|
| Prometheus | 9090 | 指标采集 |
| Grafana | 3001 | 仪表盘(账号 admin / GRAFANA_PASSWORD) |
| Loki | 3100 | 日志聚合 |
| Promtail | - | 日志收集(docker logs) |
| AlertManager | 9093 | 告警路由 |
| AlertManager-Feishu | 5000 | 飞书告警网关 |

**关键告警阈值(ADR 0032):**

- 验证失败率 > 5%
- PG 连接数 > 80%
- 磁盘 > 85%
- 卡密枚举告警(同 IP 1 分钟失败 > 20)
- Redis 内存 > 80%

## 9. HTTPS 配置

详见 [deploy/HTTPS.md](../deploy/HTTPS.md)。

**SaaS 生产方案(ADR 0045):**

```
用户 -> Cloudflare(*.winmelon.cn 通配符证书)-> 服务器:443
     -> 宿主机 nginx(/etc/nginx/sites-available/your-domain)
     -> 127.0.0.1:8088(xcj-nginx)
     -> xcj-backend:3000(API)或 xcj-admin-web:80(前端)
```

**开源版方案:** Let's Encrypt + certbot,见 deploy/HTTPS.md。

## 10. 服务器内存调优(ADR 0050)

雨云 1C2G 内存有限,需调优 PG + Redis:

| 服务 | 参数 | 值 | 默认值 |
|---|---|---|---|
| PG | shared_buffers | 128MB | 256MB |
| PG | effective_cache_size | 512MB | 4GB |
| Redis | maxmemory | 64MB | 无限 |
| Redis | maxmemory-policy | allkeys-lru | noeviction |

**内存预算(2G):**

| 组件 | 内存 |
|---|---|
| 系统 | 300MB |
| NestJS | 200MB |
| PG | 400MB |
| Redis | 100MB |
| Nginx | 20MB |
| 预留 | 980MB |

## 11. 常用运维命令

```bash
# 服务状态
docker compose ps

# 查看日志
docker compose logs -f backend
docker compose logs -f xcj-postgres

# 重启服务
docker compose restart backend

# 停止全部
docker compose down

# 重新构建(代码更新后)
git pull
docker compose up -d --build backend admin-web

# 进 PG
docker exec -it xcj-postgres psql -U xcj_dba xiaochengjian

# 进 Redis
docker exec -it xcj-redis redis-cli -a $REDIS_PASSWORD

# 健康检查
curl http://localhost/health
curl http://localhost:8088/health  # 走 xcj-nginx 反代
```

## 12. 故障排查

| 问题 | 排查 |
|---|---|
| backend 启动失败 | `docker compose logs backend` 看 Prisma 迁移错误 / 安全基线检查失败 |
| 健康检查 db: error | `docker compose ps` 检查 postgres 是否 healthy |
| 502 Bad Gateway | backend 未就绪,等 30 秒或查日志 |
| Grafana 无数据 | 检查 Prometheus targets http://localhost:9090/targets |
| promtail 不推日志 | `docker logs xcj-promtail` + 检查 loki:3100 可达 |
| OOM | 调低 PG shared_buffers(ADR 0050) |
| 磁盘满 | 清理 docker logs + 旧备份(`find /opt/xcj-backups -mtime +7 -delete`) |

## 13. 升级路径

详见 [ADR 0031](adr/0031-saas-deployment.md) 分阶段:

| 阶段 | 触发 | 升级内容 |
|---|---|---|
| MVP(当前) | - | 单机 Compose |
| 小规模 | 用户 > 200 | 2 台服务器 + PG 主从 |
| 中规模 | 用户 > 1000 | K8s + PG 主从 + Redis 哨兵 |
| 大规模 | 用户 > 10000 | K8s 多区域 + PG 分片 |

## 14. 关联文档

- [ADR 0012](adr/0012-deployment-compose-k8s.md) · Compose + K8s
- [ADR 0031](adr/0031-saas-deployment.md) · SaaS 部署架构
- [ADR 0032](adr/0032-monitoring-logging.md) · 监控告警
- [ADR 0033](adr/0033-backup-dr.md) · 备份灾备(理想方案)
- [ADR 0072](adr/0072-mvp-backup-simplified.md) · MVP 备份简化(实际落地)
- [ADR 0027](adr/0027-server-security-baseline.md) · 安全基线
- [ADR 0045](adr/0045-domain-overseas-server.md) · 域名 + 海外服务器
- [ADR 0046](adr/0046-server-rainyun-1c2g.md) · 雨云 1C2G
- [ADR 0050](adr/0050-server-memory-tuning.md) · 内存调优
- [deploy/README.md](../deploy/README.md) · 开源版部署详细
- [deploy/SAAS-CHECKLIST.md](../deploy/SAAS-CHECKLIST.md) · SaaS 上线检查清单
- [deploy/HTTPS.md](../deploy/HTTPS.md) · HTTPS 配置
- [deploy/backup/README.md](../deploy/backup/README.md) · 备份系统
