# 小城笺 · SaaS 上线检查清单

> 详见 ADR 0040-0052(SaaS 上线决策)+ ADR 0044(发卡网)

## 上线前准备(用户操作)

### 1. 服务器(雨云)

- [ ] 注册雨云账号 https://www.rainyun.com
- [ ] 购买 1C2G 海外服务器(¥80/月,ADR 0046)
- [ ] 记录服务器 IP / SSH 密码
- [ ] 安全组开放端口:80 / 443 / 22

### 2. 域名

- [ ] 注册域名(国内注册商,.com,¥50-80/年)
- [ ] 域名解析 A 记录指向服务器 IP
- [ ] 等待 DNS 生效(10 分钟 - 24 小时)

### 3. RSA 密钥对(SDK 通信加密)

```bash
mkdir -p backend/keys
openssl genrsa -out backend/keys/private.pem 2048
openssl rsa -in backend/keys/private.pem -pubout -out backend/keys/public.pem
```

### 4. JWT 密钥

```bash
openssl rand -hex 32  # JWT_ACCESS_SECRET
openssl rand -hex 32  # JWT_REFRESH_SECRET
```

### 5. WM 发卡网(ADR 0044/0051)

- [ ] WM 发卡网部署(如可用)
- [ ] 配置商品:基础版月度 ¥18 / VIP 月度 ¥68 / VIP 终身 ¥128
- [ ] 自动发货:激活码(从会员激活码生成接口拉取)
- [ ] 兜底方案:个人微信/支付宝收款码 + 手动开通

### 6. 飞书告警 webhook(ADR 0032)

- [ ] 飞书群创建自定义机器人
- [ ] 复制 webhook URL
- [ ] 填入 deploy/.env 的 FEISHU_WEBHOOK_URL

---

## 部署步骤(服务器端执行)

### 1. SSH 登录服务器

```bash
ssh root@your-server-ip
```

### 2. 安装 Docker + Docker Compose

```bash
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker
docker --version  # 验证
```

### 3. 克隆代码

```bash
git clone https://github.com/your-username/xiaochengjian.git
cd xiaochengjian/deploy
```

### 4. 配置环境变量

```bash
cp .env.example .env
vi .env
# 必须修改:
#   POSTGRES_PASSWORD=强密码
#   REDIS_PASSWORD=强密码
#   JWT_ACCESS_SECRET=步骤4生成的
#   JWT_REFRESH_SECRET=步骤4生成的
#   GRAFANA_PASSWORD=强密码
#   FEISHU_WEBHOOK_URL=步骤6的 webhook
#   CORS_ORIGINS=https://your-domain.com
#   ADMIN_WEB_URL=https://your-domain.com
```

### 5. 复制 RSA 密钥

```bash
# 把步骤3生成的 keys/ 上传到服务器
scp -r backend/keys root@your-server-ip:~/xiaochengjian/backend/
```

### 6. 启动服务

```bash
docker compose up -d
# 等待 2-3 分钟(首次构建镜像)
docker compose ps  # 所有服务应 Up + healthy
```

### 7. 验证

```bash
# 健康检查
curl http://localhost/health
# 期望:{"status":"ok","db":"ok"}

# API 文档
# 浏览器:http://your-domain.com/docs

# 管理后台
# 浏览器:http://your-domain.com
```

### 8. HTTPS 配置(ADR 迭代4)

```bash
# 参考 deploy/HTTPS.md
# 用 Let's Encrypt + certbot
docker compose stop nginx
docker run --rm -p 80:80 -v $(pwd)/nginx/certs:/etc/letsencrypt certbot/certbot certonly --standalone -d your-domain.com --email you@example.com --agree-tos --no-eff-email
cp nginx/nginx-https.conf nginx/nginx.conf
# 编辑 nginx.conf 确认证书路径
# docker-compose.yml 取消 443 端口注释
docker compose up -d nginx
```

### 9. 创建管理员账号

```bash
# 注册第一个开发者(通过 API)
curl -X POST https://your-domain.com/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@your-domain.com","password":"StrongPassword123"}'

# 登录获取 token
# 在数据库把 role 改为 ADMIN:
docker exec -it xcj-postgres psql -U xcj_admin xiaochengjian -c "UPDATE developer SET role='ADMIN' WHERE email='admin@your-domain.com';"
```

### 10. 生成首批会员激活码(测试)

```bash
# 用管理员 token 生成 10 个 VIP 月度激活码
curl -X POST https://your-domain.com/v1/admin/membership-codes/generate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"level":"VIP","durationDays":30,"count":10,"remark":"首批测试"}'
# 保存返回的 codes,用于 WM 发卡网测试
```

---

## 上线后监控

### 1. Grafana 仪表盘

- 访问 http://your-domain.com:3001(账号 admin / .env 的 GRAFANA_PASSWORD)
- 数据源已自动 provisioning(Prometheus + Loki)
- 查看后端 QPS / 错误率 / PG 连接数

### 2. 飞书告警

- 测试告警:手动停 backend,1 分钟后应收到飞书告警
- 恢复后应收到"告警已恢复"卡片

### 3. 日志

```bash
# 实时日志
docker compose logs -f backend

# Loki 查询( Grafana)
# {container="xcj-backend"} |= "ERROR"
```

### 4. 数据备份

```bash
# 每日自动备份(cron)
echo "0 3 * * * docker exec xcj-postgres pg_dump -U xcj_admin xiaochengjian | gzip > /backup/xcj-$(date +\%Y\%m\%d).sql.gz" | crontab -

# 备份保留 7 天
find /backup -name "xcj-*.sql.gz" -mtime +7 -delete
```

---

## 紧急处理

### 服务不可用

```bash
docker compose ps  # 查看哪个服务挂了
docker compose logs backend  # 看后端日志
docker compose restart backend  # 重启
```

### 数据库 OOM

```bash
# PG OOM:调低 shared_buffers
vi .env  # 加 PG_SHARED_BUFFERS=128MB
docker compose down postgres
docker compose up -d postgres
```

### 被攻击(卡密枚举)

```bash
# 查看限流日志
docker compose logs backend | grep "RATE_LIMIT"
# 封 IP(nginx)
vi nginx/nginx.conf  # 加 deny x.x.x.x
docker compose restart nginx
```

---

## 检查清单(上线前最终确认)

- [ ] 服务器 1C2G 已购买
- [ ] 域名解析已生效
- [ ] RSA 密钥已上传
- [ ] .env 所有密码已改(非默认值)
- [ ] JWT 密钥 32+ 字符
- [ ] docker compose ps 全部 healthy
- [ ] /health 返回 db: ok
- [ ] HTTPS 证书有效
- [ ] 管理员账号已创建 + role=ADMIN
- [ ] 首批激活码已生成
- [ ] WM 发卡网已配置(或手动兜底就绪)
- [ ] 飞书告警已测试
- [ ] 数据备份 cron 已配置

全部 ✅ 后,SaaS 正式上线。
