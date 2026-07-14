# 小城笺 · HTTPS 证书配置(Let's Encrypt + certbot 自动续期)

> 详见 ADR 0012(部署)

## 方式一:Docker Compose + Let's Encrypt(推荐,免费)

### 1. 准备域名

将域名 A 记录指向服务器 IP(如 `xcj.example.com -> 1.2.3.4`)。

### 2. 首次获取证书(standalone 模式)

```bash
# 临时停止 nginx(释放 80 端口)
docker compose stop nginx

# 用 certbot 获取证书
docker run --rm \
  -p 80:80 \
  -v $(pwd)/nginx/certs:/etc/letsencrypt \
  certbot/certbot certonly \
  --standalone \
  -d xcj.example.com \
  --email you@example.com \
  --agree-tos --no-eff-email

# 证书会生成在 nginx/certs/live/xcj.example.com/
```

### 3. 配置 Nginx 用证书

```bash
# 用 HTTPS 配置替换默认配置
cp nginx/nginx-https.conf nginx/nginx.conf

# 编辑 nginx.conf,确认证书路径:
#   ssl_certificate /etc/nginx/certs/live/xcj.example.com/fullchain.pem;
#   ssl_certificate_key /etc/nginx/certs/live/xcj.example.com/privkey.pem;
```

### 4. 启用 443 端口

编辑 `docker-compose.yml`,nginx 服务取消 443 端口注释:
```yaml
  nginx:
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/certs:/etc/nginx/certs:ro
```

### 5. 启动

```bash
docker compose up -d nginx
```

### 6. 自动续期(证书 90 天过期)

```bash
# 添加 cron 任务,每月 1 号自动续期
echo "0 3 1 * * docker run --rm -v $(pwd)/nginx/certs:/etc/letsencrypt certbot/certbot renew --quiet && docker compose restart nginx" | crontab -
```

## 方式二:自签证书(测试用)

```bash
mkdir -p nginx/certs
openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout nginx/certs/privkey.pem \
  -out nginx/certs/fullchain.pem \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=Xiaochengjian/CN=localhost"
```

## 方式三:云服务商免费证书

阿里云/腾讯云提供免费 DV 证书(1 年),下载后放到 `nginx/certs/`。

## 验证

```bash
# 健康检查(HTTPS)
curl https://xcj.example.com/health

# 证书信息
openssl s_client -connect xcj.example.com:443 -servername xcj.example.com < /dev/null 2>/dev/null | openssl x509 -noout -dates -issuer
```

## 故障排查

| 问题 | 排查 |
|---|---|
| 证书无效 | 检查域名解析 + 证书路径 |
| 80 端口被占 | certbot 需要 80 端口,先 `docker compose stop nginx` |
| 续期失败 | `certbot renew --dry-run` 测试 |
| HSTS 锁定 | 开发环境不要启用 HSTS(浏览器会强制 HTTPS) |
