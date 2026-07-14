#!/bin/bash
# 小城笺 SaaS 一键部署脚本
# 详见 ADR 0046(雨云 1C2G)+ deploy/SAAS-CHECKLIST.md
#
# 用法:SSH 连接服务器后,以 root 运行:
#   curl -fsSL https://raw.githubusercontent.com/donggua12339/xiaochengjian/main/deploy/saas-deploy.sh | bash
#
# 或下载后运行:
#   wget https://raw.githubusercontent.com/donggua12339/xiaochengjian/main/deploy/saas-deploy.sh
#   bash saas-deploy.sh

set -e

echo "=========================================="
echo "小城笺 SaaS 一键部署"
echo "=========================================="

# 1. 检查 root
if [ "$EUID" -ne 0 ]; then
  echo "❌ 请用 root 运行:sudo bash saas-deploy.sh"
  exit 1
fi

# 2. 装 Docker
echo "[1/6] 检查 Docker..."
if ! command -v docker &> /dev/null; then
  echo "  安装 Docker..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
  echo "  ✅ Docker 已安装"
else
  echo "  ✅ Docker 已存在:$(docker --version)"
fi

# 3. clone 仓库
echo "[2/6] 克隆代码..."
if [ -d /opt/xiaochengjian ]; then
  echo "  /opt/xiaochengjian 已存在,跳过 clone"
  cd /opt/xiaochengjian
  git pull --rebase || true
else
  git clone https://github.com/donggua12339/xiaochengjian.git /opt/xiaochengjian
  cd /opt/xiaochengjian
  echo "  ✅ 代码已克隆"
fi

# 4. 配置环境变量
echo "[3/6] 配置环境变量..."
cd /opt/xiaochengjian/deploy
if [ ! -f .env ]; then
  cp .env.example .env

  # 生成随机密码 + JWT 密钥
  PG_PASS=$(openssl rand -hex 16)
  REDIS_PASS=$(openssl rand -hex 16)
  JWT_ACCESS=$(openssl rand -hex 32)
  JWT_REFRESH=$(openssl rand -hex 32)
  GRAFANA_PASS=$(openssl rand -hex 8)

  sed -i "s|POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$PG_PASS|" .env
  sed -i "s|REDIS_PASSWORD=.*|REDIS_PASSWORD=$REDIS_PASS|" .env
  sed -i "s|JWT_ACCESS_SECRET=.*|JWT_ACCESS_SECRET=$JWT_ACCESS|" .env
  sed -i "s|JWT_REFRESH_SECRET=.*|JWT_REFRESH_SECRET=$JWT_REFRESH|" .env
  sed -i "s|GRAFANA_PASSWORD=.*|GRAFANA_PASSWORD=$GRAFANA_PASS|" .env

  echo "  ✅ .env 已生成(密码已随机化)"
  echo "  ⚠️  请记录以下密码(后续需要):"
  echo "     PostgreSQL: $PG_PASS"
  echo "     Redis: $REDIS_PASS"
  echo "     Grafana: $GRAFANA_PASS"
  echo "  ⚠️  请编辑 .env 修改 CORS_ORIGINS 为你的域名"
else
  echo "  .env 已存在,跳过"
fi

# 5. 生成 RSA 密钥
echo "[4/6] 生成 RSA 密钥..."
if [ ! -f /opt/xiaochengjian/backend/keys/private.pem ]; then
  mkdir -p /opt/xiaochengjian/backend/keys
  openssl genrsa -out /opt/xiaochengjian/backend/keys/private.pem 2048 2>/dev/null
  openssl rsa -in /opt/xiaochengjian/backend/keys/private.pem -pubout -out /opt/xiaochengjian/backend/keys/public.pem 2>/dev/null
  echo "  ✅ RSA 密钥已生成"
else
  echo "  RSA 密钥已存在,跳过"
fi

# 6. 启动 Docker Compose
echo "[5/6] 构建 + 启动 Docker Compose..."
docker compose up -d --build
echo "  ✅ 服务已启动"

# 等待健康检查
echo "[6/6] 等待服务就绪(60 秒)..."
sleep 60

# 验证
echo ""
echo "=========================================="
echo "部署完成!验证:"
echo "=========================================="

HEALTH=$(curl -s http://localhost/health 2>/dev/null || echo "FAILED")
echo "健康检查: $HEALTH"

if echo "$HEALTH" | grep -q '"status":"ok"'; then
  echo "✅ 服务正常运行!"
else
  echo "⚠️  服务可能未就绪,等 30 秒后重试:"
  echo "   curl http://localhost/health"
  echo ""
  echo "查看日志:"
  echo "   cd /opt/xiaochengjian/deploy && docker compose logs -f backend"
fi

echo ""
echo "=========================================="
echo "访问地址:"
echo "=========================================="
echo "API:        http://$(curl -s ifconfig.me):3000/v1"
echo "健康检查:   http://$(curl -s ifconfig.me)/health"
echo "Swagger:    http://$(curl -s ifconfig.me)/docs"
echo "管理后台:   http://$(curl -s ifconfig.me)/"
echo "Grafana:    http://$(curl -s ifconfig.me):3001"
echo ""
echo "下一步:"
echo "1. 浏览器打开 http://服务器IP/ 注册管理员账号"
echo "2. 把管理员 role 改为 ADMIN:"
echo "   docker exec xcj-postgres psql -U xcj_admin xiaochengjian -c \"UPDATE developer SET role='ADMIN' WHERE email='你的邮箱';\""
echo "3. 用管理员生成会员激活码,在发卡网售卖"
echo "=========================================="
