# 小城笺 · 后端(NestJS)

> NestJS 10 + TypeScript 5 strict + PostgreSQL 16 + Redis 7 + Prisma 5

## M1.1 已实现

- [x] NestJS 项目骨架(tsconfig strict / ESLint / Prettier)
- [x] 配置管理(`@nestjs/config` + Joi 校验,生产环境强制安全基线)
- [x] Prisma schema(9 个表,见 `prisma/schema.prisma`)
- [x] 全局异常过滤器(统一错误响应,不泄露内部细节)
- [x] 请求日志拦截器(含 requestId)
- [x] 响应脱敏拦截器(cardKey/password/secret/token -> ***)
- [x] 健康检查(`GET /health`)
- [x] Swagger 文档(`GET /docs`,非生产环境)
- [x] API 前缀 `/v1`
- [x] CORS + Helmet + Cookie Parser
- [x] E2E 测试骨架

## 启动

### 1. 安装依赖

```bash
cd backend
pnpm install
```

### 2. 配置环境变量

```bash
cp .env.example .env
# 编辑 .env,修改 DATABASE_URL / JWT secrets
```

### 3. 生成 RSA 密钥对(SDK 通信加密用)

```bash
mkdir -p keys
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
```

### 4. 数据库迁移

```bash
pnpm prisma:generate
pnpm prisma:migrate
```

### 5. 启动

```bash
pnpm start:dev
```

访问:
- API: http://localhost:3000/v1
- 健康检查: http://localhost:3000/health
- Swagger: http://localhost:3000/docs

## 测试

```bash
pnpm test         # 单测
pnpm test:cov     # 覆盖率
pnpm test:e2e     # E2E
```

## 关键文件

| 文件 | 说明 |
|---|---|
| `src/main.ts` | 应用入口 |
| `src/app.module.ts` | 根模块 |
| `src/config/configuration.ts` | 配置校验(生产环境安全基线) |
| `src/prisma/prisma.service.ts` | Prisma 客户端 |
| `src/common/filters/all-exceptions.filter.ts` | 全局异常过滤器 |
| `src/common/interceptors/logging.interceptor.ts` | 请求日志 |
| `src/common/interceptors/desensitize.interceptor.ts` | 响应脱敏 |
| `src/common/dto/pagination.dto.ts` | 分页 DTO |
| `src/health/health.controller.ts` | 健康检查 |
| `prisma/schema.prisma` | 数据模型 |

## 后续里程碑

- M1.2 认证模块(注册/登录/JWT/2FA)
- M1.3 多租户 RLS + 安全基线检查
- M1.4 应用模块
- M1.5 卡密核心
- M1.6 设备模块
- M1.7 统计模块
- M1.8 SDK 接口 + 签名
- M1.9 限流 + 审计
- M1.10 Vue3 后台
- M1.11 测试
- M1.12 联调 + 验收

## 关键 ADR

- [ADR 0005 · NestJS](../docs/adr/0005-backend-tech-stack.md)
- [ADR 0006 · PostgreSQL](../docs/adr/0006-database-postgresql.md)
- [ADR 0007 · Redis](../docs/adr/0007-cache-redis.md)
- [ADR 0018 · 多租户](../docs/adr/0018-multi-app-multi-tenant.md)
- [ADR 0027 · 服务端安全基线](../docs/adr/0027-server-security-baseline.md)
