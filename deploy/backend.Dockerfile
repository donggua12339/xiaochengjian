# 小城笺后端 Docker 镜像(多阶段构建)
# 详见 ADR 0012 (Docker Compose + K8s 双模式)

# ---- 构建阶段 ----
FROM node:22-alpine AS builder
WORKDIR /app

# 安装 pnpm
RUN corepack enable && corepack prepare pnpm@9 --activate

# 复制 workspace 根(用于 pnpm workspace 解析)
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml ./
COPY backend/ ./backend/

# 安装依赖 + 构建(不用 frozen-lockfile,允许 lockfile 更新)
RUN cd backend && pnpm install --no-frozen-lockfile
RUN cd backend && pnpm prisma generate
RUN cd backend && pnpm nest build

# ---- 运行阶段 ----
FROM node:22-alpine AS runner
WORKDIR /app

RUN corepack enable && corepack prepare pnpm@9 --activate
RUN apk add --no-cache openssl wget

COPY pnpm-workspace.yaml package.json pnpm-lock.yaml ./
COPY backend/ ./backend/
# 重新安装(含 devDependencies,prisma CLI 需要)+ 生成 Prisma client
RUN cd backend && pnpm install --no-frozen-lockfile && pnpm prisma generate
# 复制构建产物
COPY --from=builder /app/backend/dist ./backend/dist

WORKDIR /app/backend

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:3000/health || exit 1

CMD ["sh", "-c", "pnpm prisma migrate deploy && node dist/main.js"]
