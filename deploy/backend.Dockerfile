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

# 安装依赖 + 构建
RUN cd backend && pnpm install --frozen-lockfile
RUN cd backend && pnpm prisma generate
RUN cd backend && pnpm nest build

# ---- 运行阶段 ----
FROM node:22-alpine AS runner
WORKDIR /app

RUN corepack enable && corepack prepare pnpm@9 --activate
RUN apk add --no-cache openssl wget

COPY pnpm-workspace.yaml package.json pnpm-lock.yaml ./
COPY backend/package.json ./backend/
COPY --from=builder /app/backend/node_modules ./backend/node_modules
COPY --from=builder /app/backend/dist ./backend/dist
COPY --from=builder /app/backend/prisma ./backend/prisma

WORKDIR /app/backend

EXPOSE 3000

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:3000/health || exit 1

# 启动命令(prisma migrate deploy + start)
CMD ["sh", "-c", "pnpm prisma migrate deploy && node dist/main.js"]
