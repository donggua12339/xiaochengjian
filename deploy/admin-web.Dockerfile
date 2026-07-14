# 小城笺管理后台 Docker 镜像(多阶段构建)
# 详见 ADR 0012

# ---- 构建阶段 ----
FROM node:22-alpine AS builder
WORKDIR /app

RUN corepack enable && corepack prepare pnpm@9 --activate

COPY pnpm-workspace.yaml package.json pnpm-lock.yaml ./
COPY admin-web/ ./admin-web/

RUN cd admin-web && pnpm install --frozen-lockfile
RUN cd admin-web && pnpm build

# ---- 运行阶段(Nginx 托管静态文件) ----
FROM nginx:alpine AS runner
COPY --from=builder /app/admin-web/dist /usr/share/nginx/html
COPY deploy/admin-web.nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
