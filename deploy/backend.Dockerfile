# 小城笺后端 Docker 镜像(多阶段构建)
# 详见 ADR 0012 (Docker Compose + K8s 双模式)

# ---- 构建阶段 ----
FROM node:22-alpine AS builder
WORKDIR /app

# 安装 pnpm
RUN corepack enable && corepack prepare pnpm@9 --activate

# 用淘宝 npm 镜像(海外服务器访问官方源慢)
RUN pnpm config set registry https://registry.npmmirror.com

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
RUN apk add --no-cache openssl wget unzip openjdk17-jre bash

# 安装 Android SDK build-tools(含 apksigner,ADR 0077 自有 APK 诊断用)
# 注:build-tools_r35 在 dl.google.com 上 404,用 r34(android-14)
# 注:apksigner 是 bash 脚本 wrapper,alpine 默认无 bash,需显式安装
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV ANDROID_HOME=/opt/android-sdk
ENV APKSIGNER_PATH=/opt/android-sdk/build-tools/34.0.0/apksigner
RUN mkdir -p /opt/android-sdk/build-tools && \
    wget -qO /tmp/build-tools.zip https://dl.google.com/android/repository/build-tools_r34-linux.zip && \
    unzip -q /tmp/build-tools.zip -d /tmp/bt && \
    mv /tmp/bt/android-14 /opt/android-sdk/build-tools/34.0.0 && \
    rm -rf /tmp/build-tools.zip /tmp/bt

# 安装 apktool(ADR 0088 Packer Manifest 修改用,H9 修复)
# apktool 用于反编译 APK -> 修改 AndroidManifest.xml -> 重打包
RUN mkdir -p /opt/apktool && \
    wget -qO /opt/apktool/apktool.jar https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar && \
    printf '#!/bin/sh\nexec java -jar /opt/apktool/apktool.jar "$@"\n' > /usr/local/bin/apktool && \
    chmod +x /usr/local/bin/apktool

# 用淘宝 npm 镜像(海外服务器访问官方源慢)
RUN pnpm config set registry https://registry.npmmirror.com

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
