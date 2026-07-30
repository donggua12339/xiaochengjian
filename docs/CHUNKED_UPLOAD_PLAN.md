# 分片上传功能 — 实施计划 (Plan)

> 版本: 2026-07-31 | 方法论: TDD Red-Green-Refactor

## Phase 0: 基础设施

### Step 0.1: ChunkStorageService
- Redis 管理 upload 元数据 (uploadId → devId/fileName/fileSize/totalChunks/receivedChunks)
- 磁盘管理 tmp/chunks/{uploadId}/ 目录
- 方法: createUpload / receiveChunk / isComplete / mergeChunks / cleanup

## Phase 1: 后端 /upload/init (TDD)

### Step 1.1: 🔴 Red
- `chunked-upload.spec.ts`: init 成功 + init 超限 + init 无 auth

### Step 1.2: 🟢 Green
- controller 加 @Post('upload/init')
- 校验 fileSize ≤ 1GB → 400
- 创建目录 + Redis SET

### Step 1.3: ♻️ Refactor
- 提取 MAX_FILE_SIZE 常量

## Phase 2: 后端 /upload/chunk (TDD)

### Step 2.1: 🔴 Red
- chunk 成功 + chunk 幂等 + chunk 无效 uploadId + chunk 他人 uploadId

### Step 2.2: 🟢 Green
- controller 加 @Post('upload/chunk') + multer memoryStorage 6MB
- 写 .part 文件 + Redis 更新 receivedChunks

### Step 2.3: ♻️ Refactor

## Phase 3: 后端 /upload/complete (TDD)

### Step 3.1: 🔴 Red
- complete 成功 + complete 缺分片 + complete 非 APK

### Step 3.2: 🟢 Green
- controller 加 @Post('upload/complete')
- 拼接分片 + 校验大小 + magic bytes + Redis 注册 fileId + 清理

### Step 3.3: ♻️ Refactor

## Phase 4: 前端分片上传 (TDD)

### Step 4.1: 🔴 Red
- 预检 >1GB / 预检 ≤1GB / 进度计算 / 并发控制

### Step 4.2: 🟢 Green
- hardening.ts 新增 uploadInit / uploadChunk / uploadComplete
- HardenUpload.vue 加 filePrecheck + chunkedUpload 逻辑
- 进度条: 总进度 = (已完成片 × 5MB + 当前片进度) / 总大小

### Step 4.3: ♻️ Refactor
- 提取 ChunkUploader 类 (uploadId / queue / inFlight / progress)
- 断点续传: sessionStorage 存储

## Phase 5: 部署 + 验证

### Step 5.1: nginx 配置不变 (分片每片 5MB < 50MB 限制)
### Step 5.2: Docker build + deploy
### Step 5.3: 浏览器测试: 上传 200MB APK → 进度条平滑 → 分析 → 加固

## 依赖关系

```
Phase 0 → Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5
```

Phase 1-3 后端串行（complete 依赖 chunk，chunk 依赖 init）。
Phase 4 依赖 Phase 1-3 的 API 契约。
