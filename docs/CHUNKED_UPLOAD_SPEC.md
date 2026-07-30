# 分片上传功能 — 规格说明 (Spec)

> 版本: 2026-07-31 | 状态: 已审批 | 决策来源: grill-me 4 轮拷问

## 1. 问题陈述

上传 >50MB APK 时进度条卡住。根因链：
1. 主机 nginx `client_max_body_size 50m` → 超过 50MB 时中途切断连接
2. axios `onUploadProgress` 在某个百分比突然停止
3. nginx 切断后可能不发 413 响应 → axios Promise 挂起
4. 前端进度条冻住，无错误提示

## 2. 目标

| # | 目标 | 验收标准 |
|---|------|---------|
| G1 | 支持 ≤1GB APK 上传 | 200MB APK 能完整上传+分析 |
| G2 | >1GB 友好拒绝 | 选文件后立即提示，不发请求 |
| G3 | 上传进度实时 | 总进度 = (已完成片×5MB + 当前片进度) / 总大小 × 100 |
| G4 | 断点续传 | 网络断开后重连，从 lastChunkIndex 续传 |
| G5 | 无卡死 | 任何阶段失败都显示红色 Alert + 重试按钮 |
| G6 | 3 并发 | 同时最多 3 片上传，峰值内存 15MB |
| G7 | 服务端拼接 | complete 时拼接临时文件 + magic bytes 校验 + Redis 注册 |

## 3. API 规格

### 3.1 新端点

```
POST /v1/hardening/upload/init
  Content-Type: application/json
  Body: { fileName: string, fileSize: number, totalChunks: number }
  Auth: JWT
  Response: { uploadId: string, chunkSize: number }
  校验: fileSize > 1GB → 400 "APK 体积过大(上限 1GB)"

POST /v1/hardening/upload/chunk
  Content-Type: multipart/form-data
  Body: uploadId (string) + chunkIndex (string) + chunk (file, max 6MB)
  Auth: JWT
  Response: { received: true, chunkIndex: number }
  校验: chunkIndex 重复 → 200 幂等返回

POST /v1/hardening/upload/complete
  Content-Type: application/json
  Body: { uploadId: string }
  Auth: JWT
  Response: { fileId: string, fileName: string, fileSize: number }
  行为: 拼接所有分片 → 校验大小 → magic bytes 校验 → Redis 注册 → 清理分片
```

### 3.2 保留端点

```
POST /v1/hardening/upload    → 保留，用于 <10MB 小文件直接上传(可选优化)
POST /v1/hardening/analyze   → 不变，接收 fileId
POST /v1/hardening/harden    → 不变
GET  /v1/hardening/status/*  → 不变
GET  /v1/hardening/tasks     → 不变
GET  /v1/hardening/download/* → 不变
```

### 3.3 Redis 数据结构

```
hardening:upload:{uploadId}  →  { devId, fileName, fileSize, totalChunks, receivedChunks: number[], createdAt }  TTL=3600s
hardening:file:{fileId}      →  不变  TTL=1800s
```

### 3.4 分片临时文件

```
tmp/chunks/{uploadId}/{chunkIndex}.part   → 每个分片一个文件
complete 后拼接为 tmp/hardening/{devId}/{fileId}_{fileName}
拼接完成后删除 tmp/chunks/{uploadId}/ 目录
```

## 4. 前端规格

### 4.1 文件预检

选择文件后立即检查：
- `file.size > 1GB` → NAlert error "APK 体积过大(上限 1GB)，请压缩资源后重试"
- `file.size <= 1GB` → 进入分片上传流程

### 4.2 分片上传逻辑

```typescript
const CHUNK_SIZE = 5 * 1024 * 1024; // 5MB
const MAX_CONCURRENT = 3;
const MAX_FILE_SIZE = 1024 * 1024 * 1024; // 1GB

// 1. init
const { uploadId } = await uploadInit(file.name, file.size, totalChunks);

// 2. 并发上传分片(滑动窗口 3)
const queue = chunkIndices; // [0, 1, 2, ..., N-1]
let completed = 0;
// 滑动窗口: 同时最多 3 个 in-flight
while (queue.length > 0 || inFlight > 0) {
  while (inFlight < MAX_CONCURRENT && queue.length > 0) {
    const idx = queue.shift()!;
    inFlight++;
    uploadChunk(uploadId, idx, file.slice(idx*CHUNK_SIZE, (idx+1)*CHUNK_SIZE))
      .then(() => { completed++; updateProgress(completed, totalChunks, ...); inFlight--; })
      .catch(() => { /* 记录失败片, 重试 */ });
  }
  await sleep(50); // 让出事件循环
}

// 3. complete
const { fileId } = await uploadComplete(uploadId);
```

### 4.3 进度计算

```
总进度 = (已完成片数 × CHUNK_SIZE + 当前在传片的 onUploadProgress 字节) / fileSize × 100
```

### 4.4 断点续传

- 上传中断时保存 `{ uploadId, completedChunks: number[] }` 到 sessionStorage
- 页面恢复时检查 sessionStorage，如果有未完成上传 → 提示"检测到未完成的上传，是否继续？"
- 继续 → 跳过已完成片，从断点续传
- 取消 → 调后端清理接口(或等 TTL 过期)

### 4.5 错误处理

- 单片上传失败 → 自动重试 3 次，间隔 1s/2s/4s
- 3 次都失败 → 暂停所有上传 → 显示红色 Alert "第 N 片上传失败，点击重试"
- 用户点重试 → 从失败片继续
- init 失败 → 直接显示错误
- complete 失败 → 显示错误 + "分片已保存，可稍后重试"

## 5. 后端规格

### 5.1 init 端点

- 校验 fileSize ≤ 1GB
- 生成 uploadId (UUID)
- 创建 `tmp/chunks/{uploadId}/` 目录
- Redis SET upload 元数据 TTL 3600s
- 返回 `{ uploadId, chunkSize: 5242880 }`

### 5.2 chunk 端点

- multer memoryStorage, fileSize 限制 6MB (5MB + 余量)
- 校验 uploadId 存在 + devId 匹配
- 校验 chunkIndex < totalChunks
- 写 `tmp/chunks/{uploadId}/{chunkIndex}.part`
- Redis 更新 receivedChunks 数组
- 幂等: 已收到的 chunkIndex 直接返回 200

### 5.3 complete 端点

- 校验 uploadId 存在 + 所有分片已收到
- 按 chunkIndex 顺序拼接 → `tmp/hardening/{devId}/{fileId}_{fileName}`
- 校验拼接后大小 == fileSize
- Magic bytes 校验 (PK\x03\x04)
- Redis 注册 fileId (同 FileStorageService.save)
- 删除 `tmp/chunks/{uploadId}/` 目录
- 删除 Redis upload key
- 返回 `{ fileId, fileName, fileSize }`

### 5.4 MulterExceptionFilter

已有，不变。chunk 端点的 multer 限制是 6MB，超了返回 413。

## 6. 不做的事

- 不做服务端分片合并的流式优化（先全量拼接，简单可靠）
- 不做分片 MD5 校验（HTTPS 已保证传输完整性）
- 不做跨设备续传（sessionStorage 是同浏览器同标签页）
- 不删除旧的 `/upload` 端点（保留兼容）

## 7. 测试规格

### 7.1 后端单测 (Jest)

| 测试 | 描述 |
|------|------|
| init 成功 | 合法参数 → 返回 uploadId + Redis 有记录 |
| init 超限 | fileSize > 1GB → 400 |
| init 无 auth | → 401 |
| chunk 成功 | 合法 uploadId + chunk → 文件落盘 + Redis 更新 |
| chunk 幂等 | 重复 chunkIndex → 200 不报错 |
| chunk 无效 uploadId | → 404 |
| chunk 他人 uploadId | → 404 |
| complete 成功 | 所有分片已传 → 拼接 + magic 校验 + fileId |
| complete 缺分片 | 未传完 → 400 |
| complete 非 APK | magic bytes 错 → 400 |

### 7.2 前端单测 (Vitest)

| 测试 | 描述 |
|------|------|
| 预检 >1GB | 显示 Alert 不发请求 |
| 预检 ≤1GB | 进入分片流程 |
| 进度计算 | 3/10 片完成 → 进度 ~15% |
| 并发控制 | 同时在传 ≤3 片 |
| 断点续传 | sessionStorage 有记录 → 提示续传 |
| 单片重试 | 失败 → 自动重试 3 次 |
