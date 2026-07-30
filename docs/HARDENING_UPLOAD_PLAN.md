# APK 上传加固功能重构 — 实施计划 (Plan)

> 版本: 2026-07-30 | 方法论: TDD Red-Green-Refactor

## Phase 0: 基础设施（无测试，纯配置）

### Step 0.1: MulterExceptionFilter
- 新建 `backend/src/hardening/multer-exception.filter.ts`
- 映射 LIMIT_FILE_SIZE → 413, LIMIT_UNEXPECTED_FILE → 400
- 在 `hardening.module.ts` 注册为 controller-scoped filter

### Step 0.2: Redis file 元数据 service
- 新建 `backend/src/hardening/file-storage.service.ts`
- `save(fileId, devId, path, fileName, fileSize)` → Redis SET TTL 1800
- `get(fileId, devId)` → Redis GET + 校验 devId
- `delete(fileId)` → Redis DEL + fs.unlink
- 方法签名先写，实现后补

## Phase 1: 后端 `/upload` 端点（TDD）

### Step 1.1: 🔴 Red — 写失败测试
- `hardening-upload.spec.ts`
- 测试: POST /v1/hardening/upload + 合法 APK → 期望 201 + fileId + Redis 有记录

### Step 1.2: 🟢 Green — 最少代码通过
- 在 `hardening.controller.ts` 加 `@Post('upload')` 端点
- 使用 `FileInterceptor('apk', { storage: diskStorage({...}) })`
- 调 `fileStorage.save()` → 返回 `{ fileId, fileName, fileSize }`

### Step 1.3: ♻️ Refactor
- 提取 diskStorage destination 为配置常量
- 加 magic bytes 校验（PK\x03\x04）

### Step 1.4: 🔴 Red — 边界测试
- 文件过大 → 413
- 非 APK 文件 → 400
- 无 JWT → 401

### Step 1.5: 🟢 Green + ♻️ Refactor

## Phase 2: 后端 `/analyze` 重构（TDD）

### Step 2.1: 🔴 Red
- 测试: POST /v1/hardening/analyze + `{ fileId }` → 期望 200 + taskId

### Step 2.2: 🟢 Green
- 重构 `/analyze` 端点：从 `@UploadedFile` 改为 `@Body() { fileId }`
- 从 `fileStorage.get(fileId, devId)` 拿文件路径
- 调 `hardeningService.startAnalysis(path, devId, fileName)`
- 分析完成后调 `fileStorage.delete(fileId)`

### Step 2.3: 🔴 Red — 边界测试
- 无效 fileId → 404
- 他人 fileId → 404
- 文件已被清理 → 404 + 友好消息

### Step 2.4: 🟢 Green + ♻️ Refactor

## Phase 3: 后端 `/harden` 重构（TDD）

### Step 3.1: 🔴 Red
- 测试: POST /v1/hardening/harden + fileId + keystore + 配置 → 期望 200 + taskId

### Step 3.2: 🟢 Green
- 重构 `/harden`：APK 用 fileId 从 Redis 取路径
- Keystore 用 `FileInterceptor('keystore', { storage: memoryStorage(), limits: { fileSize: 10MB } })`
- 加固完成后调 `fileStorage.delete(fileId)`

### Step 3.3: 🔴 Red — 边界测试
- 无 keystore → 400
- ownershipConfirmed=false → 400
- keystore 格式错误 → 400

### Step 3.4: 🟢 Green + ♻️ Refactor

## Phase 4: 前端上传进度条（TDD）

### Step 4.1: 🔴 Red — 写失败测试
- `HardenUpload.spec.ts`
- 测试: 选择文件 → uploadProgress ref 从 0 更新到 100

### Step 4.2: 🟢 Green
- 在 `hardening.ts` 新增 `uploadApk(file, onProgress)` 函数
- 使用 `longTimeoutClient.post('/hardening/upload', formData, { onUploadProgress })`
- 在 `HardenUpload.vue` 加 `uploadProgress` ref + `NProgress` 组件
- Step 0 显示上传进度条，完成后自动调 analyze

### Step 4.3: ♻️ Refactor
- 提取进度计算为 `computePercent(loaded, total)` 纯函数
- 上传/分析/加固三阶段进度条用不同颜色区分

### Step 4.4: 🔴 Red — 错误场景测试
- 上传中断 → globalError 有值 + 进度条停止
- 轮询 5 次失败 → 停止 + 错误

### Step 4.5: 🟢 Green + ♻️ Refactor

## Phase 5: 集成测试 + 部署

### Step 5.1: 后端集成测试
- supertest 模拟完整流程: upload → analyze → status 轮询 → harden → download

### Step 5.2: 前端 E2E 验证
- 手动浏览器测试：上传 → 进度条 → 分析进度 → 配置 → 加固 → 下载

### Step 5.3: 部署
- Docker build + push + 服务器 pull + recreate

### Step 5.4: 生产验证
- 用户测试上传加固全流程

## 依赖关系

```
Phase 0 ──→ Phase 1 ──→ Phase 2 ──→ Phase 3 ──→ Phase 4 ──→ Phase 5
  (配置)      (upload)    (analyze)   (harden)    (前端)      (集成)
```

Phase 1-3 可并行开发（都是后端端点），Phase 4 依赖 Phase 1 的 API 契约。

## 预估

| Phase | 文件变更 | 预估 |
|-------|---------|------|
| Phase 0 | 2 新文件 | 30 min |
| Phase 1 | 1 新测试 + 1 改 controller | 45 min |
| Phase 2 | 1 新测试 + 1 改 controller | 45 min |
| Phase 3 | 1 新测试 + 1 改 controller | 45 min |
| Phase 4 | 1 改 api + 1 改 vue + 1 新测试 | 60 min |
| Phase 5 | 部署 + 验证 | 30 min |
| **合计** | **~5 新文件 + 4 改文件** | **~4 小时** |
