# APK 上传加固功能重构 — 规格说明 (Spec)

> 版本: 2026-07-30 | 状态: 已审批 | 决策来源: grill-me 5 轮拷问

## 1. 问题陈述

当前 APK 上传加固功能存在**场景 B 卡死**：用户上传 APK 后看到静态沙漏图标，进度条 0% 不动。

根因链（已确认 6 层）：
1. multer 默认 1MB 限制 → APK 被拒
2. `res.data` 双重解包 → `taskId=undefined`
3. `catch {}` 空吞异常 → 404 无限循环
4. KeepAlive 缓存恢复旧状态
5. JWT 过期但路由守卫不检查 → 全 401
6. 401 else 缺 return → Promise 挂起

**核心体验问题**：上传阶段**零进度反馈**，30MB APK 在 5Mbps 带宽下需 48 秒，期间用户看到空白沙漏。

## 2. 目标

| # | 目标 | 验收标准 |
|---|------|---------|
| G1 | 上传有进度条 | axios `onUploadProgress` 实时显示 0-100% |
| G2 | 文件只传一次 | `/upload` 返回 `fileId`，`/analyze` 和 `/harden` 只传 fileId |
| G3 | 流式写盘 | multer `diskStorage`，50MB APK 内存峰值 < 10MB |
| G4 | 文件自动清理 | Redis TTL 30min，分析/加固完成后主动删除 |
| G5 | 全程无卡死 | 任何阶段失败都显示红色 Alert + 重试按钮 |
| G6 | Keystore 不落盘 | memoryStorage 内存传，处理完立即清除 |
| G7 | 任务可恢复 | Redis 持久化任务状态，刷新页面后可继续 |

## 3. API 规格

### 3.1 新端点

```
POST /v1/hardening/upload
  Content-Type: multipart/form-data
  Body: apk (file, diskStorage, max 200MB)
  Auth: JWT
  Response: { fileId: string, fileName: string, fileSize: number }

POST /v1/hardening/analyze
  Content-Type: application/json
  Body: { fileId: string }
  Auth: JWT
  Response: { taskId: string }

POST /v1/hardening/harden
  Content-Type: multipart/form-data
  Body: fileId (string) + keystore (file, memoryStorage, max 10MB)
        + keystorePassword + keyAlias + keyPassword
        + config (JSON string) + analysisJson (JSON string)
        + ownershipConfirmed (string "true"/"false")
  Auth: JWT
  Response: { taskId: string, status: string, message: string }
```

### 3.2 保留端点（不变）

```
GET  /v1/hardening/status/:taskId   → 轮询进度
GET  /v1/hardening/tasks            → 任务列表
GET  /v1/hardening/download/:taskId → 下载加固 APK
```

### 3.3 删除端点

```
POST /v1/hardening/analyze  (旧的：接收文件+启动分析)  →  删除，替换为上面的新 analyze
```

### 3.4 Redis 数据结构

```
hardening:file:{fileId}  →  { path, devId, fileName, fileSize, uploadedAt }  TTL=1800s
hardening:task:{taskId}  →  HardeningTask JSON                                TTL=86400s
hardening:user_tasks:{devId}  →  [taskId, ...]                                TTL=86400s
```

## 4. 前端规格

### 4.1 上传阶段（Step 0）

- 用户选择 APK 文件后**立即显示上传进度条**
- 进度条使用 `axios.onUploadProgress` 回调：`(loaded / total) * 100`
- 上传完成 → 显示文件信息（名称、大小）→ 自动调 `/analyze`
- 上传失败 → 红色 Alert + "重新选择"按钮

### 4.2 分析阶段（Step 1）

- 调 `/analyze` 拿到 `taskId` → 开始轮询 `/status/:taskId`
- 进度条显示后端返回的 `progress`（0-100）
- 步骤图标 + 文字描述（"解压 APK..."、"解析 DEX..."）
- 分析完成 → 显示分析结果 → 进入配置步骤
- 分析失败 → 红色 Alert + "重新上传"按钮

### 4.3 加固阶段（Step 3-4）

- Keystore 选择 + 密码填写 + 所有权声明
- 点"开始加固" → 调 `/harden`（multipart：fileId + keystore + 配置）
- 加固进度轮询同分析阶段
- 加固完成 → 下载按钮

### 4.4 错误处理

- 全局 `globalError` ref，所有 catch 块设置
- `onUploadProgress` 中断（网络断开）→ 停止进度条 + 显示错误
- 轮询连续 5 次失败 → 停止轮询 + 显示错误
- KeepAlive `onActivated` → 重置卡住状态
- 路由守卫 JWT exp 预检 → 过期自动跳登录

## 5. 后端规格

### 5.1 Multer 配置

| 端点 | Storage | fileSize | 理由 |
|------|---------|----------|------|
| `/upload` | `diskStorage` → `tmp/hardening/{devId}/` | 200MB | APK 大文件流式写盘 |
| `/harden` | `memoryStorage` | 10MB | Keystore 小文件，不落盘 |

### 5.2 MulterExceptionFilter

全局异常过滤器，映射 multer 错误码：
- `LIMIT_FILE_SIZE` → 413 + "文件大小超过限制"
- `LIMIT_UNEXPECTED_FILE` → 400 + "字段名错误"
- 其他 → 500 + "文件上传失败"

### 5.3 文件校验

- `/upload`：校验 magic bytes（APK = ZIP = `PK\x03\x04`）
- `/harden`：校验 keystore magic bytes（JKS = `\xFE\xED\xFE\xED` 或 PKCS12 = `0x30`）

### 5.4 文件清理

- `/analyze` 完成后：删除磁盘文件 + 删除 Redis file key
- `/harden` 完成后：同上
- TTL 兜底：30 分钟自动过期

## 6. 不做的事

- 不做分片上传（APK 最大 200MB，不需要）
- 不做断点续传（复杂度不值得）
- 不做对象存储（1C2G 服务器无 S3）
- 不改变 `/status`、`/tasks`、`/download` 端点

## 7. 测试规格

### 7.1 后端单测（Jest）

| 测试 | 描述 |
|------|------|
| upload 成功 | 上传合法 APK → 返回 fileId + 文件落盘 + Redis 有记录 |
| upload 文件过大 | 上传 201MB → 413 |
| upload 非 APK | 上传 .txt → 400 |
| upload 无认证 | 无 JWT → 401 |
| analyze 成功 | 传有效 fileId → 返回 taskId + Redis task 记录 |
| analyze 无效 fileId | 传不存在的 fileId → 404 |
| analyze 他人 fileId | 传别人的 fileId → 404 |
| harden 成功 | 传 fileId + keystore + 配置 → 返回 taskId |
| harden 无 keystore | 缺 keystore → 400 |
| harden 无声明 | ownershipConfirmed=false → 400 |
| 文件清理 | analyze 完成后文件被删除 |

### 7.2 前端单测（Vitest）

| 测试 | 描述 |
|------|------|
| 上传进度回调 | onUploadProgress 触发 → progress ref 更新 |
| 上传失败显示错误 | 模拟网络错误 → globalError 有值 |
| 轮询成功推进 | 模拟 status 返回 → currentStep 推进 |
| 轮询 5 次失败停止 | 模拟连续 500 → 停止轮询 + 显示错误 |
| KeepAlive 恢复 | 模拟 onActivated → 卡住状态重置 |
