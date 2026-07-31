# 加固子功能重构规格说明 (Spec)

> 版本: 2026-07-31 | 范围: 除文件上传外的加固全链路

## 1. 问题清单

| # | 问题 | 严重度 | 根因 |
|---|------|:------:|------|
| A | 前端 catch 显示 "Request failed with status code 400" 而非后端消息 | 高 | `errMsg(e)` 没提取 `e.response.data.message` |
| B | 加固 Step 4 进度条无初始状态 | 低 | taskStatus 初始值缺失 |
| C | Keystore 上传无进度反馈 | 低 | NUpload 无 progress 回调 |
| D | 下载 200MB APK 全量加载到浏览器内存 | 中 | blob 全量 → 改用流式 a 标签 |
| E | 任务列表无"取消"按钮 | 低 | 缺少 cancel API + UI |
| F | 分析/加固失败只能"重新开始" | 中 | 缺少重试按钮(不重传文件) |
| G | 分片上传并发丢片(42 片只收 36 片) | 高 | 3 并发下部分 chunk POST 被 Cloudflare 限流,重试 3 次仍失败后 throw 但前端可能未正确处理 |

## 2. 修复方案

### A: 统一错误消息提取
前端 `errMsg(e)` 增加 axios response 提取:
```typescript
if (axios.isAxiosError(e) && e.response?.data?.message) {
  return e.response.data.message;
}
```

### B: 加固进度初始状态
`startHardening` 中立即设置 `taskStatus` 含 message="正在连接服务器..."

### C: Keystore 上传反馈
NUpload 加 `@update:file-list` 回调,显示文件名+大小+✅图标

### D: 流式下载
改用 `<a>` 标签 + `window.open` 直接下载 URL(让浏览器流式处理)
后端 download 端点改用 `res.download()` 或 `StreamableFile`

### E: 取消任务
- 后端: `DELETE /v1/hardening/tasks/:taskId` → 设 status=cancelled + 清理文件
- 前端: 任务列表每行加"取消"按钮(仅 analyzing/hardening 状态显示)

### F: 重试按钮
- 分析失败: 显示"重试分析"按钮 → 用已有 fileId 重新调 analyze
- 加固失败: 显示"重试加固"按钮 → 用已有 fileId + keystore 重新调 harden
- 上传失败: 显示"重新上传"按钮(已有)

### G: 分片丢片修复
- 前端: chunk POST 增加 timeout 30s(单片),失败重试增加到 5 次
- 前端: complete 前校验 `completedSet.size === totalChunks`
- 后端: complete 返回缺失片列表,前端可补传
- 后端: mergeChunks 改为返回缺失片列表而非直接 400

## 3. API 变更

```
新增: DELETE /v1/hardening/tasks/:taskId  → 取消任务
变更: POST /v1/hardening/upload/complete → 缺片时返回 { missing: number[] } 而非 400
```

## 4. 验收标准

| # | 验收 | 方法 |
|---|------|------|
| A | 后端 400 时前端显示后端 message 而非 axios 通用消息 | 模拟 400 响应 |
| B | Step 4 进度条立即显示"正在连接..." | 视觉检查 |
| C | 选择 keystore 后显示文件名+大小 | 视觉检查 |
| D | 下载 200MB 不卡浏览器 | 实测 |
| E | 任务列表可取消进行中任务 | 点击取消 → 状态变 cancelled |
| F | 失败后显示重试按钮 | 视觉检查 + 点击重试 |
| G | 200MB 分片上传不丢片 | 实测 42/42 片 |
