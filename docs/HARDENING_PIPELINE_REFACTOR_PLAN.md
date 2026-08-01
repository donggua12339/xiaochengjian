# 加固流水线重构实施计划 (Plan)

> 版本: 2026-08-01 | 方法: TDD Red-Green-Refactor

## Phase 0: 基础设施 (无测试)

### Step 0.1: Dockerfile 装 zip
- `deploy/backend.Dockerfile`: `apk add --no-cache zip`
- 验证: `docker exec xcj-backend which zip`

### Step 0.2: 安装 adm-zip
- `cd backend && pnpm add adm-zip @types/adm-zip`

## Phase 1: 预检模块 (TDD)

### Step 1.1: 🔴 Red — 写 preflight 测试
- `hardening-preflight.spec.ts`
- 测试: keystore 有效 → pass
- 测试: keystore 密码错 → throw "Keystore 密码错误"
- 测试: 别名不存在 → throw "别名不存在"
- 测试: APK magic bytes 错 → throw "APK 损坏"
- 测试: APK 已加固 → throw "请勿重复加固"
- 测试: SDK 产物缺失 → throw "SDK 未构建"

### Step 1.2: 🟢 Green — 实现 preflight service
- `preflight.service.ts`
- `validateKeystore(ksPath, ksPass, alias)` → execFile keytool
- `validateApk(apkPath)` → magic bytes + 已加固检测
- `validateSdkArtifacts()` → statSync candidates
- `checkDiskSpace(workDir, apkSize)` → statfs

### Step 1.3: ♻️ Refactor
- 提取 keytool 路径到配置

## Phase 2: 加固流水线重写 (TDD)

### Step 2.1: 🔴 Red — 写 runHarden 测试
- `hardening-pipeline.spec.ts`
- 测试: 正确顺序 strip→inject→apktool→zipalign→sign
- 测试: 进度回调 12 步全触发
- 测试: 超时 → status=failed + workDir 清理
- 测试: apksigner stderr 透传到 task.error
- 测试: 失败后 workDir 清理

### Step 2.2: 🟢 Green — 重写 runHarden
- 新顺序: preflight → strip(adm-zip) → inject config/dex/so(adm-zip) → apktool d → modify manifest → apktool b → zipalign → apksigner → cleanup
- 动态超时: `AbortController` + `setTimeout`
- 每步 `updateProgress(task, step, percent, message, subMessage)`
- execFile 捕获 stderr → 存入 task.error

### Step 2.3: ♻️ Refactor
- 提取 execWithTimeout 工具函数
- 提取 adm-zip 注入为 injectToZip / removeFromZip

## Phase 3: 前端进度展示 (无后端测试)

### Step 3.1: 前端 stepIcons 补 12 步图标
### Step 3.2: 子进度展示(如 "注入 so arm64-v8a...")

## Phase 4: 集成测试 + 部署

### Step 4.1: 后端全量测试 25+ tests
### Step 4.2: Docker 构建 + 部署
### Step 4.3: 端到端验证

## 依赖关系

```
Phase 0 ──→ Phase 1 ──→ Phase 2 ──→ Phase 3 ──→ Phase 4
 (基础设施)   (预检TDD)   (流水线TDD)  (前端进度)   (集成部署)
```

## 预估

| Phase | 文件变更 | 预估 |
|-------|---------|------|
| Phase 0 | 2 文件 | 10 min |
| Phase 1 | 2 新文件 | 40 min |
| Phase 2 | 1 重写 + 1 新测试 | 60 min |
| Phase 3 | 1 改文件 | 20 min |
| Phase 4 | 部署 | 20 min |
| **合计** | **~6 文件** | **~2.5h** |
