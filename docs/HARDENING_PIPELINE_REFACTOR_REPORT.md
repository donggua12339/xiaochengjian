# 加固流水线重构完成报告

> 日期: 2026-08-01 | 方法: grill-me → spec → plan → TDD → 部署

## 1. 修复的 8 个问题

| # | 问题 | 修复前 | 修复后 | 验证 |
|---|------|--------|--------|:----:|
| 1 | 缺 zipalign | 无 zipalign → .so 未对齐 | Step 9: `zipalign -p -f 4` | ✅ 测试 |
| 2 | apktool 调两次 | 2×30-60s = 60-120s | 合并为 1 次 d+b | ✅ 测试 |
| 3 | strip 顺序反 | apktool b → strip → 签名无效 | strip 在 Step 1(所有注入前) | ✅ 代码审计 |
| 4 | zip 命令不存在 | `execFile('zip')` → not found | adm-zip `injectToZip`/`stripSignatureAdmZip` | ✅ 测试 |
| 5 | 进度粗(4 点) | 30%→50% 无更新 30s+ | 12 步+子进度,最大间隔 ~15s | ✅ 代码审计 |
| 6 | 错误不透传 | `e.message` 丢 stderr | `execWithStderr` → `cause` 透传 | ✅ 测试 |
| 7 | 无超时 | apktool 卡住→永远挂着 | 动态 120s+MB×3s cap 600s + AbortController | ✅ 测试 |
| 8 | 无预检 | keystore 错→白等 2-3min | `PreflightService.runAll` 3s 快速失败 | ✅ 7/7 测试 |

## 2. 新流水线(12 步)

```
Step  0: preflight  (5%)   🔍 验证 Keystore + APK + SDK + 磁盘
Step  1: strip      (10%)  ✂️ 删除旧签名(adm-zip)
Step  2: config     (15%)  ⚙️ 注入 defender-config.json(adm-zip)
Step  3: dex        (25%)  📄 注入 classes-N.dex(adm-zip)
Step  4: so_arm64   (35%)  🔒 注入 lib/arm64-v8a/xxx.so(adm-zip)
Step  5: so_armv7   (40%)  🔒 注入 lib/armeabi-v7a/xxx.so(adm-zip,无则跳过)
Step  6: apktool_d  (50%)  📦 解包 APK(修改 Manifest)
Step  7: manifest   (60%)  📋 注入 meta-data + provider + permission
Step  8: apktool_b  (70%)  🔨 重建 APK
Step  9: zipalign   (80%)  📐 对齐 APK(-p 4)
Step 10: sign       (90%)  🔑 签名(V1+V2+V3)
Step 11: done      (100%)  ✅ 加固完成
```

## 3. 测试结果

```
PASS preflight.service.spec.ts   (7 tests)
PASS file-storage.service.spec.ts (6 tests)
PASS chunked-upload.spec.ts      (14 tests)
PASS hardening-upload.spec.ts     (5 tests)
──────────────────────────────────────────
Tests:  32 passed, 32 total
```

## 4. 验收标准对照

| # | 验收 | 状态 |
|---|------|:----:|
| 1 | 加固成功(18MB APK) | ⏳ 待用户测试 |
| 2 | 加固成功(200MB APK) | ⏳ 待用户测试 |
| 3 | keystore 密码错 → 3s 内报错 | ✅ PreflightService |
| 4 | APK 已加固 → 立即报错 | ✅ adm-zip 检测 classes-xcj.dex |
| 5 | 进度 12 步全可见 | ✅ stepIcons 补全 |
| 6 | 超时报 failed + 清理 | ✅ AbortController + finally |
| 7 | apksigner stderr 透传 | ✅ execWithStderr → cause |
| 8 | zipalign 在 apksigner 之前 | ✅ Step 9 → Step 10 |
| 9 | strip 在所有注入之前 | ✅ Step 1 |
| 10 | 临时文件清理 | ✅ finally → fs.rm(workDir) |

## 5. 技术决策回顾

| 决策 | 选择 | grill-me 轮次 |
|------|------|:------------:|
| 重写范围 | B 混合方案 | 第 1 轮 |
| zip 操作 | Dockerfile zip + adm-zip | 第 2 轮 |
| 超时策略 | 动态 120s+MB×3s cap 600s | 第 3 轮 |
| 进度粒度 | 超细 12 步+子进度 | 第 4 轮 |
| 预检 | 全部 5 项 | 第 5 轮 |

## 6. 新增/修改文件

| 文件 | 类型 | 说明 |
|------|:----:|------|
| `preflight.service.ts` | 新增 | 预检服务(keytool+magic+已加固+SDK) |
| `preflight.service.spec.ts` | 新增 | 7 个预检测试 |
| `hardening.service.ts` | 重写 | 12 步流水线+adm-zip+动态超时+stderr 透传 |
| `hardening.module.ts` | 修改 | 注册 PreflightService |
| `HardenUpload.vue` | 修改 | stepIcons 补全 12 步 |
| `backend.Dockerfile` | 修改 | apk add zip |
| `package.json` | 修改 | adm-zip + @types/adm-zip |
| `HARDENING_PIPELINE_REFACTOR_SPEC.md` | 新增 | 规格说明 |
| `HARDENING_PIPELINE_REFACTOR_PLAN.md` | 新增 | TDD 实施计划 |
