# 加固流水线重构规格说明 (Spec)

> 版本: 2026-08-01 | 方法: grill-me 5 轮决策

## 1. 问题

当前 `runHarden` 有 8 个问题导致加固失败或体验极差：

| # | 问题 | 严重度 | 根因 |
|---|------|:------:|------|
| 1 | **缺 zipalign** | 致命 | apksigner 前未 zipalign → .so 页面未对齐 → extractNativeLibs=false 时加载失败 |
| 2 | **apktool 调两次** | 高 | injectMetaSoName + patchManifestForHardening 各解包+重建一次，200MB 各 ~30-60s |
| 3 | **strip 在 apktool 之后** | 高 | 先 apktool b 重建（含签名）再 strip → 顺序反了 |
| 4 | **zip 命令不存在** | 致命 | Alpine 容器没装 zip → injectAsset/injectNativeSo/stripSignature 全崩 |
| 5 | **进度粗(4 点)** | 中 | 30%→50% 间隔 30s 无更新，用户以为卡死 |
| 6 | **错误不透传** | 高 | catch 只存 e.message，apksigner stderr 丢了 |
| 7 | **无超时** | 高 | apktool 卡住 → 任务永远挂着 |
| 8 | **无预检** | 高 | keystore 密码错 → 白等 2-3 分钟才在 apksigner 报错 |

## 2. 新流水线（12 步 + 子进度）

```
正确顺序: strip → inject all → apktool d → modify → apktool b → zipalign → apksigner

Step  0: 预检(5s)        → 5%    "正在验证 Keystore 和 APK..."
  0a: keytool 验证 keystore 密码 + 别名
  0b: APK magic bytes 检查
  0c: 已加固检测(classes-xcj.dex / DefenderInitProvider)
  0d: SDK 产物存在性
  0e: 磁盘空间检查(> APK × 3)
Step  1: strip 签名      → 10%   "删除旧签名..."
Step  2: 注入 config     → 15%   "注入 defender-config.json..."
Step  3: 注入 DEX        → 25%   "注入 classes-N.dex..."
Step  4: 注入 SO arm64   → 35%   "注入 lib/arm64-v8a/xxx.so..."
Step  5: 注入 SO armv7   → 40%   "注入 lib/armeabi-v7a/xxx.so..." (无则跳过)
Step  6: apktool 解包    → 50%   "解包 APK(修改 Manifest)..."
Step  7: 修改 Manifest   → 60%   "注入 meta-data + provider + permission..."
Step  8: apktool 重建    → 70%   "重建 APK..."
Step  9: zipalign        → 80%   "对齐 APK(-p 4)..."
Step 10: apksigner       → 90%   "签名(V1+V2+V3)..."
Step 11: 清理+完成       → 100%  "加固完成! 启用 N 个模块"
```

## 3. 验收标准

| # | 验收 | 方法 |
|---|------|------|
| 1 | 加固成功(18MB APK) | 端到端测试 |
| 2 | 加固成功(200MB APK) | 端到端测试 |
| 3 | keystore 密码错 → 3s 内报错 | 预检 keytool |
| 4 | APK 已加固 → 立即报错 | 预检检测 |
| 5 | 进度 12 步全可见 | 前端轮询 task.step |
| 6 | 超时报 failed + 清理 | 模拟超时 |
| 7 | apksigner stderr 透传 | 模拟签名失败 |
| 8 | zipalign 在 apksigner 之前 | 代码审计 |
| 9 | strip 在所有注入之前 | 代码审计 |
| 10 | 临时文件清理 | 加固完/失败后 workDir 删除 |

## 4. 技术决策

| 决策 | 选择 | 理由 |
|------|------|------|
| zip 操作 | adm-zip(注入/删除) + Dockerfile 装 zip(后备) | 无 fork 开销 + 错误清晰 |
| apktool | 合并为一次 d+b | 避免两次解包+重建 |
| 超时 | 动态 120s + MB×3s, cap 600s | 18MB→174s, 200MB→600s |
| 进度 | 12 步 + 子进度 | 最大无更新 ~15s |
| 预检 | 全部 5 项 | 快速失败 ~3s |
| 错误 | stderr 捕获 + 透传 | 用户能看到 apksigner 具体错误 |
