# ADR 0068 · v2 注入工具架构:仅 SDK 集成辅助

- 状态:accepted
- 日期:2026-07-19
- 决策者:小城笺项目
- 层次:技术栈 / 注入工具

## 背景

ADR 0011 / 0028 / 0063 / 0064 / 0065 / 0066 描述了"Smali + dex 双引擎注入"路径,核心是**修改他人或自有 APK 的字节码,自动注入 `XiaochengjianSDK.init(this)` 调用**。其中 ADR 0028 进一步规定 SaaS 版提供"上传 APK 到服务器处理"的 Web 注入工具。

2026-07-15 ~ 2026-07-18 的 v2 重构期间,前任工程师基于以下理由整体推翻了这套架构:

1. **合规红线冲突**:CLAUDE.md 第 2 节明确"不得实现绕过其他验证系统""不得注入他人 APK 用于商业转售"。虽然 ADR 0011/0030 限定"仅注入开发者自有 APK",但 dex 注入工具客观上具备修改任意 APK 的能力,工具一旦发布即不可控,法律风险高于收益。
2. **维护成本**:dexlib2 + ImmutableDexFile 重建 + AXMLPrinter2 解析 + 加固兼容 + Smali 降级,任一项都是独立工程,单人维护不可持续。
3. **SaaS 风险**:ADR 0028 设计的"服务器端处理 APK"会让服务器持有他人 APK(侵权证据),即使立即删除仍有法律风险。
4. **ROI 低**:开发者主动集成 SDK 一行 gradle 依赖 + 一个 Application 类即可完成,无需注入工具。

v2 重构已落地代码:
- `injector/` CLI 仅保留 `init`(生成集成代码模板)+ `sign`(对开发者自有 APK 签名 + 水印)两个子命令
- `injector-android/` APP 移除"APK 注入"Tab,改为"打包辅助"Tab(纯文档展示 + 剪贴板复制)
- `backend/src/inject/` 模块完全删除
- demo APP 不再演示注入路径

但前任工程师**未按 CLAUDE.md 第 10 节要求**写新 ADR 标记旧 ADR 为 superseded,导致 ADR 0011/0028/0063-0066 状态仍是 `accepted`,与代码事实严重不符。本 ADR 补齐决策追溯。

## 决策

### v2 注入工具架构:仅 SDK 集成辅助,不做字节码注入

**保留的能力:**

| 子系统 | v2 能力 | 边界 |
|---|---|---|
| `injector` CLI `init` | 生成 gradle 依赖片段 + Application 初始化代码模板 + 集成说明 README | 不修改任何 APK,只产出文本模板 |
| `injector` CLI `sign` | 对开发者**自有** APK 做 V1+V2+V3 签名 + 可选水印 | 不修改 APK 内容,只签名 + 加水印文件 |
| `injector-android` APP | 3 Tab:卡密管理 / 打包辅助(文档向导)/ 统计 | "打包辅助"Tab 只展示代码片段 + 复制到剪贴板,不执行任何字节码修改 |
| 水印 | `META-INF/xcj-watermark.txt` 写入 APK,记录工具版本 + 开发者 ID + 时间戳 | 明文可读(开发者自查),不可擦除(重打包后水印仍在) |

**移除的能力:**

- ❌ dex 字节码注入(ImmutableDexFile 重建,ADR 0063)
- ❌ Smali 降级注入(ADR 0011 备选引擎)
- ❌ Application.onCreate / attachBaseContext 注入点(ADR 0064)
- ❌ 创建 XcjApplication + Manifest 注册(ADR 0065)
- ❌ AXMLPrinter2 解析 AndroidManifest(ADR 0066)
- ❌ 服务器端 APK 处理(ADR 0028 的 SaaS 独占功能)
- ❌ 加固 APK 兼容 / 自动脱壳(ADR 0067 MVP 决策不变,继续推迟)

### 开发者工作流(v2)

```
1. 开发者在 admin-web 创建应用,获得 appId + appSecret
2. 开发者运行 `injector init --app-id=... --server-url=... -o ./xcj-integration`
   -> 生成 gradle 依赖片段 + XcjApplication.kt 模板 + README
3. 开发者按 README 手动集成到自己的源码
4. 开发者编译自己的 APK(标准 Android 构建)
5. (可选)开发者运行 `injector sign -i app.apk -o app-signed.apk --keystore=... --watermark-id=...`
   -> 签名 + 加水印
6. 开发者分发 APK
```

### 与 ADR 0030 防滥用的关系

ADR 0030 的"签名密钥强制 + 注入水印"两项在 v2 仍保留:
- `injector sign` 强制要求 keystore(签名密钥强制)
- `injector sign --watermark-id=...` 写入水印文件
- 但水印实现简化为明文(ADR 0030 原设计为"AES-256 加密,密钥服务端持有")。**这是 ADR 0030 的部分未实现,不在本 ADR 取代范围内**,需在后续 ADR 单独处理(见 P1/P2 待办)。

### SaaS 独占功能边界调整

ADR 0041 把"Web APK 注入工具"列为 SaaS 独占增值点。本 ADR 移除该能力后,SaaS 独占功能需重新定义。建议(本 ADR 不强制,留给后续 ADR):
- SaaS 独占保留:多租户运维、Prometheus/Grafana 监控、AlertManager 飞书告警、SLA
- SaaS 独占移除:Web APK 注入工具

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| A. 恢复 dex 注入(回到 ADR 0011/0028) | 功能完整 | 合规风险、维护成本高 | 违反 CLAUDE.md 第 2 节红线 |
| B. 仅文档化移除决策,不写新 ADR | 省事 | 违反 CLAUDE.md 第 10 节 | 决策追溯断裂,后续工程师无法信任 ADR |
| C. 写新 ADR 整体取代(本方案) | 合规、追溯完整 | 6 份旧 ADR 同时 superseded,跨度大 | 合理(实际推翻是一体决策,不宜拆分) |
| D. 逐项写 6 份新 ADR 分别取代 | 追溯更细 | 6 份新 ADR 内容高度重复,且实际是同一个决策 | 冗余 |

## 影响

- **正面:**
  - ADR 与代码事实一致,后续工程师可信任 ADR(CLAUDE.md 第 10 节合规)
  - 合规红线对齐,工具客观能力边界清晰(只签名 + 水印,不修改字节码)
  - 维护成本大幅降低,injector 模块代码量从数千行降至约 250 行
  - 服务器不再持有他人 APK,法律风险消除
- **负面:**
  - SaaS 失去"Web APK 注入"增值点(ADR 0041 边界需调整)
  - 开发者集成门槛略高(需手动改 Application 类,不能"一键注入")
  - 已删除的 backend inject 模块代码若历史上有调用方,需确认无残留引用
- **风险:**
  - 开发者误以为 v2 仍提供注入能力,需在 README + sdk-integration.md 明确说明
  - ADR 0030 水印加密决策未落地,需单独 ADR 处理(不在本 ADR 范围)

## 关联

- **取代(superseded by 0068):**
  - ADR 0011 · APK 注入方案:Smali + dex
  - ADR 0028 · 注入工具架构
  - ADR 0063 · dex 指令插入:ImmutableDexFile 重建
  - ADR 0064 · 注入点:Application.onCreate + attachBaseContext
  - ADR 0065 · 无自定义 Application:创建 XcjApplication + Activity 兜底
  - ADR 0066 · AXML 解析:AXMLPrinter2
- **保留不变:**
  - ADR 0067 · 加固 APK 兼容:MVP 不支持(MVP 决策不变,继续推迟到 v3)
  - ADR 0030 · 防滥用机制(签名强制 + 水印两项保留,水印加密待后续 ADR)
- **关联 ADR:** 0001(合规红线)、0041(SaaS 与开源边界,需后续调整)、0002(部署形态)
- **关联代码:**
  - `injector/src/main/kotlin/com/xcj/injector/InjectorMain.kt`(init + sign 子命令)
  - `injector/src/main/kotlin/com/xcj/injector/watermark/Watermark.kt`(明文水印)
  - `injector/src/main/kotlin/com/xcj/injector/sign/ApkSigner.kt`(V1+V2+V3 签名)
  - `injector-android/app/src/main/kotlin/com/xcj/app/ui/PackHelperTab.kt`(打包辅助 Tab)
- **关联文档:** `docs/sdk-integration.md`、`docs/handover.md`、`CLAUDE.md` 第 2 节
- **关联 git commit:** `6edb027 fix(v2): 移除 admin-web APK 注入 Tab + backend inject 模块(红线)`(2026-07-15~18 v2 重构期间)
