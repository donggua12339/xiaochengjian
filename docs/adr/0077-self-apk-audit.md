# ADR 0077 · 自有 APK 诊断功能(含技术兜底)

- 状态:accepted
- 日期:2026-07-19
- 决策者:小城笺项目
- 层次:功能 / 安全 / 合规

## 背景

ADR 0076 accept 方案 B,引入"自有 APK 诊断"作为有限红方能力。本 ADR 是 ADR 0076 的功能级实现 ADR,定义:

1. 功能边界(做什么 / 不做什么)
2. 技术兜底(三重校验,法律自证清白的证据)
3. 实现方案(后端 + CLI + 安卓端)
4. 审计日志要求
5. 与现有 ADR 的关系

**核心约束**(ADR 0076 用户决策):
> 红方功能严格限定为"仅处理用户本地拥有的、具有合法著作权的 APK 文件"。
> 技术兜底:在代码层面实现强制校验(包名白名单、签名校验比对、或本地私有目录隔离),确保工具无法被轻易用于第三方 APK 的通用脱壳。这既是技术需求,也是法律自证清白的证据。

## 决策

### 1. 功能边界

**允许的能力(自有 APK 诊断)**:

| 能力 | 说明 | 实现 |
|---|---|---|
| APK 静态分析 | JADX 反编译查看(只读) | 集成 JADX CLI |
| AndroidManifest 查看 | 二进制 AXML 解析 | AXMLPrinter2 |
| 签名信息查看 | V1/V2/V3 签名块解析 | apksigner verify --print-certs |
| 资源查看 | resources.arsc 解析 | aapt2 dump |
| dex 结构查看 | dex 头部 + 类列表(不反编译) | dexlib2 只读 |
| SDK 后门扫描 | 扫描已知可疑 API 调用(反射 loadLibrary 等) | 自定义规则 |

**禁止的能力(红线)**:

- ❌ 通用脱壳(任意 APK 脱壳,FRIDA-DEXDump 类)
- ❌ 通用去签名校验(任意 APK 去签)
- ❌ 字节码修改(改 dex / 改 smali / 改资源)
- ❌ 重打包(改 APK 后重新签名)
- ❌ 他人 APK 处理(三重校验任一失败即拒绝)

**所有能力均为只读**,不修改上传的 APK,不输出修改后的 APK。

### 2. 技术兜底:三重校验(法律自证清白的证据)

**校验 1:包名白名单**

- 开发者必须在 admin-web 后台注册自有应用包名(如 `com.yourcompany.yourapp`)
- 诊断时,后端从 APK 的 AndroidManifest 解析包名,与开发者注册的包名白名单比对
- 包名不在白名单 -> 拒绝诊断,返回 `APP_NOT_OWNED`
- **法律意义**:证明工具仅处理开发者已声明为自有的 APK

**校验 2:签名校验比对**

- 开发者在 admin-web 后台配置自有应用的预期签名 hash(SHA-256)
- 诊断时,后端从 APK 提取签名块,计算 hash,与开发者配置的预期 hash 比对
- 签名不匹配 -> 拒绝诊断,返回 `SIGNATURE_MISMATCH`
- **法律意义**:证明工具仅处理开发者拥有签名密钥的 APK(签名密钥即所有权证据)

**校验 3:本地私有目录隔离**

- 诊断操作在服务器临时目录 `/tmp/audit/<taskId>/` 完成
- 目录权限 700,仅 xcj-claude 用户可读写
- 诊断完成后,临时目录立即删除(`rm -rf /tmp/audit/<taskId>/`)
- 不持久化上传的 APK,不持久化诊断中间产物
- **法律意义**:服务器不持有他人 APK(无侵权证据),与 ADR 0068 原则一致

**三重校验执行顺序**:
```
1. 上传 APK -> 计算 hash -> 检查大小(< 200MB)
2. 解析 AndroidManifest -> 提取包名
3. 校验 1:包名白名单(失败 -> 拒绝)
4. 提取签名块 -> 计算 hash
5. 校验 2:签名 hash 比对(失败 -> 拒绝)
6. 校验 3:在 /tmp/audit/<taskId>/ 隔离目录操作
7. 诊断完成 -> 删除临时目录
8. 审计日志记录(含三重校验结果)
```

**任一校验失败即拒绝,不提供跳过开关**(与 ADR 0027 安全基线一致)。

### 2.1 例外条款(签名回填 + 梆梆适配器,2026-07-20 修订)

三重校验为强制基线,以下两类场景在严格约束下作为**例外**允许。例外不削弱三重校验本身,而是在校验通过后追加允许的操作;任一例外违反其约束即整体拒绝。

#### 例外 A:签名回填(META-INF only,自有 APK 重签名场景)

**适用场景**:开发者对自有 APK 完成诊断后,需以自有 keystore 重新签名以恢复可安装状态(例如:对自有 APK 做了无侵入的 metadata 调整后需重签)。

**约束(任一违反即拒绝)**:

1. **范围限定**:仅修改 APK 内 `META-INF/` 目录下的签名相关文件(`CERT.RSA` / `CERT.SF` / `MANIFEST.MF` / `*.RSA` / `*.SF` 等),**不得修改** `classes*.dex` / `resources.arsc` / `AndroidManifest.xml` / `res/` / `lib/` / `assets/` 等业务文件
2. **keystore 自有**:必须使用开发者上传的自有 keystore(`.jks` / `.keystore` + 密码),工具不提供任何默认/通用 keystore,不提供 keystore 共享/借用
3. **签名方案**:V1 + V2 + V3(`apksigner`,与 ADR 0030 一致),不做 V4(增量安装,与诊断无关)
4. **白名单同步**:回填后的 APK 整体 SHA-256 hash 自动写入服务端白名单(开发者应用配置),后续诊断的校验 2 比对该 hash
5. **三重校验前置**:回填操作前必须先通过三重校验(包名白名单 + 原签名 hash 比对 + 目录隔离),未通过校验的 APK 拒绝回填
6. **审计日志**:回填操作单独记入 `audit_log_own`(`status=RESIGN`),含原 hash / 新 hash / keystore 指纹(SHA-256,不存密码)

**法律意义**:工具仅协助开发者维护自有 APK 的签名完整性,不提供"通用去签"能力(通用去签 = 修改他人 APK 签名以绕过校验,本工具不支持)。

**禁止变体**:
- ❌ 全量签名替换(改 dex 后重签,本工具不做)
- ❌ 通用签名剥离(去 V1/V2/V3 不重签,本工具不做)
- ❌ keystore 共享/借用(必须开发者自有)

#### 例外 B:梆梆加固自检适配器(详见 ADR 0078)

**适用场景**:开发者自有 APK 使用梆梆加固,需诊断加固层完整性(so/API 扫描,不脱壳)。

**约束**:见 ADR 0078 的 3 把锁:
- **锁 A**:仅梆梆一家,360 / 爱加密 / 乐固 / 腾讯乐固等其他加固方案不支持,适配器不扩展
- **锁 B**:admin-web 上必须先勾选 EULA 才能启用,无 EULA 不开放
- **锁 C**:仅输出完整性报告 + so/API 扫描结果,**不输出反编译源码**

**与三重校验的关系**:三重校验仍然强制,但校验 2 比对的签名 hash 是**梆梆加固后**的 hash(开发者在 admin-web 配置加固后的预期 hash,而非加固前的原始 hash)。

**法律意义**:证明工具不提供通用脱壳,仅限自有 APK 的加固层自检。

**开发前置(强制)**:本例外的代码实现必须在 ADR 0078 律师咨询意见落地后才可启动,在此之前只允许 ADR 设计,禁止写代码(CLAUDE.md §2 红线第 6 条)。

### 3. 实现方案

#### 3.1 后端(`backend/src/audit/`)

**模块结构**:
```
backend/src/audit/
├── audit.module.ts
├── audit.controller.ts       # POST /v1/audit/analyze(管理员)
├── audit.service.ts          # 三重校验 + 调度诊断
├── audit-validators.ts       # 包名白名单 + 签名校验 + 目录隔离
└── audit-log.service.ts      # 审计日志(独立表 audit_log_own)
```

**API 端点**:

| 端点 | 方法 | 用途 | 鉴权 |
|---|---|---|---|
| `/v1/audit/analyze` | POST | 上传 APK + 诊断(multipart/form-data) | JWT + ADMIN |
| `/v1/audit/results/:taskId` | GET | 查询诊断结果(诊断完成后保留 24h) | JWT + ADMIN |
| `/v1/audit/apps/:appId/signature` | POST | 配置预期签名 hash | JWT + ADMIN |

**诊断流程**:
```
1. 接收 APK 上传(< 200MB)
2. 计算 APK hash + 大小
3. 解析 AndroidManifest -> 包名
4. 三重校验(见上)
5. 在 /tmp/audit/<taskId>/ 隔离目录:
   a. JADX 反编译(只读查看)
   b. AXMLPrinter2 解析 Manifest
   c. apksigner verify --print-certs
   d. aapt2 dump resources
   e. dexlib2 列出类(不反编译)
   f. SDK 后门扫描(自定义规则)
6. 生成诊断报告(JSON + HTML)
7. 删除 /tmp/audit/<taskId>/
8. 审计日志记录
9. 返回诊断报告
```

#### 3.2 CLI(`injector/src/main/kotlin/com/xcj/injector/audit/`)

**新子命令**:`injector audit`

```bash
# 诊断自有 APK(需先在 admin-web 注册包名 + 配置签名 hash)
injector audit \
  --apk my-app.apk \
  --app-id app-xxx \
  --server-url https://xcj.winmelon.cn \
  --token <admin-jwt>
```

**CLI 流程**:
1. 读取本地 APK
2. 上传到 `/v1/audit/analyze`(带 JWT)
3. 等待诊断完成(轮询 `/v1/audit/results/:taskId`)
4. 下载诊断报告到本地
5. 打开 HTML 报告(可选)

**注**:CLI 不在本地做诊断(避免本地环境差异),统一在后端做(便于审计 + 三重校验统一)。

#### 3.3 安卓端(`injector-android/app/src/main/kotlin/com/xcj/app/ui/AuditTab.kt`)

**新 Tab**:"自有诊断"

- 选择本地 APK(文件选择器)
- 上传到后端(带 JWT)
- 显示诊断进度
- 诊断完成后,展示报告(WebView 渲染 HTML)

**注**:安卓端只做上传 + 展示,不做本地诊断(与 CLI 一致)。

### 4. 审计日志

**独立表**:`audit_log_own`(与现有 `audit_log` 分开,便于专项查询)

```prisma
model AuditLogOwn {
  id            String   @id @default(uuid())
  developerId   String
  appId         String
  apkHash       String   // SHA-256
  apkSize       Int      // bytes
  packageName   String   // 从 Manifest 解析
  signatureHash String   // 从签名块计算
  check1Passed  Boolean  // 包名白名单
  check2Passed  Boolean  // 签名 hash 比对
  check3Passed  Boolean  // 目录隔离(始终 true,记录用)
  status        String   // SUCCESS / REJECTED / FAILED
  rejectReason  String?  // 校验失败原因
  reportPath    String?  // 诊断报告路径(临时,24h 后删除)
  ip            String
  userAgent     String
  createdAt     DateTime @default(now())
}
```

**保留期**:1 年(ADR 0032 审计日志要求)

**日志脱敏**:不记录 APK 内容,只记录 hash + 包名 + 签名 hash(ADR 0027 强制)

### 5. 诊断报告内容

**JSON 报告结构**:
```json
{
  "taskId": "audit-xxx",
  "apkInfo": {
    "packageName": "com.yourcompany.yourapp",
    "versionName": "1.0.0",
    "versionCode": 1,
    "minSdk": 21,
    "targetSdk": 34,
    "signatureHash": "sha256:abc123..."
  },
  "manifest": {
    "permissions": ["android.permission.INTERNET", ...],
    "activities": [...],
    "services": [...],
    "receivers": [...],
    "providers": [...]
  },
  "dexAnalysis": {
    "classCount": 1234,
    "methodCount": 5678,
    "suspiciousClasses": []
  },
  "sdkAudit": {
    "knownSDKs": ["com.google.firebase", "com.tencent.bugly"],
    "suspiciousCalls": [],
    "networkEndpoints": ["https://api.example.com"]
  },
  "securityFindings": {
    "cleartextTraffic": false,
    "debuggable": false,
    "backupEnabled": false,
    "customPermissions": []
  }
}
```

**HTML 报告**:JSON 报告渲染为可读 HTML,含风险等级标注 + 修复建议。

### 6. SDK 后门扫描规则(自定义)

扫描以下可疑模式:
- `System.loadLibrary` 调用(加载可疑 so)
- `DexClassLoader` 调用(动态加载 dex)
- `Runtime.exec` 调用(执行命令)
- 反射调用 `Class.forName` + `getMethod` + `invoke` 组合
- 网络请求到非 HTTPS 端点
- 硬编码 IP 地址
- 读取 IMEI / Android ID / MediaDRM ID(隐私敏感)

**注**:规则不公开(避免被绕过),但扫描结果在报告中展示。

### 7. 资源限制

| 项 | 限制 | 原因 |
|---|---|---|
| APK 大小 | < 200MB | 与 ADR 0028 一致 |
| 并发诊断 | 每开发者最多 1 个 | 服务器资源有限(1C2G) |
| 诊断超时 | 30 分钟 | 自动取消 |
| 报告保留 | 24 小时 | 节省磁盘 |
| 临时目录 | /tmp/audit/<taskId>/ | 隔离 + 即时删除 |

### 8. 与现有 ADR 的关系

| ADR | 关系 |
|---|---|
| 0076(项目定位修订) | 本 ADR 是 0076 方案 B 的功能级实现 |
| 0001(项目定位,已 superseded by 0076) | 不再有效 |
| 0029(加固 APK 兼容性) | 本 ADR 不涉及通用脱壳,0029 仍不接受通用脱壳 |
| 0067(加固 APK MVP 不支持,accepted;其"自动脱壳推 v3"条款被 ADR 0079 部分取代,仅梆梆自检场景) | 0079 仅对梆梆自检场景部分取代 0067 的"自动脱壳推 v3"条款;其他加固方案 + 0067 其他条款仍有效 |
| 0068(v2 注入工具架构) | 本 ADR 不涉及注入,0068 不变;例外 A 签名回填在 `injector audit resign` 子命令内实现(详见 ADR 0078 关联代码) |
| 0078(梆梆加固自检适配器,待创建) | 本 ADR 例外 B 的具体实现 ADR,3 把锁 + 律师前置 |
| 0079(部分取代 0067,待创建) | 仅梆梆自检场景的部分取代,其他加固方案不取代 |
| 0027(服务端安全基线) | 本 ADR 遵守(强制校验 + 日志脱敏) |
| 0032(监控告警) | 本 ADR 审计日志遵守 |
| 0030(防滥用机制) | 本 ADR 不涉及水印,0030 不变;例外 A 签名回填使用 V1+V2+V3(与 0030 一致) |

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| A. 本地诊断(开发者机器跑 JADX) | 无服务器成本 | 无法统一审计 + 校验 | 法律自证清白证据不足 |
| B. 后端诊断 + 三重校验(本方案) | 统一审计 + 强制校验 | 服务器资源占用 | 合规优先 |
| C. 后端诊断无校验 | 简单 | 法律风险高 | 违反 ADR 0076 决策 |
| D. 第三方 SaaS(如 VirusTotal) | 省开发 | 隐私泄露 + 不可控 | 用户 APK 数据外泄 |

## 影响

### 正面影响

- 满足 ADR 0076 方案 B 的功能实现
- 覆盖 2 项成立正当用途(自有 SDK 审计 + 遗产维护)
- 法律风险低(三重校验 + 只读 + 不持久化)
- 与 v2 重构边界一致(不返工)
- 三重校验作为法律自证清白的证据(用户要求)

### 负面影响

- 开发成本:后端模块 + CLI 子命令 + 安卓端 Tab,约 2-3 周
- 服务器资源:JADX 反编译耗 CPU + 内存(1C2G 需排队)
- 用户体验:需先在 admin-web 注册包名 + 配置签名 hash(门槛)

### 风险

- **绕过风险**:开发者上传他人 APK + 配置错误的签名 hash
  - 缓解:签名 hash 配置后需 2FA 确认 + 审计日志记录
- **服务器资源耗尽**:大 APK 反编译耗尽内存
  - 缓解:200MB 限制 + 并发 1 + 30 分钟超时
- **JADX 漏洞**:恶意 APK 利用 JADX 漏洞
  - 缓解:JADX 在 Docker 容器内运行(隔离)+ 定期更新版本

## 关联

- **关联 ADR:**
  - 0076(项目定位修订,本 ADR 是其功能级实现)
  - 0029(加固 APK 兼容性,本 ADR 不涉及)
  - 0067(加固 APK MVP 不支持,本 ADR 不涉及)
  - 0068(v2 注入工具架构,本 ADR 不涉及)
  - 0027(服务端安全基线)
  - 0032(监控告警与日志)
- **关联代码(待实现):**
  - `backend/src/audit/audit.module.ts`
  - `backend/src/audit/audit.controller.ts`
  - `backend/src/audit/audit.service.ts`
  - `backend/src/audit/audit-validators.ts`(三重校验)
  - `backend/src/audit/audit-log.service.ts`
  - `backend/prisma/schema.prisma`(加 AuditLogOwn 表)
  - `injector/src/main/kotlin/com/xcj/injector/audit/AuditCommand.kt`
  - `injector-android/app/src/main/kotlin/com/xcj/app/ui/AuditTab.kt`
  - `admin-web/src/views/Audit.vue`(诊断报告查看页)
- **关联文档:**
  - `CLAUDE.md` 第 2 节(红线:红方功能仅限自有 APK)
  - `docs/compliance/user-agreement.md` 第 3 节(自有 APK 诊断条款)
  - `docs/security.md`(安全白皮书,加自有诊断章节)
- **关联法律**:
  - 《著作权法》第 48 条(本 ADR 通过三重校验规避)
  - 《计算机软件保护条例》第 24 条(本 ADR 通过三重校验规避)
  - 刑法 285 条(本 ADR 不提供通用绕过,不触发)
