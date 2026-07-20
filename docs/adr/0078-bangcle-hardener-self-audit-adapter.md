# ADR 0078 · 梆梆加固自检适配器(自有 APK 诊断例外 B 的实现)

- 状态:proposed(律师前置,代码未实现)
- 日期:2026-07-20
- 决策者:小城笺项目
- 层次:功能 / 安全 / 合规
- Supersedes: ADR 0067(partial,仅"自动脱壳推 v3"条款,仅梆梆自检场景;详见 ADR 0079)

## 背景

ADR 0077 例外 B 允许在严格约束下做梆梆加固层自检。本 ADR 定义该适配器的具体边界、技术实现、3 把锁和律师前置流程。

**核心约束(ADR 0077 例外 B + 用户决策)**:
> 梆梆加固自检适配器是唯一允许的加固层自检目标,360 / 爱加密 / 乐固 / 腾讯乐固等其他加固方案明确不支持。
> 适配器带 3 把锁:仅梆梆一家 / EULA 前置 / 仅完整性报告。
> 开发必须先过律师,法律意见未落地前不写代码。

## 决策

### 1. 功能边界

**允许的能力(自有梆梆加固 APK 自检)**:

| 能力 | 说明 | 实现路径 |
|---|---|---|
| 加固层完整性扫描 | 扫描梆梆 so 列表 + 梆梆特有 API 调用 | libNative.so / libSecShell.so / libDexHelper.so 等梆梆 so 特征匹配 |
| so 文件完整性报告 | 列出加固 so 的 SHA-256 + 大小 + 加载路径 | 文件级哈希,不脱壳 |
| 可疑 API 扫描 | 扫描梆梆 hook 入口(reflective load / native_bridge) | 静态规则,不运行 |
| META-INF 签名验证 | 验证梆梆加固后的 APK 签名完整性 | apksigner verify --print-certs |

**禁止的能力(红线)**:

- ❌ 通用脱壳(从加固 APK 还原 dex,FRIDA-DEXDump 类)
- ❌ 反编译加固 so 还原原始代码(IDA / Ghidra 还原)
- ❌ 动态运行加固 APK(模拟器/真机都不做)
- ❌ 输出反编译源码(锁 C 强制)
- ❌ 360 / 爱加密 / 乐固 / 腾讯乐固等其他加固方案(锁 A 强制)
- ❌ 绕过梆梆自身校验逻辑(只读扫描,不修改)

### 2. 三把锁(核心约束)

#### 锁 A:仅梆梆一家

- 适配器仅识别梆梆加固特征(so 名称 / 加固入口 / native bridge 模式)
- 检测到非梆梆加固 -> 返回 `UNSUPPORTED_HARDENER`,拒绝诊断
- 已知不支持的加固厂商(明确拒绝列表):
  - 360 加固(360 Jiagu)
  - 爱加密(Ijiami)
  - 腾讯乐固(Tencent Legu)
  - 百度加固(Baidu)
  - 通付盾(Mobifree)
  - 娜迦(Nagain)
  - 其他厂商一律不支持
- 锁 A **不可扩展**:扩展支持其他厂商必须新建 ADR 并与用户 + 律师确认

#### 锁 B:EULA 前置

- admin-web 的"自有诊断"页面新增 EULA 勾选区域
- EULA 内容(摘要):
  - 声明 APK 为开发者自有(具有合法著作权或授权)
  - 声明不用于绕过梆梆自身保护机制
  - 知悉工具只做完整性报告,不脱壳不反编译
  - 同意审计日志记录
- EULA 未勾选 -> `audit` 子命令的 `--hardener bangcle` 选项不可用,返回 `EULA_REQUIRED`
- EULA 勾选状态记入 `audit_log_own`(`eulaAccepted=true`)
- EULA 文本由 `docs/compliance/audit-eula.md` 维护,版本号变化需重新勾选

#### 锁 C:仅完整性报告

- 适配器输出格式为 JSON 报告,字段限定:
  ```json
  {
    "hardener": "bangcle",
    "integrity": {
      "soFiles": [
        { "name": "libSecShell.so", "sha256": "...", "size": 1234567, "loadPath": "/lib/arm64-v8a/" }
      ],
      "entryClass": "com.bangcle.test.MainApplication",
      "signatures": { "v1": true, "v2": true, "v3": true }
    },
    "suspiciousCalls": [
      { "type": "NATIVE_LOAD", "symbol": "loadLibrary", "count": 12 }
    ],
    "scanVersion": "1.0.0",
    "scanTime": "2026-07-20T12:00:00Z"
  }
  ```
- **不输出**:反编译 Java 源码、smali、dex 类列表(对加固 so 不做反编译)
- **不输出**:梆梆内部密钥 / 算法实现
- 报告生成后立即从 `/tmp/audit/<taskId>/` 删除中间产物(与 ADR 0077 校验 3 一致)

### 3. 实现方案(代码在律师意见落地后才写)

#### 3.1 后端(`backend/src/audit/hardener/`)

```
backend/src/audit/hardener/
├── bangcle.adapter.ts       # 梆梆适配器(扫描 so + API)
├── hardener-detector.ts     # 加固厂商识别(so 特征匹配)
├── hardener-eula.service.ts # EULA 状态管理
└── hardener-report.ts       # 报告生成(锁 C 字段限定)
```

**API 端点**(在 ADR 0077 的 `/v1/audit/analyze` 上扩展):

| 端点 | 方法 | 用途 | 鉴权 |
|---|---|---|---|
| `/v1/audit/analyze` | POST | 加 `?hardener=bangcle` query 触发适配器 | JWT + ADMIN + EULA |
| `/v1/audit/eula` | GET | 获取当前 EULA 文本 + 版本 | JWT + ADMIN |
| `/v1/audit/eula/accept` | POST | 接受 EULA(版本号绑定) | JWT + ADMIN |

#### 3.2 CLI(`injector/src/main/kotlin/com/xcj/injector/audit/`)

```bash
# 诊断自有梆梆加固 APK(需先在 admin-web 接受 EULA)
injector audit \
  --apk my-app.apk \
  --app-id app-xxx \
  --hardener bangcle \
  --server-url https://xcj.winmelon.cn \
  --token <admin-jwt>
```

#### 3.3 安卓端(`injector-android`)

- "自有诊断" Tab 加"加固厂商"下拉(默认"无加固",可选"梆梆")
- 选梆梆 -> 弹 EULA 弹窗,勾选后才允许上传

#### 3.4 数据库

`AuditLogOwn` 表(ADR 0077 §4)新增字段:

```prisma
model AuditLogOwn {
  // ... 原有字段
  hardener     String?  // "bangcle" / null(无加固)
  eulaVersion  String?  // EULA 版本号(梆梆场景必填)
  eulaAccepted Boolean? // 梆梆场景必填
}
```

### 4. 检测规则(梆梆特征,部分公开)

公开特征(便于审计):
- so 文件名匹配:`libSecShell.so` / `libDexHelper.so` / `libNative.so`(梆梆历史命名)
- Application 类名前缀:`com.bangcle.` / `com.secapk.`(梆梆 wrapper)
- AndroidManifest 中 `<meta-data android:name="com.bangcle.*">` 标签

不公开特征(避免被绕过):so 文件内部结构指纹(限于篇幅,规则内部维护)。

### 5. 律师前置(强制流程)

**本 ADR 代码实现的硬前置**:

1. 用户聘请律师出具法律意见书,明确:
   - 梆梆加固自检(仅完整性扫描,不脱壳不反编译)是否构成《著作权法》第 48 条规避技术措施
   - EULA 条款是否有法律效力
   - 审计日志保留是否符合个保法
2. 律师意见书存档路径(不入库,与 SSH 凭证同等级保密):用户保管,路径记入 memory `reference_xiaochengjian_legal_opinion.md`(待用户创建)
3. 律师意见**通过**后:本 ADR 状态改为 `accepted`,允许写代码
4. 律师意见**未通过**:本 ADR 改为 `rejected`,删除例外 B,ADR 0077 例外 B 标注"未启用"
5. 律师意见**部分通过**(有限制条件):本 ADR 改为 `accepted with conditions`,按条件调整约束

**在律师意见落地前**:
- 本 ADR 保持 `proposed`
- 禁止写任何代码(`backend/src/audit/hardener/` 目录不创建)
- 禁止在 admin-web 加 EULA 勾选 UI
- 禁止在 CLI 加 `--hardener bangcle` 选项

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| A. 不做加固自检 | 无法律风险 | 自有梆梆 APK 无法诊断 | 用户要求做 |
| B. 通用加固自检(不限厂商) | 灵活 | 法律风险高 | 违反锁 A |
| C. 本方案(仅梆梆 + 3 把锁 + 律师前置) | 合规可控 | 开发成本 | 用户决策 |
| D. 第三方加固检测 SaaS | 省开发 | 隐私泄露 + 不可控 | 用户 APK 数据外泄 |

## 影响

### 正面影响

- 覆盖自有梆梆加固 APK 诊断场景(成立正当用途之一)
- 3 把锁限制法律风险
- 与 ADR 0077 三重校验兼容
- 律师前置确保合规

### 负面影响

- 开发成本:适配器 + EULA UI + 报告生成,约 1-2 周
- 仅梆梆一家,其他加固用户需自行脱壳后再诊断(但工具不提供脱壳)
- 律师意见落地前无法开发

### 风险

- **梆梆厂商投诉风险**:适配器扫描梆梆 so 可能被视为逆向梆梆本身
  - 缓解:仅文件级哈希 + 公开 so 名,不反编译 so;EULA 声明不绕过梆梆保护;律师意见书背书
- **EULA 法律效力不足**:用户勾选 EULA 后仍起诉
  - 缓解:EULA 文本由律师审核;勾选状态记入审计日志作为证据
- **检测规则失效**:梆梆更新加固方式导致检测不到
  - 缓解:扫描版本号 `scanVersion` 记入报告,定期更新公开特征

## 关联

- **关联 ADR:**
  - 0077(自有 APK 诊断,本 ADR 是其例外 B 的实现)
  - 0079(部分取代 0067,本 ADR 的功能前提)
  - 0067(加固 APK MVP 不支持,本 ADR 仅对梆梆场景部分取代)
  - 0029(加固 APK 兼容性,本 ADR 不涉及通用脱壳)
  - 0027(服务端安全基线,本 ADR 遵守)
  - 0030(防滥用机制,EULA + 审计日志同源)
- **关联代码(待实现,律师意见落地后才可写)**:
  - `backend/src/audit/hardener/bangcle.adapter.ts`
  - `backend/src/audit/hardener/hardener-detector.ts`
  - `backend/src/audit/hardener/hardener-eula.service.ts`
  - `backend/src/audit/hardener/hardener-report.ts`
  - `backend/prisma/schema.prisma`(AuditLogOwn 加字段)
  - `injector/src/main/kotlin/com/xcj/injector/audit/BangcleAdapter.kt`
  - `injector-android/app/src/main/kotlin/com/xcj/app/ui/AuditTab.kt`(加固厂商下拉 + EULA 弹窗)
  - `admin-web/src/views/Audit.vue`(EULA 勾选区域)
  - `docs/compliance/audit-eula.md`(EULA 文本)
- **关联文档**:
  - `CLAUDE.md` 第 2 节(红线:例外 B)
  - `docs/compliance/user-agreement.md` 第 3 节(自有诊断条款)
  - `docs/security.md`(加梆梆适配器章节)
- **关联法律**:
  - 《著作权法》第 48 条(规避技术措施,需律师判断是否触发)
  - 《计算机软件保护条例》第 24 条(同上)
  - 《个人信息保护法》(审计日志合规)
  - 刑法 285 条(本 ADR 不提供通用绕过,不触发)
