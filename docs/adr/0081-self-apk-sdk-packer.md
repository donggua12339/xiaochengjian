# ADR 0081 · 自有 APK 的 xcj-auth-sdk 封装器(Packer 模块)

- 状态:accepted(律师预审通过,2026-07-21,综合评级 🟡 中低,附 3 项硬约束)
- 日期:2026-07-21
- 决策者:小城笺项目
- 层次:功能 / 安全 / 合规
- 回退方案:ADR 0080(SDK 源码级集成,零字节码修改)
- 律师预审案号:XCJ-ADR0081-2026

## 背景

### 问题

ADR 0080(SDK 源码级集成)是卡密鉴权的默认方式,但无法覆盖以下场景:

1. **无源码的遗产 APK**:开发者持有已编译的 .apk 文件,但丢失了源码或无法重新编译
2. **无 Android Studio 环境**:开发者不具备 Android 开发环境,无法编译集成 SDK
3. **第三方 SDK 依赖**:原 APK 依赖的第三方 SDK 无法在新环境中重新编译

这些开发者需要一种方式,为自有 APK 增加卡密鉴权能力,而无需源码。

### 定位

本功能**不是"通用注入工具"**,而是"云端版自有 APK 的 SDK 打包器":

- **对象**:仅限于通过三重校验(包名白名单 + 签名 Hash + tmp 隔离)的开发者自有 APK
- **内容**:仅注入固定的 `classes-xcj.dex`(xcj-auth-sdk 编译产物),不修改原 APK 既有 dex 的业务逻辑
- **目的**:帮助无 Android Studio 环境或持有遗产 APK 的开发者,为其自有软件增加卡密鉴权和后台管理能力

### 与 ADR 0076 方案 B 的关系

本提案不推翻 ADR 0076 方案 B 的"规避刑事风险"原则,而是在"自有 APK"这一安全域内,补全创作者对其资产的商业化管控能力。六锁合规架构确保不具备"通用性"和"侵入他人"的属性。

## 决策

### 六锁合规架构

沿用 ADR 0077/0078 的旧三锁,新增三把技术锁:

| 锁 | 名称 | 类型 | 约束 |
|---|---|---|---|
| 1 | 对象锁定 | 旧(ADR 0077) | 三重校验强制通过,拒绝处理未知或非自有 APK |
| 2 | 内容锁定 | 新 | 注入内容仅为 xcj-auth-sdk 的固定 dex 文件;不允许自定义 smali,不允许插入非 SDK 逻辑 |
| 3 | 入口锁定 | 新 | Manifest 修改仅限于 Application 委托模式(改父类)或配置 xcj 专用 Meta-data,不改变原应用的交互逻辑 |
| 4 | 签名锁定 | 新 | 封装后强制使用开发者在后台备案的自备 Keystore 进行 V1/V2/V3 重签;小城笺不提供通用签名 |
| 5 | 权限锁定 | 新 | 后台"禁用/改规则"等控制操作仅限开发者账号自身 JWT 触发;平台管理员仅可读(审计),不可写 |
| 6 | 数据锁定 | 新 | SDK 仅上报匿名化设备标识(OAID)和包信息,不采集通讯录、位置等敏感隐私 |
| 7 | **客户端签名自检(律师预审新增)** | **新** | **SDK 初始化时自检当前 APK 签名 hash 是否与 xcj_app_id 备案一致,不一致直接拒启(PACKAGE_TAMPERED);把"专门性"焊死到客户端侧,服务端+客户端双重锁,刑法 285 第三款"专门性"抗辩闭环** |

锁 7 是律师预审(2026-07-21)要求的**硬约束**,把"专门性"抗辩从服务端(三重校验)延伸到客户端(签名自检),防止 packer 输出的 APK 被二次修改后用于他人 APK。

### 与现有红方工具的本质区别

| 维度 | 小纸片/Arm Pro | 本提案(ADR 0081) |
|---|---|---|
| 对象 | 任意第三方 APK | 仅限开发者自有 APK(三重校验) |
| 内容 | 任意 smali/弹窗/过签 | 仅固定 xcj-auth-sdk(单一用途) |
| 签名 | 通用或作者提供 | 强制开发者自备 Keystore |
| 法律基础 | 处于灰色地带,风险自担 | 开发者侧:条例 17(改自有包);小城笺侧:工具中立性(类比 AS / 云打包)+ 刑法 285 不勾(六锁+客户端自检) |
| 审计 | 无 | 完整审计日志(每次封装操作记录) |

### Packer 模块架构

```
backend/src/packer/
├── packer.module.ts              # 模块注册
├── packer.controller.ts          # API 端点
├── packer.service.ts             # 封装主流程(六锁校验 + dex 注入 + 重签)
├── packer-validators.ts          # 六锁校验逻辑
├── dex-injector.ts               # dex 注入(ASM/dexlib2 改 superclass + 注入 classes-xcj.dex)
├── manifest-patcher.ts           # Manifest 修改(Application 委托 + Meta-data)
├── multidex-handler.ts           # MultiDex 兼容(检测原 APK Dex 结构)
└── packer-log.service.ts         # 封装审计日志
```

### 封装流程

```
1. 上传 APK + Keystore + 凭证
2. 锁 1(对象锁定):三重校验(包名白名单 + 签名 Hash + tmp 隔离)
3. 锁 2(内容锁定):验证注入内容为固定 classes-xcj.dex(SHA-256 白名单)
4. 锁 3(入口锁定):Manifest 修改仅限 Application 委托或 Meta-data
5. dex 注入:
   a. 反编译 APK(apktool / dexlib2)
   b. 检测 MultiDex 结构
   c. 注入 classes-xcj.dex
   d. 修改原 Application 的 superclass 为 XcjApplication
   e. 修改 AndroidManifest.xml(Application 类名 + Meta-data)
   f. 重打包
6. 锁 4(签名锁定):用开发者自备 Keystore V1+V2+V3 重签
7. 锁 5(权限锁定):验证 JWT(仅开发者自身可触发)
8. 锁 6(数据锁定):SDK 配置仅含 OAID + 包信息
9. 返回封装后 APK + 审计日志
```

### API 端点

| 端点 | 方法 | 作用 | 鉴权 |
|---|---|---|---|
| `/v1/packer/pack` | POST | 上传 APK + Keystore,执行封装 | JWT + 开发者自身 |
| `/v1/packer/status/:taskId` | GET | 查询封装状态 | JWT + 开发者自身 |
| `/v1/packer/download/:taskId` | GET | 下载封装后 APK | JWT + 开发者自身 |
| `/v1/packer/logs` | GET | 查询封装历史 | JWT + 开发者自身 |

### 审计日志字段

`packer_log` 表:

| 字段 | 类型 | 说明 |
|---|---|---|
| id | String | 主键 |
| developerId | String | 开发者 ID |
| appId | String | 应用 ID |
| apkHash | String | 原 APK SHA-256 |
| apkSize | Int | 原 APK 大小 |
| packageName | String | 包名 |
| signatureHash | String | 原签名 SHA-256 |
| check1Passed | Boolean | 包名白名单 |
| check2Passed | Boolean | 签名 Hash 比对 |
| check3Passed | Boolean | 目录隔离 |
| contentLockPassed | Boolean | 内容锁定(注入内容 SHA-256 白名单) |
| entryLockPassed | Boolean | 入口锁定(Manifest 修改范围) |
| signLockPassed | Boolean | 签名锁定(自备 Keystore) |
| dexInjected | Boolean | 是否成功注入 dex |
| multidexHandled | Boolean | MultiDex 兼容处理 |
| resignedApkHash | String | 重签后 APK SHA-256 |
| keystoreFingerprint | String | Keystore 指纹(SHA-256,不存密码) |
| status | String | SUCCESS / REJECTED / FAILED |
| rejectReason | String? | 拒绝原因 |
| ip | String | 请求 IP |
| userAgent | String? | UA |
| createdAt | DateTime | 创建时间 |

### 技术实现要点

#### 1. Application 适配("改父类"模式)

采用 ASM/dexlib2 修改原 Application 类的 superclass 为 `XcjApplication`:

```
原:MyApp extends Application
改:MyApp extends XcjApplication extends Application
```

- XcjApplication 在 `onCreate()` 中先执行 SDK 鉴权,再调用 `super.onCreate()`(即原 MyApp 的逻辑)
- 原 Application 的生命周期逻辑完整执行,SDK 鉴权在父类优先执行
- 如果原 APK 没有自定义 Application(直接用 android.app.Application),则 Manifest 中直接配置 XcjApplication

**安全性论证**:
- 仅修改 superclass 指针,不修改原 Application 的任何方法体
- 原 Application 的 `onCreate()` / `onTerminate()` 等生命周期方法完整保留
- XcjApplication 仅在 `onCreate()` 开头插入 SDK 初始化逻辑,不改变原应用的交互逻辑
- 如果原 Application 有 `attachBaseContext()`,XcjApplication 也需正确委托

#### 2. MultiDex 兼容

封装器需检测原 APK 的 Dex 结构:

- **单 Dex**:直接添加 `classes-xcj.dex` 为 `classes2.dex`
- **MultiDex**:检测现有 dex 数量,添加为 `classesN.dex`(N = 现有数量 + 1)
- **确保 MultiDex.install() 被调用**:如果原 APK 未使用 MultiDex,需在 XcjApplication 的 `attachBaseContext()` 中调用 `MultiDex.install()`

**无损性论证**:
- 仅添加新的 dex 文件,不修改原有 dex 文件的内容
- MultiDex 是 Android 官方支持的机制,不影响原 APK 功能
- 如果原 APK 已使用 MultiDex,新增 dex 自动被加载

#### 3. 后台控制逻辑

- 控制流的主体是开发者(通过 admin-web 操作)
- 小城笺仅提供 API 通道
- SDK 的行为是"执行开发者预设的鉴权规则",而非"小城笺远控用户设备"
- 锁 5(权限锁定):平台管理员仅可读(审计),不可写(不能修改开发者的鉴权规则)

### 内容锁定实现(锁 2)

注入的 `classes-xcj.dex` 是 xcj-auth-sdk 的固定编译产物:

- SHA-256 白名单:每次 SDK 版本更新时,更新白名单
- 不允许自定义 smali:API 不接受用户上传的 dex/smali 文件
- 不允许插入非 SDK 逻辑:dex 注入器仅从白名单中选择固定的 classes-xcj.dex

### 入口锁定实现(锁 3)

Manifest 修改仅限:

1. **Application 委托模式**:修改 `<application android:name="...">` 为 XcjApplication(或改原 Application 的 superclass)
2. **Meta-data 配置**:添加 `<meta-data android:name="xcj.appId" android:value="..." />` 等 SDK 配置
3. **权限声明**:添加 `<uses-permission android:name="android.permission.INTERNET" />`(SDK 必需)

**不允许**:
- ❌ 修改 Activity/Service/Receiver/Provider 的类名或属性
- ❌ 添加新的 Activity/Service/Receiver/Provider
- ❌ 修改 intent-filter
- ❌ 修改 UI 相关属性(theme / label / icon)

## 律师预审结果(2026-07-21,案号 XCJ-ADR0081-2026)

**律师预审已通过,综合风险评级 🟡 中低,可推进,但需满足以下 3 项硬约束。**

### Q1:刑法 285 第三款"侵入工具"风险

- **评估**:🟡 中低(六锁 + 自有 + 工具中立)
- **结论**:"自有 + 固定 SDK + 自备签 + 六锁 + 客户端签名自检"架构下,构成 285 第三款"侵入工具"的概率较低,与 MT 管理器/NP 管理器(多年未触 285)属同类合规水位
- **硬约束 1**:加锁 7(客户端签名自检,PACKAGE_TAMPERED 拒启),把"专门性"焊死到客户端侧
- **硬约束 2**:正式法律意见书让律师写明"参考 MT/NP 类案"做类比
- **硬约束 3**:会员获利规模控制在"情节不严重"档(< 5 万/年,具体数额以司法解释最新版为准)

### Q2:《计算机软件保护条例》第 17 条适用性

- **评估**:🟢 低(开发者侧直接适用)/ 🟡 中(小城笺侧靠工具中立性)
- **结论**:条例 17 不能直接作为小城笺的免责盾,但能作为"开发者侧行为合法"的依据,进而支撑"小城笺作为工具提供方的中立性"
- **法条组合**:
  - 开发者侧:条例 17(改自有包的正当性)
  - 小城笺侧:工具中立性(类比 AS / 云打包平台)+ 刑法 285 不勾(自有+六锁+客户端自检)
- **建议**:律师意见书不要把"商业化封装"直接写"条例 17 兜底",写成"开发者侧可援引条例 17,小城笺作为工具方的中立性由六锁+客户端自检支撑"

### Q3:与 ADR 0076 方案 B 兼容性

- **评估**:🟢 兼容(在"自有"安全域内的有限扩展)
- **结论**:0076 方案 B 禁的是"通用红方"(通用脱壳/通用去签/通用注入),0081 的六锁架构已将"通用性"掐死(对象自有 + 内容固定 + 自备签),与 0076 "切割通用注入"原则不冲突
- **回应口径**(律师写进意见书):"0076 方案 B 的'第一优先级'指'不与通用红方工具卷刑事风险'。0081 的六锁架构已将'通用性'掐死,与 0077/0078 同属'蓝方-自有'安全域,风险等级仍低于通用注入工具 1-2 档。0076 未被推翻,0081 是其'自有'安全域内的有限扩展。"

### 综合风险评级表

| 风险项 | 等级 | 缓释 |
|---|---|---|
| 刑法 285 第三款 | 🟡 中低 | 六锁 + 客户端自检 + MT/NP 类比 + 会员规模控档 |
| 著作权法 48 / 条例 24(避开技术措施) | 🟢 低 | 自有 APK + 自备签,加固 APK 走 0078 EULA 前置 |
| 条例 17 适用性(开发者侧) | 🟢 低 | 直接适用 |
| 条例 17 适用性(小城笺侧,工具方) | 🟡 中 | 靠"工具中立 + MT/NP 类比"支撑,不直接兜 |
| 加固厂商 EULA(梆梆等) | 🟡 中 | 0078 已处理(EULA 前置 + 仅梆梆 + 不出 dex) |
| 刑法 285 "专门性"抗辩 | 🟡 中 | 六锁 + 客户端自检 + MT/NP 类比 |

**整体评级:🟡 中低风险,可推进,但需律师正式意见书 + 客户端加锁 7 + 会员规模控档。**

## 前置合规检查(强制)

**ADR 0081 进入开发阶段前,必须完成知识产权律师咨询**,重点确认:

1. **"自有 APK + 固定 SDK + 自备签名"模式对刑法 285 条的规避有效性**
   - 刑法 285 条:提供侵入、非法控制计算机信息系统程序、工具罪
   - 需确认:限定为"自有 APK"的封装工具是否构成"侵入工具"
   - 需确认:六锁架构是否足以排除"通用性"

2. **《计算机软件保护条例》第 17 条的适用范围**
   - 需确认:商业化封装工具是否适用"兼容性/功能性修改"条款
   - 需确认:是否需要额外的软件著作权登记

3. **与 ADR 0076 方案 B 的兼容性**
   - 需确认:APK 级封装是否与"切割与通用注入的关联"原则兼容
   - 需确认:六锁架构是否足以切割与"小纸片/Arm Pro"类工具的关联

## 风险熔断

**若律师评估认为 APK 级封装风险不可控,则自动回退至 ADR 0080(源码级集成),不强行推进。**

回退条件(任一满足即触发):
1. 律师认为刑法 285 条风险不可排除
2. 律师认为《计算机软件保护条例》第 17 条不适用
3. 律师认为与 ADR 0076 方案 B 不兼容
4. 律师建议不推进 APK 级封装

回退后:
- ADR 0081 状态改为 `rejected`
- ADR 0077 例外条款(指向 ADR 0081)删除
- CLAUDE.md §2 例外条款删除
- 已开发的 Packer 模块代码删除或归档

## 备选方案

| 方案 | 说明 | 不选原因 |
|---|---|---|
| A. 仅源码级集成(ADR 0080) | 零字节码修改 | 无法覆盖无源码场景 |
| B. APK 级封装(本方案) | 修改已编译 APK | 法律风险高,需律师前置 |
| C. 两者并存(推荐) | 源码级为主,APK 级为补充 | 需律师确认 B 的可行性 |
| D. 不做 APK 级封装 | 放弃遗产 APK 场景 | 丧失部分用户 |

## 影响

### 正面影响

- 填补"遗产 APK 商业化"的工具空白
- 将"卡密/鉴权"核心需求纳入蓝方合规框架
- 与 ADR 0078(梆梆自检)形成闭环:先自检加固包,再 SDK 封装

### 负面影响

- 法律风险高(需律师前置)
- 技术复杂度高(ASM/dexlib2 + MultiDex + Manifest 修改)
- 与 ADR 0077 禁止能力冲突(需加例外条款)
- 与 ADR 0068 冲突(v2 移除了 dex 注入,需说明是限定例外)

### 风险

- **刑法 285 条风险**:APK 级封装工具可能被认定为"侵入工具"
  - 缓解:六锁架构 + 律师前置 + 风险熔断
- **工具滥用风险**:即使限定"自有 APK",工具可能被用于非自有 APK
  - 缓解:三重校验强制 + 审计日志 + 签名锁定(自备 Keystore)
- **技术兼容性风险**:改 superclass + MultiDex 可能影响原 APK 功能
  - 缓解:仅修改 superclass 指针,不修改方法体;MultiDex 是官方机制

## 关联

- **关联 ADR**:
  - 0076(项目定位,本 ADR 不推翻方案 B)
  - 0077(自有 APK 诊断,本 ADR 需加例外条款)
  - 0078(梆梆自检,与本 ADR 形成闭环)
  - 0080(SDK 源码级集成,本 ADR 的回退方案)
  - 0068(v2 注入工具架构,本 ADR 是限定例外)
  - 0030(防滥用机制,签名 + 水印)
- **关联代码(待实现,律师前置)**:
  - `backend/src/packer/`(Packer 模块)
  - `sdk-android/kotlin/xcj-sdk/`(xcj-auth-sdk,编译为 classes-xcj.dex)
  - `admin-web/src/views/Packer.vue`(封装 UI)
  - `injector/src/main/kotlin/com/xcj/injector/packer/`(CLI 封装命令)
- **关联文档**:
  - `CLAUDE.md` §2(红线例外)
  - `docs/sdk-integration.md`(集成指南)
  - `docs/compliance/packer-eula.md`(封装 EULA,待起草)
