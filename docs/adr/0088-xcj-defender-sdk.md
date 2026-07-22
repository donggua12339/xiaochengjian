# ADR 0088 · 自研 xcj-defender-sdk 防守内核

- 状态:accepted(代码实现完成,2026-07-22)
- 日期:2026-07-21(设计)/ 2026-07-22(实现完成)
- 决策者:小城笺项目
- 层次:功能 / 安全
- 关联 ADR:0081(Packer 注入机制)

## 背景

MT/NP 管理器的"防守功能"(签名校验/防调试/防 Hook/防截屏)本质上是在 APK 中植入检测代码。MT/NP 的做法是**修改已有 smali/dex**(侵入式),踩"字节码修改"红线。

小城笺的思路:**不修改已有字节码,而是注入一个独立的、预编译的 SDK**(xcj-defender-sdk),SDK 与业务代码逻辑隔离。注入方式与 xcj-auth-sdk 完全一致(ADR 0081 Packer),复用七锁架构。

## 与 MT/NP 的本质区别

| 维度 | MT/NP | 小城笺(xcj-defender-sdk) |
|---|---|---|
| 注入方式 | 修改已有 smali/dex | 添加独立 dex(Packer 注入) |
| 侵入性 | 高(改业务字节码) | 零(业务字节码不动) |
| 合规 | 灰色(字节码修改) | 合规(ADR 0081 七锁) |
| 通用性 | 任意 APK | 仅自有 APK(三重校验) |
| 可定制 | 用户自定义 smali | 固定 SDK,可选模块开关 |

## 能力映射

### MT/NP 功能 -> xcj-defender-sdk 对应

| MT/NP 功能 | xcj-defender-sdk | 类型 |
|---|---|---|
| 注入签名校验 | `SignatureVerifier` | ✅ 防守(检测签名篡改) |
| 去除签名校验 | ❌ **不做**(进攻性,违反守城军规Ⅰ) | 禁止 |
| 一键 Xposed 检测 | `EnvironmentInspector` | ✅ 防守(检测 Hook 框架) |
| 一键禁止截屏 | `WindowSecurer` | ✅ 防守(FLAG_SECURE) |
| 去除弹窗/对话框 | ❌ **不做**(干扰应用,进攻性) | 禁止 |
| APK 伪加密 | `IntegrityChecker` | ✅ 防守(CRC/Hash 校验) |
| 控制流混淆 | SDK 自身混淆 | ✅ 防守(防逆向 SDK 本身) |
| 防调试 | `AntiDebug` | ✅ 防守(ptrace 检测) |
| 防 Frida | `AntiFrida` | ✅ 防守(端口/线程检测) |
| 防 Dump | `AntiDump` | ✅ 防守(/proc/self/maps 监控) |
| Root 检测 | `RootDetector` | ✅ 防守(su/Magisk 检测) |
| 模拟器检测 | `EmulatorDetector` | ✅ 防守(硬件特征) |

## 技术架构

### Java 层

```
xcj-defender-sdk/src/main/java/com/xcj/defender/
├── DefenderInit.java           # 初始化入口(attachBaseContext / ContentProvider)
├── SignatureVerifier.java      # 签名哈希校验
├── EnvironmentInspector.java   # Root/Xposed/模拟器检测
├── WindowSecurer.java          # 防截屏(FLAG_SECURE)
├── IntegrityChecker.java       # APK 完整性校验(CRC/Hash)
└── DefenderConfig.java         # 配置(哪些模块开启)
```

### Native 层(C/C++)

```
xcj-defender-sdk/src/main/cpp/
├── anti_debug.cpp              # ptrace 反调试
├── anti_frida.cpp              # Frida 检测(端口 27042 / 线程名)
├── anti_dump.cpp               # /proc/self/maps 监控
├── integrity_native.cpp        # Native 层 APK 完整性校验
└── defender_jni.cpp            # JNI 桥接
```

### 初始化流程

```
APK 启动
  ↓
Application.attachBaseContext()
  ↓
DefenderInit.init(context, config)
  ├── SignatureVerifier.verify()     // 签名校验(锁 7 客户端签名自检)
  ├── AntiDebug.start()              // ptrace 反调试
  ├── AntiFrida.scan()               // Frida 检测
  ├── EnvironmentInspector.check()   // Root/Xposed/模拟器
  └── IntegrityChecker.verify()      // APK 完整性
  ↓
检测结果异常 -> 按配置响应(退出/告警/上报)
  ↓
原 Application.onCreate() 继续执行
```

### 模块开关(DefenderConfig)

开发者通过 admin-web 勾选启用哪些防守模块:

```json
{
  "signatureVerify": true,       // 签名校验
  "antiDebug": true,             // 反调试
  "antiFrida": true,             // 防 Frida
  "antiDump": false,             // 防 Dump(可选,有性能影响)
  "rootDetect": true,            // Root 检测
  "emulatorDetect": true,        // 模拟器检测
  "xposedDetect": true,          // Xposed 检测
  "secureScreen": true,          // 防截屏
  "integrityCheck": true,        // 完整性校验
  "onViolation": "exit"          // 响应方式:exit(退出)/warn(告警)/report(上报)
}
```

## 与 ADR 0081 Packer 的集成

### 注入方式

xcj-defender-sdk 编译为 `classes-defender.dex`,与 `classes-xcj.dex`(auth-sdk)并列注入:

```
Packer 封装流程:
  1. 三重校验(锁 1)
  2. 注入 classes-xcj.dex(auth-sdk,锁 2 白名单)
  3. 注入 classes-defender.dex(defender-sdk,独立白名单)
  4. Manifest 加 DefenderInit ContentProvider(锁 3)
  5. 自备 Keystore 重签(锁 4)
  6. 客户端签名自检(锁 7)
```

### 白名单

`XCJ_DEFENDER_SDK_DEX_WHITELIST` 与 `XCJ_AUTH_SDK_DEX_WHITELIST` 独立,每次 SDK 版本更新时同步。

## 合规性

### 红线检查

| 守城军规 | xcj-defender-sdk |
|---|---|
| Ⅰ 禁止通用脱壳 | ✅ 不脱壳,SDK 是防守检测 |
| Ⅱ 禁止非授权重打包 | ✅ 仅自有 APK(Packer 七锁) |
| Ⅲ 禁止越界操作 | ✅ SDK 代码固定,不含逆向中间产物 |
| Ⅳ 禁止伪装身份 | ✅ 自备 Keystore(锁 4) |

### 与 ADR 0081 的关系

xcj-defender-sdk 是 ADR 0081 Packer 的**第二个注入物**(第一个是 xcj-auth-sdk)。两者并列注入,共用七锁架构,不改变 Packer 的任何合规约束。

### 不做的事

- ❌ **去除签名校验**(进攻性,违反守城军规Ⅰ)
- ❌ **去除弹窗/对话框**(干扰应用,进攻性)
- ❌ **绕过其他应用的防护**(SDK 仅保护宿主 APK)
- ❌ **通用脱壳/反编译**(违反 ADR 0077)

## 影响

### 正面影响

- 将 MT/NP 的防守功能转化为合规 SDK,形成差异化优势
- 与 xcj-auth-sdk 形成生态绑定(开发者同时用两个 SDK)
- Native 层反调试/防 Frida 是对抗脱壳的核心,高价值

### 负面影响

- Native 层(C/C++)开发量较大(JNI + NDK 交叉编译)
- 反调试/防 Frida 需持续更新(对抗新版本工具)
- 可能有性能影响(antiDump 需监控 /proc/self/maps)

### 风险

- **误报**:Root 检测/模拟器检测可能误判合法用户
  - 缓解:配置 `onViolation: "warn"` 而非 `"exit"`,开发者自行判断
- **兼容性**:Native 层反调试可能影响某些设备的正常调试
  - 缓解:Debug 构建默认关闭,Release 构建默认开启

## 开发计划

| 阶段 | 内容 | 工作量 |
|---|---|---|
| Phase 1 | Java 层:SignatureVerifier + EnvironmentInspector + WindowSecurer | 3-5 天 |
| Phase 2 | Native 层:AntiDebug(ptrace)+ AntiFrida(端口检测) | 5-7 天 |
| Phase 3 | Native 层:AntiDump + IntegrityChecker(CRC/Hash) | 3-5 天 |
| Phase 4 | Packer 集成 + admin-web 配置 UI + 测试 | 3-5 天 |
| **总计** | | **2-3 周** |

## 关联

- 0081(Packer 注入机制,本 SDK 通过 Packer 注入)
- 0077(自有 APK 诊断,三重校验复用)
- 0076(项目定位,纯防守向)
- 0087(深度安全审计,defender-sdk 的检测结果可作为审计输入)