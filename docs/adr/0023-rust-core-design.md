# ADR 0023 · Rust 核心模块设计

- 状态:**superseded by 0071**(9 项子决策中 5 项修订,4 项保留)
- 日期:2026-07-13
- 决策者:小城笺项目
- 层次:安全

> **本 ADR 已被 [ADR 0071](0071-rust-core-design-revision.md) 取代**(2026-07-19)。
> 修订内容:模块清单从 9 个减至 6 个(撤除 anti_debug / vm_detect / obfuscation);JNI 默认语义化命名(opaque-jni 改为可选 feature);允许 JString;撤除 .text 段自校验(见 ADR 0069);常量混淆改用 obfstr(optional)。
> 保留内容:输入校验在 Rust 内 / 错误码而非异常 / 测试覆盖率 ≥ 90%。
> 本文档保留作为决策追溯,不再有效。

## 背景

开源 + SaaS 双模式下,Rust so 是客户端安全的最后防线。设计不当会让 Rust 退化为"难一点的 Java"。

## 决策

### Rust 核心模块职责

| 模块 | 功能 |
|---|---|
| `machine_id` | 机器码生成(ADR 0016) |
| `crypto` | RSA + AES-256-GCM 加解密(ADR 0020) |
| `signing` | HMAC-SHA256 签名(ADR 0021) |
| `card_validator` | Luhn 校验(ADR 0014) |
| `offline_cache` | 离线缓存加解密(ADR 0017, 0026) |
| `anti_debug` | 反调试检测(ADR 0024) |
| `vm_detect` | VM/模拟器检测(ADR 0024) |
| `integrity` | 完整性校验(ADR 0025) |
| `obfuscation` | 常量字符串混淆 |

### JNI 接口设计约束

**1. 函数名非语义化**
- ❌ `Java_com_xiaochengjian_sdk_verifyCard`
- ✅ `Java_com_xiaochengjian_sdk_native_1from_1rust_10x01`

**2. 只接收/返回基本类型和 byte[]**
- ❌ `jstring`(易被 hook)
- ✅ `jbyteArray`、`jint`、`jboolean`

**3. 输入校验在 Rust 内部**
- 不依赖 Kotlin 层校验
- 所有输入视为不可信

**4. 错误码而非异常**
- Rust 内部 `Result<T, E>`,通过 JNI 返回错误码
- 不抛 Java 异常(易被 hook)

### Rust so 自保护
- **静态链接**:不依赖系统 libc 之外的动态库,防 LD_PRELOAD
- **.text 段自校验**:启动时 hash 自己的 .text 段,对比编译时嵌入的值
- **常量混淆**:用 `obfuscate` crate 对 RSA 公钥、HMAC secret 等常量混淆
- **控制流混淆**:release 编译开启 `cargo-llvm-obfuscator`

### 模块依赖
```
anti_debug / vm_detect / integrity  // 检测层
        ↓
crypto / signing / card_validator   // 算法层
        ↓
offline_cache                        // 业务层
        ↓
JNI 入口                             // 桥接层
```

### 测试要求
- **覆盖率 ≥ 90%**(CI 卡点)
- 关键算法(机器码/加解密/签名)必须有黄金向量测试
- 不测 JNI 桥接层(用 Kotlin 侧集成测试覆盖)

### Claude 提供 Rust 模板
- 项目作者暂无 Rust 经验
- Claude 提供 Rust 模板代码 + 详细注释
- 模板含:模块骨架、JNI 桥接示例、单元测试示例、Cargo.toml 配置

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| Rust 语义化 JNI | 易读 | 易逆向 | 不安全 |
| Rust 非语义化 JNI(本方案) | 难逆向 | 难维护 | 安全必需 |

## 影响

- 正面:开源后客户端安全仍有保障
- 负面:开发速度降低 30%,维护难度高
- 风险:Rust 编译产物体积 +2-5MB,需控制

## 关联

- 关联 ADR:0009(Kotlin + Rust)、0020(加密)、0021(签名)、0024(反调试)
- 关联代码:`sdk-android/rust/`
