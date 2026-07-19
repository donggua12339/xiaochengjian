# ADR 0071 · Rust 核心设计修订:语义化 JNI + 撤除反逆向设施

- 状态:accepted
- 日期:2026-07-19
- 决策者:小城笺项目
- 层次:安全

## 背景

ADR 0023 决策"Rust 核心模块设计",包含 9 项子决策:

1. 模块清单 9 个(machine_id / crypto / signing / card_validator / offline_cache / anti_debug / vm_detect / integrity / obfuscation)
2. JNI 函数名**非语义化**(native01-08 替代语义化)
3. JNI 只接收/返回基本类型和 byte[](**禁 jstring**)
4. 输入校验在 Rust 内部
5. 错误码而非异常
6. 静态链接
7. .text 段自校验
8. 常量混淆(obfuscate crate)
9. 控制流混淆(cargo-llvm-obfuscator)

v2 重构后代码实际状态:

| ADR 0023 子决策 | 代码实际 | 一致性 |
|---|---|---|
| 1. 模块清单 9 个 | 实际 6 个(machine_id / crypto / card_key / cache / integrity / jni_bridge),撤掉 anti_debug / vm_detect / obfuscation | ❌ |
| 2. JNI 非语义化命名 | **默认语义化**(init/generateMachineId/validateCardKey/...),`opaque-jni` feature 启用后**额外**导出 native01-08 别名 | ❌(默认反转) |
| 3. JNI 禁 jstring | 实际**用 JString**(env.get_string / env.new_string) | ❌ |
| 4. 输入校验在 Rust 内 | ✅ 符合 | ✅ |
| 5. 错误码而非异常 | ✅ 符合(jint 返回 0/-1/-2) | ✅ |
| 6. 静态链接 | 未验证(Cargo.toml 无显式配置,Rust 默认动态链接 libc) | ⚠️ |
| 7. .text 段自校验 | **撤除**(见 ADR 0069) | ❌ |
| 8. 常量混淆 obfuscate crate | 改用 `obfstr`(optional feature,默认关) | ⚠️(crate 名变了 + 默认关) |
| 9. 控制流混淆 cargo-llvm-obfuscator | **未实现**(见 ADR 0061,未来工作) | ❌ |

`lib.rs:23` 注释明确写:"so 自校验 / 反调试 / 控制流平坦化 已在 v2 撤掉(grill 决策)。理由:服务端验证是权威,客户端反逆向设施阻碍合法审计,ROI 低。"

ADR 0023 状态仍是 `accepted`,9 项子决策中有 5 项与代码不符,违反 CLAUDE.md 第 10 节。本 ADR 整体修订 ADR 0023。

## 决策

### Rust 核心设计 v2(修订 ADR 0023)

**1. 模块清单(6 个,撤除 3 个)**

| 模块 | 功能 | 状态 |
|---|---|---|
| `machine_id` | 机器码生成(ADR 0016) | ✅ 保留 |
| `crypto` | RSA + AES-256-GCM + HMAC-SHA256 + SHA-256(合并 ADR 0023 的 signing) | ✅ 保留 |
| `card_key` | Luhn mod32 校验(ADR 0014,原 card_validator) | ✅ 保留 |
| `cache` | 离线缓存加解密(ADR 0017/0026,原 offline_cache) | ✅ 保留 |
| `integrity` | APK 签名 hash 比对(简化实现,见 ADR 0070) | ✅ 保留 |
| `jni_bridge` | JNI 入口(语义化命名 + 可选 opaque-jni 别名) | ✅ 保留 |
| ~~`anti_debug`~~ | ~~反调试检测~~ | ❌ 撤除(ADR 0024 未实现) |
| ~~`vm_detect`~~ | ~~VM/模拟器检测~~ | ❌ 撤除(ADR 0024 未实现) |
| ~~`obfuscation`~~ | ~~常量混淆~~ | ❌ 改用 obfstr(optional feature) |

**2. JNI 命名:默认语义化 + 可选 opaque-jni 别名**

- **默认**:语义化命名(`Java_com_xcj_sdk_XcjNative_init` 等),便于开源审计
- **可选 feature `opaque-jni`**:启用后**额外**导出 `native01-08` 别名(不是替代)
- **理由**:开源 + SaaS 双模式下,默认透明(ADR 0042 公开边界),开发者按需启用 opaque-jni
- **反转原因**:ADR 0023 原"非语义化"决策假设闭源/半闭源场景,与 ADR 0042"架构公开,实现保留"的公开哲学冲突

**3. JNI 参数类型:允许 JString**

- ADR 0023 原"禁 jstring,只用 byte[]"决策撤除
- 实际实现用 JString(env.get_string / env.new_string)
- **理由**:JString 在 Rust 内部立即转 String 处理,不暴露给 Kotlin 层;byte[] 反而增加 Kotlin/Rust 转换成本
- **风险**:jstring 理论上可被 hook,但服务端验证是权威(ADR 0019),客户端 hook 不影响最终验证结果

**4. 输入校验在 Rust 内(保留)**

- 所有 JNI 入口视为不可信输入
- Rust 内部做长度/格式/编码校验
- 错误返回 -1/-2 错误码

**5. 错误码而非异常(保留)**

- Rust 内部 `Result<T, E>`,通过 JNI 返回 jint 错误码
- 不抛 Java 异常(易被 hook)

**6. 静态链接(待验证)**

- ADR 0023 原"静态链接,防 LD_PRELOAD"决策**保留为目标**
- 当前 Cargo.toml 未显式配置,Rust 默认动态链接 libc
- **待办**:P2 阶段验证交叉编译产物是否静态链接,若不是则补 Cargo.toml 配置

**7. .text 段自校验:撤除(见 ADR 0069)**

**8. 常量混淆:obfstr optional feature**

- ADR 0023 原"obfuscate crate"改为 `obfstr`(社区更活跃)
- **默认关闭**,开发者按需启用 `cargo build --features obfstr`
- 启用后混淆 RSA 公钥指纹 / 错误信息 / URL 等常量

**9. 控制流混淆:未实现(见 ADR 0061)**

- ADR 0061 标为"未来工作"
- 当前无 cargo-llvm-obfuscator 集成
- 长期目标:SaaS 版独占,开源版无

### 模块依赖(修订)

```
integrity              // 完整性校验(APK 签名 hash)
   ↓
crypto / card_key      // 算法层
   ↓
cache                  // 业务层(离线缓存)
   ↓
jni_bridge             // 桥接层
```

撤除 anti_debug / vm_detect 检测层(ADR 0024 未实现)。

### 测试要求(保留)

- 覆盖率 ≥ 90%(CI 卡点,ADR 0038)
- 关键算法黄金向量测试
- 不测 JNI 桥接层(用 Kotlin 集成测试覆盖)

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| A. 恢复 ADR 0023 完整实现(非语义化 + byte[] + 自校验 + 反调试) | 安全姿态最高 | 与开源哲学冲突、ROI 低、阻碍审计 | 违反 ADR 0042 公开边界 |
| B. 逐项写 9 份新 ADR 分别修订 | 追溯最细 | 9 份 ADR 高度重复 | 冗余 |
| C. 整体修订 ADR 0023(本方案) | 一致、简洁 | 单份 ADR 跨度大 | 合理(实际修订是一体决策) |
| D. 不修订,让 ADR 0023 失效 | 省事 | 违反 CLAUDE.md 第 10 节 | 决策追溯断裂 |

## 影响

- **正面:**
  - ADR 与代码事实一致(CLAUDE.md 第 10 节合规)
  - 与 ADR 0042 公开边界哲学一致(默认透明,可选加固)
  - 开源审计友好(语义化命名 + 撤除自校验)
  - 与 ADR 0019 安全哲学一致(服务端是权威)
- **负面:**
  - 客户端反逆向能力降至最低(只有 optional obfstr + opaque-jni)
  - anti_debug / vm_detect 撤除后,模拟器批量刷卡密无客户端门槛(依赖服务端 ADR 0022 防爆破)
- **风险:**
  - 攻击者可轻松 hook JNI 函数,但服务端验证是权威,hook 不影响最终结果
  - 缓解:handshake + AES + HMAC + nonce 防重放(ADR 0020/0021)保证通信安全
  - 缓解:heartbeat 每 20 分钟轮换密钥(ADR 0060)
  - 待办:P2 阶段补基础反调试(ADR 0024)作为可选 feature,不默认启用

## 关联

- **取代(superseded by 0071):**
  - ADR 0023 · Rust 核心模块设计(9 项子决策中 5 项修订,4 项保留)
- **保留不变:**
  - ADR 0019 · 安全设计哲学(服务端是权威)
  - ADR 0042 · 安全设计公开边界(架构公开,实现保留)
  - ADR 0038 · 测试策略(Rust ≥ 90% 覆盖率)
- **关联 ADR:**
  - 0009(Kotlin + Rust JNI,技术栈)
  - 0014(卡密格式,card_key 模块)
  - 0016(机器码,machine_id 模块)
  - 0017/0026(离线缓存,cache 模块)
  - 0020/0021(通信加密/签名,crypto 模块)
  - 0024(反调试,**未实现**,待 P2)
  - 0060(密钥轮换)
  - 0061(混淆策略,obfstr + 控制流平坦化未来工作)
  - 0069(so 自校验撤除)
  - 0070(APK 签名 hash 简化)
- **关联代码:**
  - `sdk-android/rust/xcj-core/src/lib.rs`(模块导出 + v2 撤除注释)
  - `sdk-android/rust/xcj-core/src/jni_bridge.rs`(语义化命名 + opaque-jni feature)
  - `sdk-android/rust/xcj-core/Cargo.toml`(obfstr / opaque-jni optional features)
- **关联文档:** `docs/handover.md`、`CLAUDE.md` 第 8 节安全要点
- **关联 git commit:** `4731300 refactor(sdk): Day 1 - 撤掉反逆向红线设施 + 配置 NDK 交叉编译`(2026-07-15~18 v2 重构期间)
