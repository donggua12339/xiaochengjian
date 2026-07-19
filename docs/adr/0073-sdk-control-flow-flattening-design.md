# ADR 0073 · SDK 控制流平坦化设计(未来工作)

- 状态:proposed(未来工作,未实现)
- 日期:2026-07-19
- 决策者:小城笺项目
- 层次:安全

## 背景

ADR 0061 决策"混淆策略:字符串 + 控制流",其中:
- **字符串混淆(obfstr)**:已实现(optional feature,ADR 0071)
- **控制流混淆(olvllvm-rust)**:未实现,标为"未来工作"
- **虚拟化**:长期目标(SaaS 版独占)

ADR 0071 修订 ADR 0023 时,将控制流平坦化明确为"未来工作",撤除反调试 / VM 检测等设施后,客户端反逆向能力降至最低。本 ADR 记录控制流平坦化的设计方案,作为未来实现依据。

**当前状态**:
- `sdk-android/rust/xcj-core/Cargo.toml` 无 `control-flow-flattening` feature
- Rust 源码无 `#[control_flow_flatten]` 类似属性
- 编译产物无控制流平坦化

## 决策

### 未来实现:控制流平坦化作为可选 Cargo feature

**feature 名**:`control-flow-flattening`

**启用方式**:
```bash
cargo build --release --features control-flow-flattening --target aarch64-linux-android
```

**默认状态**:**关闭**(与 obfstr / opaque-jni 一致,默认透明,开发者按需启用)

### 技术方案(三选一,未来 ADR 决定)

#### 方案 A:olvllvm-rust(原 ADR 0061 决策)

- **工具**:[olvllvm-rust](https://github.com/nickhutchinson/llvm-project)(基于 LLVM 的控制流平坦化 pass)
- **实现**:自定义 LLVM pass,在 Rust 编译时插入
- **效果**:控制流平坦化 + 虚假控制流
- **开销**:10-30% 性能损失(ADR 0061)
- **成熟度**:olvllvm-rust 不成熟,可能需自写 pass(2 周开发,ADR 0061 估计)
- **兼容性**:需自定义 rustc 工具链,与官方 rustc 不兼容

#### 方案 B:obfuscate-llvm(社区维护)

- **工具**:[obfuscate-llvm](https://github.com/obfuscator-llvm/obfuscator)(LLVM 混淆框架)
- **实现**:类似方案 A,但用 obfuscate-llvm 的 pass
- **效果**:控制流平坦化 + 虚假控制流 + 指令替换
- **开销**:10-30% 性能损失
- **成熟度**:obfuscate-llvm 维护不活跃,可能需 fork
- **兼容性**:同方案 A,需自定义 rustc

#### 方案 C:Rust 过程宏(纯 Rust 实现)

- **工具**:自定义 proc-macro(如 `#[control_flow_flatten]`)
- **实现**:在 Rust 源码层转换控制流(把 if/else/loop 转成 state machine)
- **效果**:控制流平坦化(无虚假控制流)
- **开销**:5-15% 性能损失(比 LLVM pass 轻)
- **成熟度**:需自研,但纯 Rust 不依赖自定义工具链
- **兼容性**:与官方 rustc 兼容,CI 友好

**推荐**:方案 C(纯 Rust 过程宏),理由:
- 不依赖自定义 LLVM 工具链(降低维护成本)
- CI 可直接跑(无需特殊 rustc)
- 与 obfstr / opaque-jni 一致的"可选 feature"模式
- 性能开销可控

### 应用范围(未来实现时)

**核心安全函数(必加)**:
- `crypto::rsa_encrypt` / `aes_encrypt` / `aes_decrypt` / `hmac_sign`
- `card_key::validate_card_key`
- `machine_id::generate_machine_id`
- `cache::encrypt_cache` / `decrypt_cache`
- `integrity::compute_apk_signature_hash`

**非核心函数(可选)**:
- `jni_bridge::*`(JNI 入口,平坦化后调用方需适配)
- `lib::version`(无必要)

### 与其他 features 的组合

| feature 组合 | 效果 | 适用场景 |
|---|---|---|
| 默认(无 feature) | 透明,可审计 | 开源版默认 |
| `obfstr` | 字符串加密 | 基础反逆向 |
| `opaque-jni` | + JNI 非语义化 | 中级反逆向 |
| `obfstr + opaque-jni + control-flow-flattening` | 全套 | SaaS VIP / 高安全场景 |

### 性能预算

- 单次 `aes_encrypt`:当前 ~0.1ms,平坦化后 ~0.13ms(+30%)
- 单次 `rsa_encrypt`:当前 ~5ms,平坦化后 ~6.5ms(+30%)
- SDK init 总耗时:当前 ~50ms,平坦化后 ~65ms(+30%)
- **可接受**(SDK init 非热路径)

### 开发量估算

| 阶段 | 工作量 | 产出 |
|---|---|---|
| 调研 + 选型(方案 A/B/C) | 3 天 | 选型报告 + 技术验证 PoC |
| proc-macro 框架(方案 C) | 5 天 | `#[control_flow_flatten]` 基础设施 |
| 核心函数应用 + 测试 | 3 天 | 5 个核心函数平坦化 + 性能基准 |
| CI 集成 + 文档 | 2 天 | `control-flow-flattening` feature 入 CI |
| **总计** | **~13 天**(2-3 周) | |

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| A. 不实现(保持现状) | 简单 | 客户端反逆向能力低 | ADR 0061 承诺的未来工作 |
| B. 只做字符串混淆(已实现) | 已完成 | 不够 | 控制流是逆向主要切入点 |
| C. 实现控制流平坦化(本 ADR) | 提升反逆向 | 2-3 周开发 | 合理(未来工作) |
| D. 直接上虚拟化(SaaS 独占) | 最强 | 数月开发 | 推迟到更晚 |

## 影响

- **正面(未来实现后):**
  - 客户端反逆向能力提升(控制流平坦化是逆向主要障碍)
  - 与 obfstr / opaque-jni 组合,达到开源项目安全极限(ADR 0061)
  - SaaS VIP 增值点(高级反逆向 features)
- **负面:**
  - 2-3 周开发工期
  - 性能开销 10-30%
  - 维护成本(自定义 proc-macro 需跟进 Rust 版本)
- **风险:**
  - proc-macro 实现可能有 bug,导致编译产物行为异常
  - 缓解:充分单元测试 + 与非平坦化版本对比测试
  - 平坦化后调试困难(堆栈跟踪混乱)
  - 缓解:开发模式禁用平坦化,仅 release 启用

## 实施前置条件

本 ADR 标为 `proposed`,实际实现需满足:
1. P2 安全姿态补齐(反调试 + VM 检测,ADR 0024)-- 否则平坦化可被 patch 跳过
2. P3 开源准备完成(SECURITY.md / 安全白皮书等)
3. 有明确的高安全客户需求(SaaS VIP 用户反馈)

## 关联

- **关联 ADR:**
  - 0023(Rust 核心设计,已由 0071 修订)
  - 0061(混淆策略:字符串 + 控制流)
  - 0071(Rust 核心设计修订,控制流平坦化标为未来工作)
  - 0042(安全设计公开边界,架构公开 + 实现保留)
- **关联代码(未来实现时):**
  - `sdk-android/rust/xcj-core/Cargo.toml`(加 `control-flow-flattening` feature)
  - `sdk-android/rust/xcj-core/src/crypto.rs`(应用 `#[control_flow_flatten]`)
  - `sdk-android/rust/xcj-core/src/card_key.rs`
  - `sdk-android/rust/xcj-core/src/machine_id.rs`
  - `sdk-android/rust/xcj-core/src/cache.rs`
  - `sdk-android/rust/xcj-core/src/integrity.rs`
  - 新增 `sdk-android/rust/xcj-flatten/`(proc-macro crate)
- **关联文档:** `docs/security.md` 第 3.4 节客户端核心
