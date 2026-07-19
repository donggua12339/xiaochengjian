# ADR 0070 · APK 签名 hash 简化实现:整文件 hash + 服务端白名单兜底

- 状态:accepted
- 日期:2026-07-19
- 决策者:小城笺项目
- 层次:安全

## 背景

ADR 0062 决策"防重打包:直接读 APK 文件解析签名 + 服务端下发预期 hash",要求:
1. **客户端**:直接读 APK 文件**解析签名块**(v2/v3 签名块),不依赖系统 API(防 hook)
2. **服务端**:开发者后台配"预期签名 hash",SDK 启动拉取对比
3. 不一致 -> 拒绝验证

代码实际实现(`sdk-android/rust/xcj-core/src/integrity.rs`):

```rust
/// 计算 APK 签名 hash(简化版,实际需解析 APK ZIP 结构 + v2/v3 签名块)
///
/// # 返回
/// 64 字符十六进制 SHA-256(实际应解析签名块,这里简化为整个文件 hash 用于测试)
pub fn compute_apk_signature_hash(apk_path: &str) -> Option<String> {
    let data = std::fs::read(apk_path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Some(hex::encode(hasher.finalize()))
}
```

**实际行为**是对整个 APK 文件做 SHA-256,**不是解析签名块**。注释里也写明"实际应解析签名块,这里简化"。

这导致两个问题:
1. **合法重签无法通过白名单**:开发者用 `injector sign` 重签后,APK 字节流变化,整文件 hash 变化,白名单需重新配置。但 ADR 0062 原设计是"原始 APK 签名 + 注入后重签的签名都加入白名单",签名块 hash 在多次重签间可能稳定(同一 keystore),整文件 hash 则每次都变。
2. **任何字节改动都触发**:加水水印、改资源、改 dex 都会让 hash 变化,白名单失去意义。

同时,服务端"预期签名 hash 列表"接口在 backend 中未实现(grep 无结果)。这是 ADR 0062 的部分未实现。

ADR 0062 状态仍是 `accepted`,与代码事实不符,违反 CLAUDE.md 第 10 节。本 ADR 补齐决策追溯并明确简化方案的边界。

## 决策

### v2 简化实现:整文件 hash + 服务端白名单兜底

**保留的能力:**

- ✅ `compute_apk_signature_hash(apk_path)` 计算整文件 SHA-256
- ✅ `verify_apk_signature(apk_path, allow_list)` 比对白名单
- ✅ 大小写不敏感比对(`eq_ignore_ascii_case`)

**撤除的能力:**

- ❌ 解析 APK ZIP 结构 + v2/v3 签名块(ADR 0062 原设计)
- ❌ 服务端下发"预期签名 hash 列表"接口(未实现)
- ❌ 开发者后台配置白名单的 UI(未实现)

### 简化方案的边界

| 场景 | 简化方案行为 | ADR 0062 原设计行为 |
|---|---|---|
| 开发者自有 APK,未重签 | ✅ hash 稳定,白名单可配 | ✅ 同 |
| 开发者自有 APK,重签一次 | ❌ hash 变化,白名单需更新 | ✅ 签名块 hash 稳定(同 keystore) |
| 攻击者重打包(改 dex + 重签) | ✅ hash 变化,白名单拒绝 | ✅ 签名块 hash 变化,白名单拒绝 |
| 攻击者改资源(不重签) | ✅ hash 变化,白名单拒绝 | ❌ 签名块 hash 不变,白名单通过 |
| 加水印(`injector sign --watermark-id`) | ❌ hash 变化,白名单需更新 | ✅ 签名块 hash 不变 |

**结论**:简化方案在"攻击者重打包"核心场景下仍有效,但"开发者重签 / 加水印"场景需更新白名单,体验差于原设计。

### 服务端白名单兜底(待实现,P2 优先级)

虽然客户端实现简化,但服务端白名单下发仍是必要的兜底机制:
- backend 加 `application.signatureAllowList` 字段(String[])
- SDK 启动时通过 handshake 或新接口拉取白名单
- 客户端 `verify_apk_signature` 用拉取的白名单比对

**这部分在 P2 阶段实现**(见 P2.2 待办)。本 ADR 仅记录"客户端简化 + 服务端待补"的当前状态,不承诺服务端实现时机。

### 与 ADR 0025 的关系

ADR 0025(完整性校验)三项:
- (a) APK 签名校验:**简化实现**(本 ADR)
- (c) so 自校验:**撤除**(ADR 0069)
- (d) 服务端下发校验值:**部分保留**(APK 签名白名单下发,待 P2 实现;so hash 下发撤除)

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| A. 实现 ADR 0062 完整方案(解析签名块) | 体验最好 | 实现复杂(需 ZIP 解析 + ASN.1 解析 + v2/v3 块定位) | 工期 1-2 周,ROI 低 |
| B. 完全撤除客户端校验,只靠服务端 | 最简单 | 离线缓存场景(ADR 0017)无任何客户端校验 | 缓存期内可被 patch |
| C. 整文件 hash + 服务端白名单兜底(本方案) | 简单、覆盖核心场景 | 开发者重签体验差 | 合理(简化方案 + 服务端兜底) |
| D. 调用系统 `PackageManager.GET_SIGNATURES` | 简单 | 易被 hook(ADR 0062 已排除) | 不安全 |

## 影响

- **正面:**
  - ADR 与代码事实一致(CLAUDE.md 第 10 节合规)
  - 客户端实现简单(20 行 Rust),无 ZIP/ASN.1 解析依赖
  - 覆盖"攻击者重打包"核心场景
- **负面:**
  - 开发者重签 / 加水印后需手动更新白名单(原设计不需)
  - 服务端白名单下发接口未实现,当前白名单需硬编码或本地配置
  - 攻击者改资源(不重签)场景下,原设计能检测,简化方案能检测(整文件 hash 变化) -- 此项简化方案反而更严
- **风险:**
  - 服务端白名单接口未实现前,客户端 `verify_apk_signature` 实际无法工作(白名单为空)
  - 缓解:handshake 阶段若白名单为空,跳过校验(记录日志),不阻塞激活
  - 待办:P2.2 实现服务端白名单下发接口

## 关联

- **取代(superseded by 0070):**
  - ADR 0062 · 防重打包:直接读 APK + 服务端下发(原设计的"解析签名块"部分被简化取代,"服务端下发"部分保留但未实现)
- **保留不变:**
  - ADR 0025 · 完整性校验与防重打包(APK 签名校验项保留,实现简化)
- **关联 ADR:** 0069(so 自校验撤除)、0017(离线验证,缓存期内校验依赖)、0019(安全哲学,服务端是权威)、0023(Rust 核心设计)
- **关联代码:**
  - `sdk-android/rust/xcj-core/src/integrity.rs`(简化实现 + 注释说明)
  - backend 待补:`application.signatureAllowList` 字段 + 拉取接口(P2.2)
- **关联文档:** `docs/handover.md`、`CLAUDE.md` 第 8 节安全要点
