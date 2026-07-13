# ADR 0026 · 离线缓存加密

- 状态:accepted
- 日期:2026-07-13
- 决策者:小城笺项目
- 层次:安全

## 背景

C6 选了缓存 7 天。缓存数据如何加密决定攻击者能否直接 patch 本地缓存绕过验证。

## 决策

### 离线缓存加密:AES + Rust 派生密钥 + 服务端下发 cacheKey

### 缓存内容
- 卡密 hash
- 设备绑定状态
- 剩余有效时间
- 上次验证时间
- 服务端下发的 `cacheKey`

### 加密方案
- **算法**:AES-256-GCM
- **密钥派生**:`AES_KEY = HKDF(cacheKey + deviceFingerprint, info="offline-cache")`
- **派生位置**:Rust so 内(不在 Kotlin)
- **密钥不长期存内存**:每次加解密时派生

### 密钥管理
- **cacheKey**:服务端首次验证成功后下发(per-device)
- **deviceFingerprint**:Rust 内生成,不暴露给 Kotlin
- **派生密钥**:不持久化,每次加解密时计算

### 缓存文件存储
- 路径:`/data/data/<pkg>/files/xcj_cache.bin`
- 权限:`0700`(仅应用可读写)
- 格式:`[IV(12B)][ciphertext][GCM tag(16B)]`

### 防篡改
- 缓存内容带 HMAC 签名
- HMAC key 与 AES key 不同(均从 cacheKey 派生)
- 篡改后下次验证直接拒绝
- 服务端记录篡改事件,触发风控

### 不用 Android Keystore 的原因
- Keystore 在 root 设备上可被提取
- 部分低端设备 Keystore 实现有 bug
- Rust 自己实现更可控

### 不用硬编码密钥的原因
- 开源后密钥公开
- 反编译即得

## 备选方案

| 方案 | 强度 | 不选原因 |
|---|---|---|
| 明文 SharedPreferences | 低 | 易篡改 |
| AES + 密钥硬编码 Kotlin | 低 | 反编译即得 |
| AES + 密钥在 Rust | 中 | 密钥可被提取 |
| AES + 服务端下发 + Rust 派生(本方案) | 高 | 合理 |
| Android Keystore + AES | 高 | root 可提取 |

## 影响

- 正面:缓存加密 + 防篡改,patch 本地缓存不可行
- 负面:每次加解密需派生密钥,增加 ~10ms 延迟
- 风险:cacheKey 泄露会导致缓存可解密(但 deviceFingerprint 仍是变量)

## 关联

- 关联 ADR:0017(离线验证)、0023(Rust 核心)、0020(通信加密)
- 关联代码:`sdk-android/rust/src/offline_cache.rs`
