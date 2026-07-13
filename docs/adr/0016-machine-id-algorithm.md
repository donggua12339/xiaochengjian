# ADR 0016 · 机器码生成算法

- 状态:accepted
- 日期:2026-07-13
- 决策者:小城笺项目
- 层次:功能

## 背景

机器码是设备绑定的依据,需稳定(换膜/小改不变化)、合规(Android 10+ 限制 IMEI)、隐私(不可逆)。

## 决策

### 机器码算法:多因素组合 SHA-256 哈希

```
machineId = SHA-256(
  ANDROID_ID +
  MediaDRM_ID +
  Build.MANUFACTURER +
  Build.MODEL +
  Build.HARDWARE +
  displayMetrics +
  abis
)[:32]
```

### 标识选择

| 标识 | 稳定性 | 合规性 | 用途 |
|---|---|---|---|
| `ANDROID_ID` | 中(恢复出厂会变) | ✅ | 核心标识,权重高 |
| `MediaDRM_ID` | 高 | ✅ | 核心标识,权重高 |
| `Build.MANUFACTURER + MODEL` | 高 | ✅ | 辅助标识,权重低 |
| `Build.HARDWARE` | 高 | ✅ | 辅助标识 |
| `displayMetrics + abis` | 中 | ✅ | 辅助标识 |
| `IMEI / MEID` | 高 | ❌ | **不用**,Android 10+ 禁 |
| `Build.SERIAL` | 高 | ⚠️ | **不用**,Android 8+ 废弃 |

### 容错策略
- 3 个核心标识(ANDROID_ID + MediaDRM + 硬件指纹)中**至少 2 个匹配**即视为同一设备
- 防 ANDROID_ID 偶发变化导致用户卡密作废
- 服务端存储各标识的独立 hash,匹配时分别比对

### 稳定性保障
- 核心标识(ANDROID_ID + MediaDRM)权重高
- 辅助标识(型号/屏幕)权重低
- 避免换膜/系统小更新就换码

### 隐私保障
- SHA-256 截断 32 字符
- 不可逆,无法反推设备信息
- 符合 GDPR / 个人信息保护法

### 算法位置
- **算法实现放 Rust so**(ADR 0023),防 patch
- 服务端只接收已计算的 machineId,不参与算法

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| 仅 ANDROID_ID | 简单 | 恢复出厂会变 | 不稳定 |
| IMEI | 稳定 | Android 10+ 禁 | 合规风险 |
| 多因素组合(本方案) | 稳定 + 合规 | 算法复杂 | 合理 |

## 影响

- 正面:稳定 + 合规 + 隐私
- 负面:MediaDRM 部分设备无,需降级到 ANDROID_ID + 硬件指纹
- 风险:换机/重置后需开发者后台解绑

## 关联

- 关联 ADR:0015(设备绑定)、0023(Rust 核心)、0024(反调试)
- 关联代码:`sdk-android/rust/src/machine_id.rs`
