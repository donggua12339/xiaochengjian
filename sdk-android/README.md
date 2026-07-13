# 小城笺 · Android SDK(Kotlin + Rust)

> Kotlin 2.0 + Rust(stable)+ JNI,AAR via 私有 Maven

## 模块结构

```
sdk-android/
├── kotlin/   # AAR 模块(SDK API 入口 / HTTP / UI)
└── rust/     # so 核心安全模块(机器码 / 加密 / 签名 / 反调试)
```

## 范围

- Kotlin:SDK API 入口、HTTP 请求、验证弹窗(Compose)
- Rust so:
  - 机器码生成(ADR 0016)
  - RSA + AES 加解密(ADR 0020)
  - HMAC 签名(ADR 0021)
  - Luhn 校验(ADR 0014)
  - 离线缓存加密(ADR 0026)
  - 反调试 + VM 检测(ADR 0024)
  - 完整性校验(ADR 0025)

## 状态

- M0:文档骨架(当前)
- M2:Rust 核心 + Kotlin SDK(待启动)

## 关键 ADR

- [ADR 0009 · Kotlin + Rust JNI](../docs/adr/0009-sdk-kotlin-rust-jni.md)
- [ADR 0010 · AAR 分发](../docs/adr/0010-sdk-distribution.md)
- [ADR 0023 · Rust 核心设计](../docs/adr/0023-rust-core-design.md)
