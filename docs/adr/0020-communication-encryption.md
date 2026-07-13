# ADR 0020 · 通信加密方案

- 状态:accepted
- 日期:2026-07-13
- 决策者:小城笺项目
- 层次:安全

## 背景

纯 HTTPS 在 Android 上可被 Frida + objection 一键绕过证书 pinning。需要应用层加密提升逆向门槛。

## 决策

### 通信加密:HTTPS + RSA 协商 AES + AES-256-GCM 加密请求体

### 加密流程
```
1. 客户端启动:
   - Rust so 内生成临时 AES-256 密钥
   - 用硬编码 RSA 公钥加密 AES 密钥
   - 将加密后的 AES 密钥发送给服务端

2. 服务端:
   - 用 RSA 私钥解密获得 AES 密钥
   - 缓存 AES 密钥(sessionId, TTL 1hour)
   - 返回 sessionId

3. 后续通信:
   - 请求体用 AES-256-GCM 加密
   - 带 sessionId,服务端用对应 AES 密钥解密
   - 响应体同样 AES-256-GCM 加密
```

### 密钥管理
- **RSA 公钥**:硬编码在 Rust so(不是 Kotlin),反编译不可得
- **RSA 私钥**:服务端持有,永不暴露
- **AES 密钥**:每次启动重新生成,不长期固定
- **sessionId**:服务端缓存 1 小时,过期重新协商

### TLS 配置
- HTTPS 强制(不开 HTTP)
- TLS 1.2+ 最低
- 证书 pinning(防中间人)
- HSTS 头

### 不选纯 HTTPS 的原因
- Frida + objection 一键绕过证书 pinning
- 抓包工具(MitmProxy/Charles)可明文查看
- 应用层加密让抓包看到的是密文

### 不选自定义二进制协议的原因
- HTTP/2 已足够,自定义协议增加 NAT/代理穿透问题
- 维护成本高

## 备选方案

| 方案 | 强度 | 维护成本 | 不选原因 |
|---|---|---|---|
| 纯 HTTPS | 中 | 低 | 易绕过 |
| HTTPS + 应用层 AES(本方案) | 高 | 中 | 合理 |
| 自定义二进制协议 | 高 | 高 | 过度设计 |

## 影响

- 正面:抓包工具看到密文,逆向门槛显著提升
- 负面:开发调试复杂,需配套解密工具
- 风险:RSA 公钥被提取后,攻击者可模拟客户端(但有 D2 签名 + D3 风控兜底)

## 关联

- 关联 ADR:0021(请求签名)、0023(Rust 核心)、0027(服务端基线)
- 关联代码:`sdk-android/rust/src/crypto/`、`backend/src/crypto/`
