# 小城笺 · 架构总览

> 本文档描述小城笺卡密验证系统的整体架构、模块依赖、数据流。
> 详细决策见 [ADR](adr/README.md)。

## 1. 系统全景

```
┌─────────────────────────────────────────────────────────────┐
│                     开发者侧                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │ 管理后台 Web │  │ 安卓管理 APP │  │ 安卓注入工具 │       │
│  │  (Vue3)      │  │  (Compose)   │  │  (Compose)   │       │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘       │
└─────────┼─────────────────┼─────────────────┼───────────────┘
          │                 │                 │
          │ HTTPS + 应用层加密(ADR 0020)      │
          │ HMAC 签名 + nonce(ADR 0021)       │
          ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────┐
│                    SaaS 服务端                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │           NestJS 后端(TS strict)                   │    │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐            │    │
│  │  │ 多租户   │ │ 卡密核心 │ │ 注入服务 │            │    │
│  │  │ TenantCtx│ │ CardKey  │ │ Inject   │            │    │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘            │    │
│  │       │            │            │                   │    │
│  │  ┌────▼────────────▼────────────▼─────┐            │    │
│  │  │  安全层:2FA / JWT / 限流 / 风控    │            │    │
│  │  └─────────────────────────────────────┘            │    │
│  └──────────────┬──────────────────────────────────────┘    │
│                 │                                            │
│  ┌──────────────▼──────┐  ┌──────────────────┐             │
│  │  PostgreSQL 16      │  │  Redis 7         │             │
│  │  (RLS 多租户隔离)   │  │  (缓存/nonce/限流)│             │
│  └─────────────────────┘  └──────────────────┘             │
└─────────────────────────────────────────────────────────────┘
          ▲
          │ HTTPS + RSA+AES 加密(ADR 0020)
          │
┌─────────┴───────────────────────────────────────────────────┐
│                  最终用户侧(Android APP)                     │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  开发者 APK(含小城笺 SDK)                          │   │
│  │  ┌─────────────────┐  ┌─────────────────────────┐    │   │
│  │  │ Kotlin 层       │  │ Rust so 核心(ADR 0023) │    │   │
│  │  │ - SDK API 入口  │  │ - 机器码生成            │    │   │
│  │  │ - HTTP 请求     │<-│ - 加解密                │    │   │
│  │  │ - UI(验证弹窗) │  │ - 签名                  │    │   │
│  │  └─────────────────┘  │ - 离线缓存              │    │   │
│  │                       │ - 反调试 / VM 检测      │    │   │
│  │                       │ - 完整性校验            │    │   │
│  │                       └─────────────────────────┘    │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

## 2. 模块拓扑

### 后端(NestJS)
```
backend/
├── src/
│   ├── auth/              # 认证(2FA / JWT)
│   ├── tenant/            # 多租户隔离(ADR 0018)
│   ├── developer/         # 开发者账号
│   ├── application/       # 应用管理
│   ├── card-key/          # 卡密核心(ADR 0013, 0014)
│   │   ├── generator.ts   # 卡密生成
│   │   ├── validator.ts   # 卡密校验
│   │   └── lifecycle.ts   # 激活/禁用/解绑
│   ├── device/            # 设备绑定(ADR 0015)
│   ├── validation/        # 验证接口(SDK 调用)
│   ├── inject/            # 注入服务(SaaS 独占)
│   ├── crypto/            # 加解密(ADR 0020)
│   ├── signing/           # 签名校验(ADR 0021)
│   ├── rate-limit/        # 限流(ADR 0022)
│   ├── security/          # 安全基线(ADR 0027)
│   ├── audit/             # 审计日志
│   └── logging/           # 日志(脱敏)
├── prisma/
│   ├── schema.prisma      # 数据模型
│   └── migrations/        # 数据库迁移
└── test/
```

### Android SDK(Kotlin + Rust)
```
sdk-android/
├── kotlin/                # AAR 模块
│   ├── src/main/
│   │   ├── kotlin/com/xcj/sdk/
│   │   │   ├── XiaochengjianSDK.kt       # SDK API 入口
│   │   │   ├── network/                  # HTTP 请求
│   │   │   ├── ui/                       # 验证弹窗(Compose)
│   │   │   └── jni/                      # JNI 桥接
│   │   └── AndroidManifest.xml
│   └── build.gradle.kts
└── rust/                  # so 核心模块
    ├── src/
    │   ├── lib.rs
    │   ├── machine_id.rs                 # 机器码(ADR 0016)
    │   ├── crypto/                       # 加解密(ADR 0020)
    │   ├── signing.rs                    # 签名(ADR 0021)
    │   ├── card_validator.rs             # Luhn 校验
    │   ├── offline_cache.rs              # 离线缓存(ADR 0026)
    │   ├── anti_debug.rs                 # 反调试(ADR 0024)
    │   ├── vm_detect.rs                  # VM 检测
    │   ├── integrity.rs                  # 完整性(ADR 0025)
    │   └── jni_bridge.rs                 # JNI 入口
    └── Cargo.toml
```

### 注入工具
```
injector/                  # CLI(Kotlin + dexlib2)
└── src/main/kotlin/
    ├── Injector.kt
    ├── dex/               # dex 引擎
    ├── smali/             # Smali 引擎(降级)
    ├── sign/              # apksigner
    └── watermark/         # 注入水印

injector-android/          # 安卓端 APP(Compose)
└── src/main/
    ├── kotlin/            # 上传 APK + 下载注入后 APK
    └── AndroidManifest.xml
```

## 3. 关键数据流

### 卡密激活流程
```
用户输入卡密
  └─> Kotlin 调 JNI native_0x01(cardKey)
      └─> Rust Luhn 校验
          ├─> 失败:返回错误码
          └─> 通过:
              └─> Rust 生成 machineId
              └─> Kotlin HTTP 请求(/v1/activate)
                  ├─> Rust 加密请求体(AES)
                  ├─> Rust HMAC 签名
                  └─> 发送
                      └─> 服务端:
                          ├─> 解密 + 验签
                          ├─> nonce 校验
                          ├─> 限流检查(ADR 0022)
                          ├─> 卡密 hash 对比
                          ├─> 设备绑定检查
                          ├─> 写入数据库
                          └─> 返回(加密 + 签名)
                              └─> Rust 解密响应
                                  ├─> 失败:错误码
                                  └─> 成功:
                                      └─> Rust 写入离线缓存
                                      └─> Kotlin 通知 APP 允许使用
```

### 离线验证流程
```
启动 APP
  └─> Rust 读取本地缓存(解密 + HMAC 校验)
      ├─> 缓存有效且 < N 天:本地验证通过
      └─> 缓存过期或无缓存:
          └─> 联网验证(同上)
              ├─> 成功:更新缓存
              └─> 失败 + 无网络 + 缓存 < N 天:允许
              └─> 失败 + 无网络 + 缓存 > N 天:拒绝
```

## 4. 多租户隔离

| 层 | 机制 |
|---|---|
| 数据库 | PostgreSQL RLS 行级安全 |
| 应用 | NestJS TenantContext + AOP |
| API | JWT 含 tenant_id |
| 缓存 | key 含 tenant_id 前缀 |
| 日志 | 强制含 tenant_id 字段 |

## 5. 安全边界

| 边界 | 防护 |
|---|---|
| 通信 | HTTPS + RSA+AES(ADR 0020) |
| 请求 | HMAC + nonce + 时间同步(ADR 0021) |
| 客户端 | Rust so + 反调试 + 完整性(ADR 0023-0026) |
| 服务端 | 限流 + 失败锁定 + 错误延迟(ADR 0022) |
| 数据库 | RLS + 加密备份(ADR 0018, 0033) |

## 6. 部署形态

| 形态 | 编排 | 适用 |
|---|---|---|
| 开源版 | Docker Compose | 自部署 |
| SaaS MVP | Docker Compose 单机 | 用户 < 1000 |
| SaaS 中规模 | K8s + PG 主从 + Redis 哨兵 | 用户 1000-10000 |
| SaaS 大规模 | K8s 多区域 + PG 分片 | 用户 > 10000 |

## 7. 技术栈速查

| 层 | 技术 | ADR |
|---|---|---|
| 后端 | NestJS + TS strict | 0005 |
| 数据库 | PostgreSQL 16 | 0006 |
| 缓存 | Redis 7 | 0007 |
| 后台 | Vue3 + Naive UI | 0008 |
| SDK | Kotlin + Rust JNI | 0009 |
| 注入工具 | Kotlin + dexlib2 | 0011 |
| 部署 | Compose + K8s | 0012 |
| 监控 | Prometheus + Grafana + Loki | 0032 |
| CI | GitHub Actions | 0034 |
