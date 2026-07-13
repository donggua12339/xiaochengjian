# ADR 0009 · Android SDK:Kotlin + Rust JNI

- 状态:accepted
- 日期:2026-07-13
- 决策者:小城笺项目
- 层次:技术栈

## 背景

开源 + SaaS 双模式下,客户端代码完全公开。Java/Kotlin 字节码反编译等于源码,Rust 编译产物是原生机器码,反编译难度指数级上升。这是参考的 3 个开源项目都没做的差异化点。

## 决策

### SDK 语言与架构
- **外层**:Kotlin 2.0(AAR 模块)
- **核心**:Rust stable(so 模块,JNI 桥接)
- **JNI 接口**:Kotlin 通过 JNI 调 Rust 函数

### 职责划分

| 逻辑 | 位置 | 理由 |
|---|---|---|
| 卡密格式校验(Luhn) | Rust | 防 patch 绕过 |
| 机器码生成 | Rust | 核心安全逻辑 |
| RSA 公钥 / AES 密钥 | Rust | 密钥不能暴露 Kotlin |
| 请求签名 HMAC | Rust | 密钥不能暴露 |
| 通信加密 AES | Rust | 加密逻辑难逆向 |
| 离线缓存加解密 | Rust | 缓存密钥不能暴露 |
| 反调试检测 | Rust | 检测逻辑难逆向 |
| VM/模拟器检测 | Rust | 同上 |
| 完整性校验 | Rust | 防重打包 |
| HTTP 请求 | Kotlin(OkHttp) | Kotlin 更稳 |
| UI(验证弹窗) | Kotlin(Compose) | UI 在 Kotlin |
| SDK API 入口 | Kotlin | 开发者集成 |

### JNI 设计约束
- JNI 函数**只接收/返回基本类型和 byte[]**,不暴露 String(防字符串被 hook)
- JNI 函数名**非语义化**:`native_0x01`、`native_0x02` 而非 `verifyCard`
- Rust so **静态链接**(不依赖系统 libc 之外的动态库)
- Rust so 启动时**自校验**(hash 自己的 .text 段)
- Rust 内部用 `obfuscate` crate 对常量字符串混淆

### Rust 工程师支持
项目作者暂无 Rust 工程经验,grill-me 中明确接受 Claude 提供 Rust 模板代码 + 详细注释。

### 构建目标
- `aarch64-linux-android`(64 位 ARM,主流)
- `armv7-linux-androideabi`(32 位 ARM,老设备)
- `x86_64-linux-android`(模拟器)

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| 纯 Kotlin | 简单 | 反编译即源码 | 开源下不安全 |
| Java + Kotlin 混合 | 兼容 | 反编译仍是源码 | 无本质改善 |
| Kotlin + Rust(本方案) | 反编译最难 | 开发速度 -30% | 安全必需 |
| Kotlin + C/C++ | 反编译难 | 内存不安全 | Rust 更现代 |

## 影响

- 正面:开源后客户端安全仍有保障,是相对参考项目的核心竞争力
- 负面:开发速度降低 30%,需 Rust 工程能力
- 风险:Rust 编译产物体积比纯 Kotlin 大 2-5MB,需控制

## 关联

- 关联 ADR:0010(AAR 分发)、0023(Rust 核心设计)、0024(反调试)
- 关联代码:`sdk-android/kotlin/`、`sdk-android/rust/`
