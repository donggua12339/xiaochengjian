# 小城笺 · 注入工具(Injector CLI)

> Kotlin + dexlib2 + apksigner,dex 主 Smali 备

## 范围

- 成品 APK 注入小城笺 SDK
- dex 字节码操作(主引擎)
- Smali 反编译重打包(降级引擎)
- Application.onCreate 注入 + MainActivity 兜底
- V1 + V2 + V3 签名
- 注入水印(加密存储)
- 原子操作 + 调试模式

## 状态

- M0:文档骨架(当前)
- M3:与部署、安卓管理 APP 并行(待启动)

## 关键 ADR

- [ADR 0011 · Smali + dex 双方案](../docs/adr/0011-injection-smali-dex.md)
- [ADR 0028 · 注入工具架构](../docs/adr/0028-injector-architecture.md)
- [ADR 0029 · 加固 APK 兼容性](../docs/adr/0029-hardened-apk-compatibility.md)
- [ADR 0030 · 防滥用机制](../docs/adr/0030-anti-abuse.md)

## 法律风险声明

⚠️ 自动脱壳功能涉及绕过技术保护措施,使用前必须阅读[用户协议第 3 条](../docs/compliance/user-agreement.md)并签署免责协议。
