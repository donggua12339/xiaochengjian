# 小城笺文档

> 开源 + SaaS 双模式 Android 卡密验证系统

## 快速导航

- [架构总览](architecture.md)
- [ADR 索引](adr/README.md)(67 个决策记录)
- [SDK 集成指南](sdk-guide.md)
- [部署指南](../deploy/README.md)
- [SaaS 上线清单](../deploy/SAAS-CHECKLIST.md)
- [HTTPS 配置](../deploy/HTTPS.md)
- [用户协议](compliance/user-agreement.md)
- [CLA](cla.md)

## 五层安全防护

| 层 | 防护 | ADR |
|---|---|---|
| 通信安全 | HTTPS + RSA + AES-256-GCM + HMAC | 0020-0021 |
| 防破解 | Rust so + 字符串混淆 + 控制流 + 反调试 | 0023-0024/0061 |
| 服务器安全 | RLS + 2FA + 限流 + 审计 | 0018/0022/0027 |
| 数据隐私 | 卡密 hash + 离线缓存加密 | 0026 |
| 弹性容灾 | Compose + K8s + 备份 + 监控 | 0012/0032 |

## 里程碑

- ✅ M0 基建(Monorepo + CI + ADR)
- ✅ M1 后端 + 后台(NestJS + Vue3 + RLS + 2FA)
- ✅ M2 SDK + Rust 核心(so + AAR + Demo APP)
- ✅ M3 注入 + 部署(dexlib2 + Compose + 监控)
- ✅ 迭代1-4(dexlib2 + 飞书告警 + 单测 + HTTPS)
- ✅ grill-me 第二轮(28 决策 ADR 0040-0067)
- ✅ 阶段1 SaaS 上线(会员激活码 + 部署清单)
- ✅ 阶段2 安全 + dex 深化(密钥轮换 + 自校验 + 反调试深化 + APK 签名下发)
- ✅ 阶段3 开源发布(README + SECURITY + CONTRIBUTING + Pages + Release)
