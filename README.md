# 小城笺 · Xiaochengjian

> 开源 + SaaS 双模式的 Android 卡密验证系统,保障创作者权益,杜绝付费应用盗版。

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Backend](https://img.shields.io/badge/backend-NestJS-red.svg)](backend/)
[![SDK](https://img.shields.io/badge/SDK-Rust%20%2B%20Kotlin-orange.svg)](sdk-android/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

## 项目定位

| 维度 | 内容 |
|---|---|
| 形态 | 开源 + SaaS 双模式(ADR 0002) |
| 目标用户 | 个人 Android 应用开发者 |
| 价值主张 | 保障创作者权益,杜绝付费应用盗版 |
| 商业模式 | 开发者订阅(月度 + 终身 + VIP,ADR 0043/0047) |

## 合规红线

本项目仅用于**开发者对自己开发的付费应用做版权保护**。禁止用于:

- ❌ 外挂、私服、破解工具
- ❌ 规避反作弊系统
- ❌ 赌博、诈骗
- ❌ 批量重打包他人 APK

详见 [用户协议](docs/compliance/user-agreement.md)。

## 五层安全防护

| 层 | 防护 | ADR |
|---|---|---|
| 通信安全 | HTTPS + RSA 协商 AES + AES-256-GCM + HMAC 签名 | 0020-0021 |
| 防破解 | Rust so 核心 + 字符串混淆 + 控制流平坦化 + 反调试 | 0023-0024/0061 |
| 服务器安全 | PostgreSQL RLS + 2FA + 限流 + 审计 + 脱敏 | 0018/0022/0027 |
| 数据隐私 | 卡密只存 hash + 离线缓存 AES 加密 | 0026 |
| 弹性容灾 | Compose + K8s + 每日备份 + Prometheus 监控 | 0012/0032 |

## 3 分钟快速开始

### SaaS 版(推荐,免部署)

1. 访问 SaaS 平台(上线后公开域名)
2. 注册开发者账号(邮箱 + 2FA)
3. 创建应用,获取 `appId + appSecret`
4. 集成 SDK(见 [SDK 集成指南](docs/sdk-guide.md))

### 开源版(自部署)

```bash
git clone https://github.com/xiaochengjian/xiaochengjian.git
cd xiaochengjian/deploy
cp .env.example .env  # 编辑密码 + JWT 密钥
mkdir -p ../backend/keys
openssl genrsa -out ../backend/keys/private.pem 2048
openssl rsa -in ../backend/keys/private.pem -pubout -out ../backend/keys/public.pem
docker compose up -d
curl http://localhost/health  # {"status":"ok","db":"ok"}
```

详见 [部署指南](deploy/README.md) + [SaaS 上线清单](deploy/SAAS-CHECKLIST.md)。

## 功能特性

- **卡密验证**:时间卡(日/周/月/永久)+ 试用卡 + 设备绑定
- **多租户**:PostgreSQL RLS 强制隔离
- **2FA**:TOTP + 备份码
- **SDK**:Rust so 核心 + Kotlin AAR,3 ABI
- **注入工具**:dex 主 + Smali 备,V1+V2+V3 签名 + 水印
- **监控**:Prometheus + Grafana + Loki + 飞书告警
- **HTTPS**:Let's Encrypt + 自动续期

## 仓库结构

```
xiaochengjian/
├── backend/              # NestJS 后端(TS strict)
├── admin-web/            # Vue3 + Naive UI 管理后台
├── sdk-android/          # Android SDK
│   ├── rust/             # Rust so 核心(cdylib)
│   └── kotlin/           # Kotlin AAR
├── injector/             # APK 注入工具(Kotlin + dexlib2)
├── injector-android/     # 安卓端管理 + 注入 APP(Compose)
├── deploy/               # Docker Compose + 监控 + 部署指南
└── docs/                 # 文档 + ADR(67 个)
```

## 文档

- [架构总览](docs/architecture.md)
- [ADR 索引](docs/adr/README.md)(67 个决策记录)
- [SDK 集成指南](docs/sdk-guide.md)
- [部署指南](deploy/README.md)
- [HTTPS 配置](deploy/HTTPS.md)
- [SaaS 上线清单](deploy/SAAS-CHECKLIST.md)
- [用户协议](docs/compliance/user-agreement.md)
- [安全披露](SECURITY.md)

## 贡献

欢迎提交 PR!请先阅读 [贡献指南](CONTRIBUTING.md)。首次 PR 需签署 [CLA](docs/cla.md)。

核心 Rust 安全模块不接受外部 PR,只接受 issue(ADR 0004)。

## License

[Apache License 2.0](LICENSE)
