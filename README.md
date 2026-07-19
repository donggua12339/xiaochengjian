# 小城笺 · Xiaochengjian

> **独立开发者的私有应用攻防与遗产维护工具**(ADR 0076,2026-07-19)
> 开源 + SaaS 双模式,蓝方(防:卡密验证/加固/防二次打包)+ 红方(攻:自有 APK 诊断,仅限开发者拥有合法著作权的自有 APK)

> ✅ **v2 已上线(2026-07-17)**
> 小城笺 v2 重构完成,SaaS 服务已恢复。
> 访问地址:https://xcj.winmelon.cn
> v2 改动:HTTPS + 域名 / 后端补齐 change-password/profile + /metrics 端点 / SDK 模块测试覆盖率 98% / injector-android (引导开发者主动集成 SDK)。
> 旧版本代码保留在 `v1-final` tag。

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Backend](https://img.shields.io/badge/backend-NestJS-red.svg)](backend/)
[![SDK](https://img.shields.io/badge/SDK-Rust%20%2B%20Kotlin-orange.svg)](sdk-android/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

## 项目定位(ADR 0076)

| 维度 | 内容 |
|---|---|
| 形态 | 开源 + SaaS 双模式(ADR 0002) |
| 定位 | 独立开发者的私有应用攻防与遗产维护工具(ADR 0076) |
| 目标用户 | 个人 Android 应用开发者 |
| 蓝方能力(防) | 卡密验证、加固、防二次打包 -- 保障创作者权益 |
| 红方能力(攻) | **自有 APK 诊断**(JADX 反编译查看 + 签名信息 + SDK 后门扫描,ADR 0077) |
| 商业模式 | 开发者订阅(月度 + 终身 + VIP,ADR 0043/0047) |

## 合规红线(强制,详见 CLAUDE.md 第 2 节)

**任何情况下不得违反以下红线:**

- ❌ 不得实现"绕过其他验证系统"的功能(通用脱壳 / 通用去签 / 通用绕过反作弊)
- ❌ 不得在客户端硬编码任何"通用绕过反作弊"的逻辑
- ❌ 不得对他人 APK 进行重打包、注入、修改字节码(注入工具仅限开发者自有 APK,详见 ADR 0068)
- ❌ 不得在日志中记录卡密明文
- ❌ **红方功能(自有 APK 诊断)仅限处理用户拥有合法著作权的自有 APK**,三重校验强制不得跳过(详见 ADR 0077):
  - 校验 1:包名白名单(APK 包名必须在 admin-web 注册)
  - 校验 2:签名 hash 比对(APK 签名必须与开发者配置的预期 hash 匹配)
  - 校验 3:本地私有目录隔离(/tmp/audit/<taskId>/,处理后立即删除)
  - 任一校验失败即拒绝,不提供跳过开关

**允许的能力**:
- ✅ 自有 APK 诊断(ADR 0077):仅限开发者拥有合法著作权的自有 APK,三重校验强制
- ✅ 开发者对自有应用做卡密验证、加固、防二次打包
- ✅ SDK 集成辅助工具(init 生成模板 + sign 签名加水印,详见 ADR 0068)

详见 [用户协议](docs/compliance/user-agreement.md) + [CLAUDE.md](CLAUDE.md) 第 2 节。

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
