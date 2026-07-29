# 小城笺 · 项目规格说明 (Specification)

> 版本: 2026-07-29 | 维护者: 项目所有者 + AI 协作

## 1. 系统概述

小城笺 (XiaoChengJian) 是面向独立开发者的**私有应用攻防与遗产维护平台**，采用开源 + SaaS 双模式运营。

### 1.1 核心能力矩阵

| 能力域             | 子模块                              | 技术栈                           |    状态     |
| ------------------ | ----------------------------------- | -------------------------------- | :---------: |
| **卡密验证**       | 生成/验证/设备绑定/解绑/批量        | NestJS + Prisma + PG             |   ✅ 生产   |
| **玄甲加固**       | X0-X9 全套(见 §3)                   | Kotlin + C/NDK + Python 构建脚本 | ✅ 代码完成 |
| **天衍加固**       | T1-T6 全套(见 §4)                   | 同玄甲 + dexlib2                 | ✅ 代码完成 |
| **反 Frida**       | 12 层纵深 A-M                       | C native + 多态 + seccomp        | ✅ 真机验证 |
| **APK 加固流水线** | 上传→分析→配置→注入→重签→下载       | NestJS + Redis + Docker          |  ✅ 已部署  |
| **SaaS 后台**      | 应用管理/加固配置/质量报告/任务列表 | Vue 3 + Naive UI                 |  ✅ 已部署  |
| **自有 APK 诊断**  | JADX 反编译 + 签名 + 后门扫描       | Java + Kotlin                    |   ✅ 生产   |
| **加固厂商适配**   | 梆梆/乐固/360 加固自检              | TypeScript                       |   ✅ 生产   |

### 1.2 部署架构

```
┌──────────────────────────────────────────────────────────┐
│                    xcj.winmelon.cn                        │
│                                                          │
│  ┌─────────┐    ┌──────────────┐    ┌───────────────┐   │
│  │  nginx   │───▶│  admin-web   │    │   backend     │   │
│  │  (HTTPS) │    │  (Vue 3 SPA) │    │  (NestJS API) │   │
│  └────┬─────┘    └──────────────┘    └───────┬───────┘   │
│       │                                      │           │
│       │              ┌───────────┐           │           │
│       └─────────────▶│  Redis    │◀──────────           │
│                      └───────────┘                       │
│                      ┌───────────┐                       │
│                      │PostgreSQL │◀── backend            │
│                      └───────────┘                       │
│                                                          │
│  Docker Compose · 1C2G 雨云服务器 · IP 162.251.93.199  │
└──────────────────────────────────────────────────────────┘
```

### 1.3 安全约束

- **纯防守向**：禁止通用脱壳/去签/重打包他人 APK
- **七锁架构**：对象/内容/入口/签名/权限/数据/客户端签名自检
- **ADR 合规闭环**：所有重大决策必须写 ADR，变更写新 ADR 标 superseded
- **密钥隔离**：构建期密钥(.gitignore) + 运行时 CFF 碎片重建
- **多租户隔离**：tenant_id + RLS + JWT

## 2. 模块边界

### 2.1 backend (NestJS)

| 模块        | 路由前缀            | 职责                       |
| ----------- | ------------------- | -------------------------- |
| auth        | /v1/auth            | JWT + OAuth + 2FA          |
| application | /v1/apps            | 应用 CRUD + 白名单         |
| card-key    | /v1/cards           | 卡密生成/验证/设备绑定     |
| sdk         | /v1/sdk             | SDK 握手(RSA + AES)        |
| packer      | /v1/packer          | APK SDK 封装(七锁)         |
| hardening   | /v1/hardening       | APK 加固流水线(异步+Redis) |
| harden      | /v1/apps/:id/harden | 加固配置 CRUD              |
| audit-own   | /v1/audit-own       | 自有 APK 审计              |
| integrity   | /v1/integrity       | 服务端完整性验证(方案 C)   |
| security    | —                   | 启动安全基线检查           |
| membership  | /v1/membership      | 会员/订阅                  |

### 2.2 admin-web (Vue 3)

| 路由            | 页面          | 功能                       |
| --------------- | ------------- | -------------------------- |
| /dashboard      | Dashboard     | 概览 + 快捷入口 + 首次引导 |
| /harden-upload  | HardenUpload  | APK 加固上传(异步轮询进度) |
| /harden-tasks   | HardenTasks   | 加固任务列表(刷新不丢)     |
| /harden-config  | HardenConfig  | 加固策略配置(应用级 CRUD)  |
| /quality-report | QualityReport | 加固质量报告(可视化+历史)  |
| /apps           | Apps          | 应用管理                   |
| /audit          | Audit         | 自有 APK 诊断              |
| /packer         | Packer        | SDK 封装                   |

### 2.3 sdk-android/defender-sdk

| 层       | 文件                                                                      | 职责                               |
| -------- | ------------------------------------------------------------------------- | ---------------------------------- |
| X0       | xcj_loader.c, so_cipher.*                                                 | SO 加密 RC4+memfd+cl 自实现 Linker |
| X1       | obfstr_poly.h, java_obf.py                                                | 字符串多态加密                     |
| X2       | defender_log.h                                                            | 日志保护+脱敏                      |
| X3       | X3LifecycleGuard.kt                                                       | 生命周期劫持检测                   |
| X4       | x4_anti_*.c, strong_evidence.c, score_engine.c                            | 反动态五层+响应链                  |
| X5-X9    | VpnProxyDetector.kt, DualAppDetector.kt, x8_anti_fart.c, x9_odex_detect.c | 环境检测                           |
| 反 Frida | anti_frida.c                                                              | 12 层纵深(A-M)                     |
| T1       | custom_linker.c                                                           | 自实现 Linker                      |
| T2       | vm_engine.c                                                               | VMP 虚拟机                         |
| T3       | t3_segment_str.c                                                          | 字符串分段散列                     |
| T4       | t4_str_decrypt.c, DexStringEncryptor.kt                                   | DEX 字符串加密                     |
| 攻击成本 | canary_guard.h, honeypot_strings.h, wb_sbox.h                             | Canary+Honeypot+白盒               |

### 2.4 injector (Kotlin CLI)

| 命令            | 功能              |
| --------------- | ----------------- |
| init            | 生成 SDK 集成模板 |
| sign            | APK 签名+水印     |
| encrypt-strings | T4 DEX 字符串加密 |
| harden          | T5 定制化加壳     |
| quality-report  | T6 质量报告       |

## 3. 玄甲功能规格 (X0-X9)

| #   | 功能       | 输入                  | 输出                              | 运行时开销   |
| --- | ---------- | --------------------- | --------------------------------- | ------------ |
| X0  | SO 加密    | libxcj_defender.so    | RC4 密文 → assets/xcj_payload.bin | 启动时 ~50ms |
| X1  | 字符串多态 | C 源码字符串常量      | 加密数组+解密函数(亿级空间)       | 0(编译期)    |
| X2  | 日志保护   | —                     | NDEBUG 砍 LOGI/LOGW, LOGE 脱敏    | 0            |
| X3  | 生命周期   | Application 实例      | 类名/Factory/LoadedApk 校验       | <1ms         |
| X4  | 反动态     | 运行时环境            | 五层检测+score+响应链             | 每轮 ~5ms    |
| X5  | VPN        | NetworkInterface+proc | score+detected                    | <2ms         |
| X6  | 双开       | uid+目录+包名         | score+detected                    | <2ms         |
| X7  | 端口       | /proc/net/tcp         | 命中/未命中                       | <1ms         |
| X8  | FART       | 文件系统扫描          | score                             | <5ms         |
| X9  | ODEX       | 文件时间+大小         | score                             | <2ms         |

## 4. 天衍功能规格 (T1-T6)

| #   | 功能          | 对抗目标           | 绕过成本            |
| --- | ------------- | ------------------ | ------------------- |
| T1  | 自实现 Linker | maps 扫描/特征定位 | 高(匿名映射)        |
| T2  | VMP           | 静态反编译         | 极高(devirtualizer) |
| T3  | 分段散列      | 内存 dump          | 高(片段无法拼合)    |
| T4  | DEX 加密      | MT/NP 字符串解密   | 高(自定义算法)      |
| T5  | 定制加壳      | —                  | — (配置层)          |
| T6  | 质量报告      | —                  | — (审计层)          |

## 5. API 规格

### 5.1 加固流水线 API

| 方法 | 路径                       | 描述                       | 认证 |
| ---- | -------------------------- | -------------------------- | :--: |
| POST | /v1/hardening/analyze      | 上传 APK 开始异步分析      | JWT  |
| POST | /v1/hardening/harden       | 提交配置+Keystore 执行加固 | JWT  |
| GET  | /v1/hardening/status/:id   | 轮询任务进度               | JWT  |
| GET  | /v1/hardening/tasks        | 用户任务列表(Redis 持久化) | JWT  |
| GET  | /v1/hardening/download/:id | 下载加固 APK               | JWT  |

### 5.2 响应格式

```json
{
  "taskId": "uuid",
  "status": "analyzing|hardening|signing|completed|failed",
  "progress": 0-100,
  "message": "人类可读状态",
  "step": "机器可读步骤标识",
  "detail": "当前步骤详情(包名/DEX/ABI 等)"
}
```

## 6. 构建规格

### 6.1 SDK 构建流水线(4 步)

```
1. gradlew assembleRelease (defender-sdk)
2. python build_x0_pack.py --so <arm64 .so>
3. gradlew assembleRelease (defender-demo)
4. python patch_x0.py --apk <apk> --so <so> --key-hex <hex>
```

### 6.2 T4 加固流水线(5 步)

```
1-4. 同上
5. xcj-injector encrypt-strings --apk <apk> --output <out.apk>
```

### 6.3 环境要求

| 工具        | 版本  | 用途                   |
| ----------- | ----- | ---------------------- |
| Node.js     | 22+   | backend + admin-web    |
| pnpm        | 9+    | 包管理                 |
| JDK         | 17    | injector + sdk-android |
| Android SDK | 35    | NDK 构建               |
| NDK         | r27   | C/C++ native           |
| Python      | 3.10+ | 构建脚本               |
| Docker      | 24+   | 部署                   |
| PostgreSQL  | 16    | 数据库                 |
| Redis       | 7+    | 缓存+任务持久化        |
