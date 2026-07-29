# 变更日志 (Changelog)

小城笺项目变更记录。格式遵循 [Keep a Changelog](https://keepachangelog.com/)，版本号遵循 [SemVer](https://semver.org/)。

## [Unreleased]

### Added

- 加固流水线: 上传 APK → 异步分析 → 配置模块 → 注入 → 重签 → 下载
- HardenTasks 页面: 加固任务列表(Redis 持久化, 刷新不丢)
- 实时分析进度: 步骤图标 + 进度条 + 已获取信息展示
- HardenConfig/HardenQuality 页面 API 联动(选择应用 → 加载/保存配置)
- `.editorconfig` 根目录 + injector + sdk-android 子项目
- `admin-web/.eslintrc.cjs` + `.prettierrc`
- `.husky/pre-commit` + `.lintstagedrc.cjs`
- `sdk-android/defender-sdk/.clang-format`
- `spec.md` 项目规格说明
- `plan.md` 项目规划/里程碑
- `tasks.md` 任务看板
- ADR 0097: 加固注入扩展至用户自有 APK + 风险自担声明

### Changed

- Dashboard 重构: 新用户引导 + 快捷入口卡片
- 侧边栏分组: 加固/应用/开发者工具/系统
- CLAUDE.md §4 扩充编码范式(异步任务/Redis 持久化/API 设计/Vue 组件/错误处理/Native C)

### Fixed

- FormData Content-Type 覆盖导致 multipart boundary 丢失 → 上传失败
- Alpine 容器 aapt glibc 兼容 → 安装 gcompat
- Dockerfile PATH 未包含 build-tools → aapt 不可执行
- hardenApk 缺 async → TS1308 编译错误

## [0.9.0] - 2026-07-29

### Added

- 玄甲 X5-X9: VPN/双开/FART/ODEX/端口检测
- 天衍 T1-T6: 自实现 Linker/VMP/分段散列/DEX 加密/定制加壳/质量报告
- 反 Frida 12 层纵深(A-M) + 多态顺序 + seccomp-bpf
- 攻击成本提升: Canary/Honeypot/白盒 S-box/VM 行为自检/opcode XOR/ELF 假 magic
- ADR 0090 accepted(律师意见书确认 DEX 加密合法)
- ADR 0092-0096 accepted
- android-hardening-impl skill(加固实现手册)
- 交接文档 2026-07-27

### Fixed

- LOGE 脱敏 30 条(预期值/实际值/路径/地址/关键词)
- X6 MIUI/华为系统分身误报
- X3 PackageManager 相对类名误判
- cl_dlopen_mem FindClass BootstrapClassLoader 回退
- X8/X9 OBF 宏/头文件/链接修复

## [0.8.0] - 2026-07-26

### Added

- 玄甲 X0: SO 本体加密(RC4 + memfd + T1 cl 匿名加载)
- 玄甲 X1: 字符串多态加密(亿级空间 + java_obf native 化)
- 玄甲 X2: 日志保护(NDEBUG + LOGE 脱敏框架)
- 玄甲 X3: 生命周期劫持检测
- 玄甲 X4: 反动态五层(L1-L5) + 响应链 + 强证据 + 弱信号 + 评分引擎
- 三刀: 运行时调用者鉴别 + 同步首轮校验 + kill delay 0-1s

### Fixed

- 方案 A hash 流程: 两轮 in-place patch 解决鸡生蛋
- mmap_apk NULL 路径未初始化

## [0.7.0] - 2026-07-22

### Added

- defender-sdk Batch 4: 9 模块(强证据/弱信号/评分/响应链/配置/遥测/回滚/干跑)
- Packer defender 集成 + admin-web UI
- V1.5 加固自检扩展: 腾讯乐固 + 360 加固保
- 水印追溯 + CSV 导出

## [0.6.0] - 2026-07-20

### Added

- ADR 0077-0087 合规闭环(七锁架构/律师预审)
- 加固厂商适配: 梆梆/乐固/360
- 深度安全审计引擎
- 水印追溯系统

## [0.5.0] - 2026-07-14

### Added

- SaaS 后台: 应用管理/审计/Packer/统计
- Docker Compose 部署
- HTTPS + nginx 反向代理

## [0.1.0] - 2026-07-13

### Added

- 卡密验证系统: 生成/验证/设备绑定/解绑/批量
- JWT 认证 + OAuth(GitHub/QQ) + 2FA(TOTP)
- NestJS 后端 + Vue 3 后台 + PostgreSQL + Redis
