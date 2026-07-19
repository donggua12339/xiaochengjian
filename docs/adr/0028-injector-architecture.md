# ADR 0028 · 注入工具架构

- 状态:**superseded by 0068**(v2 重构撤除服务器端 APK 处理,改 SDK 集成辅助)
- 日期:2026-07-13
- 决策者:小城笺项目
- 层次:安全

> **本 ADR 已被 [ADR 0068](0068-v2-injector-architecture-sdk-integration-only.md) 取代**(2026-07-19)。
> v2 重构移除了"上传 APK 到服务器处理"的注入架构,backend/src/inject/ 模块删除,injector CLI 仅保留 init + sign。
> 本文档保留作为决策追溯,不再有效。

## 背景

注入工具形态决定开发者工作流、防滥用机制、服务器架构。

## 决策

### 注入工具形态
- **安卓端注入工具 APP**:开发者手机上上传 APK 到 SaaS 服务器,服务器处理后返回
- **服务器端处理**:不持久化原始 APK,注入完成后立即删除
- **SaaS 独占**:开源版无此功能,开源版用 SDK 集成方式

### 注入流程
```
1. 开发者打开安卓注入工具 APP
2. 选择本地 APK 文件
3. APP 上传 APK 到 SaaS 服务器(HTTPS + 应用层加密)
4. 服务器:
   - 校验开发者 token + VIP 等级
   - 检测 APK 加固(ADR 0029)
   - 执行 dex/Smali 注入(ADR 0011)
   - 重打包签名(ADR 0030,需开发者提供 keystore)
   - 写入注入水印(ADR 0030)
   - 立即删除原始 APK
5. 返回注入后 APK 下载链接(短期有效,5 分钟)
6. 开发者下载并分发
```

### 注入点
- **主**:Application.onCreate(99% APK 必经)
- **备**:MainActivity.onCreate(加固 APK Application 被接管的降级)
- **无自定义 Application**:注入工具自动创建自定义 Application 类

### 注入逻辑
- 在原 Application.onCreate **首行**插入 `XiaochengjianSDK.init(this)`
- 生成独立 dex(包含 SDK 初始化代码),通过 multidex 加载,不污染原 dex

### 服务器资源管理
- **APK 上传大小限制**:200MB
- **并发注入任务**:每开发者最多 3 个并发
- **任务超时**:30 分钟自动取消
- **存储**:临时存储 `/tmp/inject/<taskId>/`,完成后删除

### 失败回滚(ADR 0030)
- 原子操作:全成功才输出最终 APK
- `--debug` 标志保留中间产物供调试
- 失败时输出详细错误码

### 版本同步(ADR 0037)
- 注入工具运行时从 Maven 拉取指定版本 SDK
- 本地缓存,首次联网后续离线可用
- `--sdk-version=1.2.0` 可指定版本

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| CLI 命令行 | 跨平台 | 开发者体验差 | 用户选安卓 APP |
| 桌面 GUI | 体验好 | 开发成本高 | 用户选安卓 APP |
| Web 工具 | 跨平台 | 上传大 APK 慢 | 用户选安卓 APP |
| 安卓 APP + 服务器处理(本方案) | 移动端友好 | 服务器负载 | 用户选择 |

## 影响

- 正面:开发者手机上即可注入,无需 PC
- 负面:服务器需承担注入计算,成本高
- 风险:服务器持有他人 APK = 侵权证据,必须立即删除

## 关联

- 关联 ADR:0011(Smali + dex)、0029(加固兼容)、0030(防滥用)
- 关联代码:`injector-android/`、`backend/src/inject/`
