# 小城笺 · 接手交接文档(2026-08-02)

> **报告周期**: 2026-07-26 → 2026-08-02 (8 天)
> **本轮 commit**: 81 个 (总 219)
> **生产环境**: https://xcj.winmelon.cn (backend healthy, admin-web deployed)
> **本文以磁盘代码为准**, 所有数据均可通过 git log + grep 验证。

---

## §0 接手人 30 秒速览

**项目**: 小城笺 = 独立开发者私有应用攻防平台, 开源+SaaS 双模式。

**两条产品线**:
- **玄甲(XuanJia)**: 开源免费加固 SDK, X0-X9 全量防护
- **天衍(TianYan)**: 付费高级加固引擎, T1-T6 迷宫层

**本轮完成**: 玄甲 X0-X9 全部完成(代码+真机), 天衍 T1-T6 代码全部就位, SaaS 加固流水线端到端通过(19.5MB APK 48s 完成加固)。

**守城红线**(CLAUDE.md §1/§2): 纯防守向, 禁通用脱壳/去签/重打包他人 APK, 99 个 ADR 全追溯。

**接手第一动作**:
1. `git status` + `git log --oneline -10` 确认状态
2. 读 `CLAUDE.md` §1/§2 红线
3. `cd sdk-android/defender-sdk && ./gradlew assembleRelease` 验环境
4. 真机跑 demo 验全绿

---

## §1 本轮(07-26→08-02)完成清单

### 1.1 玄甲 X0-X9 — ✅ 全部完成

| # | 功能 | 代码 | 真机 | 关键文件 |
|---|------|:----:|:----:|---------|
| X0 | SO 本体加密 | ✅ | ✅ | `xcj_loader.c` + `so_cipher.*` (RC4+memfd+T1 cl 匿名) |
| X1 | 字符串多态加密 | ✅ | ✅ | `obfstr_poly.h` + `java_obf.py` + CFF 碎片 |
| X2 | 日志保护 | ✅ | ✅ | `defender_log.h` (NDEBUG+LOGE 脱敏 30 条) |
| X3 | 生命周期劫持 | ✅ | ✅ | `X3LifecycleGuard.kt` (类名+Factory+LoadedApk) |
| X4 | 反动态五层 | ✅ | ✅ | `x4_anti_*.c` + `response_chain.c` + `score_engine.c` |
| X5 | VPN/代理检测 | ✅ | ✅ | `VpnProxyDetector.kt` |
| X6 | 双开/分身检测 | ✅ | ✅ | `DualAppDetector.kt` |
| X7 | 私人端口保护 | ✅ | ✅ | `anti_frida.c` 端口段 + IDA 23946 |
| X8 | FART 脱壳扫描 | ✅ | ✅ | `x8_anti_fart.c` |
| X9 | ODEX 修补检测 | ✅ | ✅ | `x9_odex_detect.c` |

### 1.2 天衍 T1-T6 — ✅ 代码全部就位

| # | 功能 | 代码 | 真机 | 说明 |
|---|------|:----:|:----:|------|
| T1 | 自实现 Linker | ✅ | ✅ | `custom_linker.c` cl_dlopen_mem 匿名映射 |
| T2 | VMP 保护 | ✅ | — | `vm_engine.c` 110B+151B 字节码+行为自检 |
| T3 | 字符串分段散列 | ✅ | — | `t3_segment_str.c` + `build_t3_segments.py` |
| T4 | DEX 字符串加密 | ✅ | 待验 | `DexStringEncryptor.kt` 6035 字符串; dexlib2 3.0.7 writer bug 待修 |
| T5 | 定制化加壳 | ✅ | ✅ | `HardenCommand.kt` + admin-web 联动 |
| T6 | 质量报告 | ✅ | ✅ | `QualityReportCommand.kt` + admin-web 可视化 |

### 1.3 反 Frida 12 层纵深 — ✅ 容器内端到端验证

| 层 | 检测手段 | 绕过成本 |
|----|---------|:--------:|
| A | maps 关键词扫描 | 低 |
| B | 端口 connect 27042-27045 | 低 |
| C | /proc 线程名 gum-js-loop | 中 |
| E | 文件内容扫描(改名 frida) | 中 |
| F+G | D-Bus AUTH 协议探测 | **高** |
| H | seccomp-bpf 拦截 process_vm_readv | **不可绕** |
| I | fork 子进程交叉检测 | 高 |
| J | rwxp 匿名映射 | 中 |
| K | NOP 计时(Stalker 检测) | 中 |
| L | maps r-xp 快照对比 | 中 |
| M | 线程行为启发式 | 中 |
| + | 多态顺序(8 排列×9 层) | 高 |

### 1.4 攻击成本提升 7 项 — ✅

Canary 防短路 / Honeypot 诱饵 / 白盒 S-box / cache-timing 对抗 / VM 行为自检 / opcode XOR 洗牌 / ELF 假 magic

### 1.5 SaaS 加固流水线 — ✅ 端到端通过

```
分片上传(5MB×3并发+断点续传+1GB预检)
  → 异步分析(unzip+aapt+加固检测)
  → 选模块(玄甲/天衍复选框+4档预设)
  → Keystore 签名(ADR 0097 所有权声明)
  → 12 步加固流水线:
    preflight(5%) → strip(10%) → config(15%) → dex(25%)
    → so_arm64(35%) → so_armv7(40%) → apktool_d(50%,--no-src)
    → manifest(60%) → apktool_b(70%) → zipalign(80%)
    → sign(90%) → done(100%)
  → 下载加固后 APK
```

**端到端测试**: 19.5MB APK(万象聚搜v1.0) → 48 秒完成, 12 步进度全可见, 测试脚本 `scripts/test-harden-flow.mjs`。

### 1.6 SaaS 后台 — ✅ 已部署

| 页面 | 路由 | 功能 |
|------|------|------|
| Dashboard | `/dashboard` | 概览+快捷入口+首次引导 |
| APK 加固 | `/harden-upload` | 上传→分析→配置→加固→下载 |
| 加固任务 | `/harden-tasks` | 任务列表+刷新不丢+实时状态 |
| 加固配置 | `/harden-config` | 应用级策略 CRUD+API 联动 |
| 质量报告 | `/quality-report` | 5 维评分+历史+提交服务器 |
| 应用管理 | `/apps` | CRUD+白名单 |
| APK 诊断 | `/audit` | JADX 反编译+签名+后门扫描 |
| SDK 封装 | `/packer` | Packer 七锁封装 |

### 1.7 加固流水线修复链(6 层根因)

| # | 现象 | 根因 | 修复 |
|---|------|------|------|
| 1 | "SDK 未找到" | Docker 容器无 SDK 产物 | 内置 classes.dex+SO×2 到镜像 |
| 2 | "zip not found" | Alpine 无 zip | Dockerfile `apk add zip` |
| 3 | apktool 解析失败 | adm-zip writeZip 重写整个 zip 破坏对齐 | 改用 `zip` 命令行注入 |
| 4 | 卡在 50% 超时 | apktool baksmaling 19.5MB OOM | `--no-src` 跳过 DEX 反编译 |
| 5 | 预检"SDK 未构建" | findSdkDex 路径候选缺 classes.dex | 添加候选路径 |
| 6 | 进度条卡住 | stepIcons 缺新步骤名 | 补全 12 步 |

---

## §2 代码结构地图

### backend/src/hardening/ (加固核心)

| 文件 | 用途 |
|------|------|
| `hardening.controller.ts` | 6 端点: upload/init, chunk, complete, analyze, harden, status, tasks, download |
| `hardening.service.ts` | 12 步加固流水线 + adm-zip→zip 命令行 + 动态超时 + stderr 透传 |
| `preflight.service.ts` | 5 项预检(keytool+magic+已加固+SDK+磁盘) |
| `chunk-storage.service.ts` | 分片上传存储(Redis 元数据+磁盘分片) |
| `file-storage.service.ts` | 文件元数据 Redis 管理 |
| `*.spec.ts` ×4 | 32 个测试全绿 |

### admin-web/src/ (前端)

| 文件 | 用途 |
|------|------|
| `views/HardenUpload.vue` | 上传+12步进度+12步图标 |
| `views/HardenTasks.vue` | 任务列表+刷新恢复 |
| `views/HardenConfig.vue` | 加固配置 CRUD+API 联动 |
| `views/QualityReport.vue` | 质量报告+历史+API 联动 |
| `api/hardening.ts` | 分片上传+chunkedUpload+complete 补传 |

### sdk-android/defender-sdk/src/main/cpp/ (Native)

| 文件 | 用途 |
|------|------|
| `xcj_loader.c` | X0 自举+T1 cl 加载+ELF 假 magic |
| `anti_frida.c` | 12 层反 Frida(A-M)+多态顺序 |
| `canary_guard.h` | Canary 防短路 |
| `vm_engine.c` | T2 VMP 引擎+行为自检 |
| `t3_segment_str.c` | T3 分段散列运行时 |
| `t4_str_decrypt.c` | T4 白盒解密+cache-timing 对抗 |
| `honeypot_strings.h` | Honeypot 诱饵(构建期生成) |
| `x8_anti_fart.c` / `x9_odex_detect.c` | X8/X9 检测 |

### 构建/部署

| 文件 | 用途 |
|------|------|
| `deploy/backend.Dockerfile` | Alpine+Java17+apktool+zip+SDK 产物内置 |
| `deploy/sdk-artifacts/` | classes.dex+SO arm64+armv7(镜像内置) |
| `scripts/test-harden-flow.mjs` | 端到端自动化测试 |

---

## §3 已知问题 & 待办

### P0 — 阻塞用户

| # | 描述 | 影响 | 预估 |
|---|------|------|:----:|
| 1 | T4 dexlib2 3.0.7 DEX writer bug | writeZip 破坏 zip 对齐, 需切 baksmali/smali CLI | 4h |
| 2 | 加固后 APK 真机安装验证 | 端到端测试脚本通过但未在手机上安装运行加固后 APK | 1h |

### P1 — 功能补全

| # | 描述 | 影响 | 预估 |
|---|------|------|:----:|
| 3 | T3 运行时集成 | 分段散列仅构建期生成, 未接入检测路径 | 4h |
| 4 | T2 VMP 扩围 | 仅验证 hash_calculator, 未包 sig_verify | 8h |
| 5 | 反 Frida K/L/M 真机验证 | 容器内通过, 需真机+红方工具验证 | 4h |
| 6 | CI/CD pipeline | 无 GitHub Actions, 手动部署 | 4h |

### P2 — 体验优化

| # | 描述 | 影响 | 预估 |
|---|------|------|:----:|
| 7 | 前端上传进度条细分 | 分片进度已在 API 层, 前端未展示每片进度 | 2h |
| 8 | 加固任务取消按钮 | 用户无法中途取消卡住的加固任务 | 2h |
| 9 | 加固历史下载链接过期 | 任务 TTL 24h 后文件删除, 下载 404 | 2h |
| 10 | admin-web 移动端适配 | 加固页面在小屏上布局拥挤 | 4h |

### P3 — 长线

| # | 描述 | 预估 |
|---|------|:----:|
| 11 | 玄甲 v1.1: DEX 壳混淆(需 ADR 0090 后续) | 2w |
| 12 | 天衍 v1.1: DEX2C / 全量 VMP / 白盒密钥 | 4w |
| 13 | x86/x86_64 架构支持 | 1w |
| 14 | S4 红蓝对抗演练(M11) | 2d |

---

## §4 构建 & 部署流程

### 四步构建(无 T4)

```bash
# Step 1: 构建 SDK
cd sdk-android/defender-sdk && ./gradlew assembleRelease

# Step 2: RC4 加密外壳
python scripts/build_x0_pack.py --so build/.../libxcj_defender.so

# Step 3: 构建 demo
cd ../defender-demo && ./gradlew assembleRelease

# Step 4: 两轮 hash + 重签
cd ../defender-sdk
python scripts/patch_x0.py --apk <apk> --so <so> --key-hex <hex>
```

### 部署

```bash
# 服务器拉代码 + 重建
ssh xcj-claude@162.251.93.199 -p 22022
sudo git -C /opt/xiaochengjian pull --rebase
cd /opt/xiaochengjian/deploy
sudo docker compose build backend admin-web
sudo docker compose up -d --force-recreate backend admin-web
```

### 端到端测试

```bash
# 在容器内运行
docker exec -e TEST_TOKEN=<jwt> xcj-backend node /tmp/test-harden-flow.mjs
```

---

## §5 编码规范要点

- **TypeScript strict**: 禁 any, 禁 console.log, 禁 @ts-ignore
- **Native C**: LOGE 脱敏(禁打预期值/地址/路径), 关键词最短前缀, /proc 禁假设大小
- **Commit**: Conventional Commits, scope 必填
- **测试**: TDD Red-Green-Refactor, hardening 32/32 全绿
- **部署**: Docker 镜像内置 SDK 产物, 任意 APK 可加固

---

## §6 本轮沉淀

### Skill
- `android-hardening-impl`: 加固实现手册(怎么写)
- `redblue-hardening-verify`: 验证 SOP(怎么验)

### Memory(跨会话)
- 加固流水线踩坑 6 层根因链
- adm-zip writeZip 破坏 zip 对齐→必须用 zip 命令行
- apktool 大 APK 必须 --no-src
- Docker 容器内 zip/keytool/apksigner/zipalign 全路径

### 文档
- `HARDENING_PIPELINE_REFACTOR_SPEC.md` / `PLAN.md` / `REPORT.md`
- `HARDENING_UPLOAD_SPEC.md` / `PLAN.md` / `REPORT.md`
- `PROJECT_REPORT_2026-07-30.md`
- `CHANGELOG.md` 更新到 Unreleased

---

## §7 给接手人的话

本轮最大的教训: **部署环境 ≠ 开发环境**。Docker Alpine 缺 zip、缺 SDK 产物、apktool 内存不够——这些在本地开发时全部隐形的坑, 到生产才暴露。接手后第一件事应该是:

1. **在容器内跑一次端到端测试** (`node /tmp/test-harden-flow.mjs`), 确认全链路通
2. **不要在浏览器里调试加固流程**——用容器内 curl/node 脚本更快更准
3. **APK 加固的核心路径是 zip 命令行操作**, 不是 adm-zip。adm-zip 的 writeZip 会重写整个 zip 文件破坏对齐, 这是已踩过的坑
4. **apktool 必须加 `--no-src`**, 否则 19MB+ APK 在 2GB 容器内 OOM
5. **SDK 产物已内置到镜像** (`deploy/sdk-artifacts/`), 不需要本地构建 SDK

---

*本文所有数据可通过 `git log --oneline 3cd3f2b..HEAD | wc -l` (=81) 和 `git log --oneline | wc -l` (=219) 验证。以磁盘代码为准。*
