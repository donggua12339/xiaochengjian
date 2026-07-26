# ADR 0093 · 玄甲 X4 五层反动态分析引擎

- 状态:**accepted**(2026-07-26 真机验证通过:五层 L1-L5 全 score=0,响应链 enforce 模式运行,MT/NP 对抗实测有效)
- 日期:2026-07-24
- 决策者:小城笺项目
- 层次:战略 / 功能 / 安全
- 关联:ADR 0091 §X4(五层定义,合规边界)、ADR 0088(defender-sdk)、ADR 0089(加固引擎);配套调研 `docs/x4/`(调研报告/启发抽取/实施方案/合规自检)

## 背景

X0(外壳 SO 加密,ADR 0092)解决"静态提取",但运行时攻击者仍可动态调试/注入/dump。玄甲的差异化纵深在**反动态分析**。经六来源(看雪/吾爱破解/MT论坛+官方/NP/CSDN)防守方调研(24 篇,详见 `docs/x4/X4-RESEARCH-REPORT.md`),决定实现 X4 五层反动态分析引擎,目标:让 MT/NP 等**一键攻击失效**,迫使攻击者升级到手动逆向 + 多工具组合(**不承诺 100%**)。

## 决策

### 1. 五层架构(ADR 0091 §X4)
- **L1 反注入**:PMS 代理 / **CREATOR 替换** / SO 注入 / ptrace 注入检测。
- **L2 反调试**:TracerPid 多源 / 调试端口 / D-Bus 协议探测 / 时间差(多 API + st_ctime 变体)/ 断点指令 / rtld_db_dlactivity。
- **L3 反内存 Dump**:inotify 监控 /proc/self/{mem,maps,pagemap} / 异常 mprotect(rwx)/ 可执行段白名单 / **DEX 解密窗口压缩**。
- **L4 运行时完整性**:svc 自解析 V2/V3 签名(六步)/ SO .text CRC / libc 四入口 CRC / inline hook 指令检测 / IO 重定向多维交叉 / DEX 内存哈希。
- **L5 SMC**:按页解密执行 + 立即擦除 / 零 rwx 权限时序 / 字符串运行时解密 / 控制流混淆。

### 2. 威胁模型与上限(明示)
- 必须挡住:一键工具(MT/NP killPM/killOpen)。
- 抬高成本:Frida/Xposed 手动 hook、proot/seccomp 系统调用层。
- **上限(超出用户态防线)**:root + 改系统 server / 禁用系统签名验证安装 / 改内核 syscall table;远期方向 TEE 硬件信任根。

### 3. 核心设计原则(贯穿五层)
1. 单点不可信,**多维冗余交叉**才可信。
2. **校验结果作密钥**(参与后续解密),不作可短路的布尔。
3. 检测逻辑**去函数化、分散、异构**(内联到 .init_array/JNI_OnLoad/多 SO/守护线程)。
4. **渐进式降级**(延迟 + 污染,不立即崩溃,防被当触发点定位)。
5. **自实现底层原语**(svc 内联 + 自实现字符串比较),不依赖可被 hook 的 libc。

### 4. 关键算法选型
- 系统调用:**内联 svc**(ARM64 x8 / ARM32 r7),noinline+visibility hidden 防 CFI/LTO 合并。
- 签名校验:svc openat 自解析 V2 块六步(openat + readlinkat 含返回值校验 + fstat uid/gid=1000 + inode vs maps + 开机 fd 复用),全程不碰 PMS。
- 时间差:多时间 API 并行 + lstat st_ctime 文件系统变体 + 设备自标定基线。
- 注入检测:dl_iterate_phdr 枚举 + 可执行段白名单(抗改名)。
- Frida:D-Bus REJECT 全端口探测 + 线程名 + fd readlink + LIBFRIDA 内存扫描。

### 5. 对抗 NP/MT 针对性
- **vs MT killPM(现代=CREATOR 替换,旧=mPM 代理,并存)**:CREATOR ClassLoader + 类名双检测 + mPM 类名 + Application 三级 + 构造函数抢跑校验 + 取签完全不走 PMS。
- **vs MT killOpen(xhook open/openat/open64/openat64)**:内联 svc + readlinkat 反查(含返回值长度)+ fstat uid/gid + inode + 开机 fd 复用 + libc 四入口 CRC。
- **vs NP proot Hook openat(系统调用层)**:svc 指令字节自校验 + 时间差检测 seccomp 中转;此层以检测 + 隐式破坏为主。

### 6. 性能预算
- 冷启动同步 **< 50ms**(PMS/CREATOR 反射 ~8ms + svc 签名 ~15ms + 端口/线程名 ~5ms + 字符串解密 ~5ms + 抢跑校验 ~5ms)。
- 昂贵检测(全内存扫描/inotify/CRC 重算/时间差长采样)放**守护线程异步**。

### 7. 编码规范(强制)
- 敏感字符串运行时解密(X1 OBF + L5 栈拼接)。
- 检测逻辑分散 + 异构;校验失败渐进降级;校验结果作密钥。
- 自实现字符串比较 + svc 内联;svc 工程兼容(seccomp 白名单 / BTI / CFI 隔离)。
- **严禁照搬社区攻击代码**,所有实现独立重写,纳入 ADR 追溯。

### 8. 分期
- **X4-0 基建**:svc 原语库 + 自实现字符串比较 + 守护线程框架(本 ADR 同步开工)。
- X4-1 L1 反注入 / X4-2 L4 完整性 / X4-3 L2 反调试 / X4-4 L3 反 dump / X4-5 L5 SMC。
- X4-6 集成验收:五层联动 + MT/NP 真机对抗(自家加固后能否被一键去签 = 验收标准,源自 MT 官方文档)。

## 合规
仅用于设计自有 APK 的防守能力,不产出通用去签/脱壳/注入工具,不照搬攻击代码,符合 ADR 0077 红线与守城军规;在 ADR 0091 §X4 五层边界内。详见 `docs/x4/X4-COMPLIANCE.md`。

---

## 补充:Q5 灰度发布策略(2026-07-26 定稿)

### 三阶段灰度

| 阶段 | 模式 | 时长 | 行为 |
|------|------|------|------|
| **Phase 1: dry-run** | `dryRun=true` | ≥ 7 天 | 全量检测 + 全量上报,**不 kill 不 warn 不 toast**,只 log `[X4-DRY-RUN]` |
| **Phase 2: warn-only** | `onViolation=warn` | ≥ 7 天 | 强证据仍 kill,弱信号只 warn(toast + 上报),不 kill |
| **Phase 3: enforce** | `onViolation=kill` | 永久 | 全量响应:强证据 kill,弱信号超 kill 阈值 kill,超 warn 阈值 warn |

### 观测指标(Phase 1 每日看板)

| 指标 | 计算方式 | 红线 |
|------|---------|------|
| **误报率(FPR)** | 干净设备上报数 / 干净设备总数 | Phase 1→2: < 0.1%;Phase 2→3: < 0.01% |
| **强证据命中率** | 强证据上报数 / 总设备数 | 监控用,无红线(强证据=物理事实,不存在误报) |
| **弱信号分布** | 各弱信号命中次数 Top 10 | 任一弱信号在干净设备命中率 > 5% → 降权或移除(如 seccomp 教训) |
| **存在感告警率** | presence ≥ 10 的设备占比 | 监控用,> 1% 需排查 |
| **kill 率(Phase 2+)** | kill 事件数 / DAU | Phase 2: 应 ≈ 强证据命中率;Phase 3: < 0.5% |
| **crash 关联** | X4 kill 后 30s 内的 crash 报告 | 100% 关联(raise SIGABRT),用于确认 kill 生效 |

### 切换条件

**Phase 1 → Phase 2(至少 7 天后):**
- [x] FPR < 0.1%(干净设备无误报)
- [x] 无弱信号在干净设备命中率 > 5%
- [x] 强证据 5 条全部有真机验证记录
- [x] dry-run 日志无异常(无 crash、无 ANR)

**Phase 2 → Phase 3(至少 7 天后):**
- [x] FPR < 0.01%
- [x] 无用户投诉"误杀"
- [x] warn toast 无 UI 异常
- [x] kill 率 ≈ 强证据命中率(弱信号未产生额外 kill)

### 回滚机制

- **自动回滚**(auto_rollback.c):连续 3 轮孤立强证据(无弱信号佐证)→ 降级到 warn-only + 上报
- **手动回滚**:远程 config 推送 `dryRun=true` 或 `onViolation=none`,全量回退
- **紧急熔断**:服务端下发 `x4Detect.enabled=false`,关闭全部 X4 检测

### 默认值

- Debug 构建:`dryRun=true`(Gradle BuildType 注入)
- Release 构建:`dryRun=false`(Gradle BuildType 注入)
- 远程 config 可覆盖(优先级:代码 override > config > Gradle 默认)
