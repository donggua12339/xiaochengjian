# 玄甲 X4 · 五层反动态分析引擎 · 技术实施方案

> 状态:草案 v1(2026-07-24,基于六来源调研综合)
> 合规边界:ADR 0091 §X4 五层定义 + ADR 0077 红线 + 守城军规(纯防守,仅借鉴思想,严禁照搬攻击代码)
> 来源标注:每条技术点标注调研文章编号(见《X4-RESEARCH-REPORT.md》《X4-INSPIRATION-DEEP.md》)
> 不承诺 100%:目标是"让一键攻击失效,迫使攻击者升级到手动逆向 + 多工具组合"。

---

## 0. 设计目标与威胁模型

**目标**:让 MT/NP/ARMPro/Modex 等**一键去签/一键过检**失效,把攻击成本从"点一下"抬到"手动逆向 + 多工具组合 + 逐点绕过"。

**威胁模型分层**(防守强度随层级递减,须明确声明上限):
| 层级 | 攻击者能力 | 玄甲防守目标 |
|---|---|---|
| 一键工具(MT/NP killPM/killOpen) | Java PMS 代理 / CREATOR 替换 / xhook open-openat | **必须挡住**(L1/L4 核心) |
| Frida/Xposed 手动 hook | inline hook / PLT hook / 改返回值 | 抬高成本(多维冗余检测,L2/L4) |
| proot/seccomp 系统调用层 | Hook openat syscall / TraceHook 沙箱 | 检测 + 隐式破坏(L2/L4,不追求完全阻断) |
| **root + 改系统 server / 禁用系统签名验证安装 / 改内核 syscall table** | 系统级降维打击 | **超出用户态防线,声明为威胁模型上限**(远期方向 TEE 硬件信任根)[MT-文章6/7/8] |

**总原则**(贯穿五层):
1. **单点不可信,交叉才可信**——任何检测点都会被单独绕过,多维冗余交叉是根本。[看雪4/吾爱3/MT-7]
2. **校验结果作密钥,不作布尔**——返回值参与后续解密(签名哈希→解密下一段),短路 `return true` 会导致解密失败而非通过。[NP-文章2 教训]
3. **检测逻辑去函数化、分散、异构**——内联展开到多处,无公共校验函数,每处变形,防单点通杀。[NP-文章2/MT-3]
4. **渐进式降级,不立即崩溃**——检测失败用延迟 + 污染(暗改非关键功能/随机延迟破坏),防被攻击者拿来当"触发点"定位。[看雪1/NP-文章5]
5. **自实现底层原语**——字符串比较、系统调用全部自实现(svc 内联),不依赖 libc 可被 hook 的函数。[看雪4/MT-8]

---

## 1. 五层检测点清单与触发时机

### L1 反注入(检测 ptrace 注入 / SO 注入 / PMS 代理 / CREATOR 替换)

| # | 检测点 | 机制 | 触发时机 | 来源 |
|---|---|---|---|---|
| L1-1 | **CREATOR ClassLoader 比对** | 系统 `PackageInfo.CREATOR` 由 BootClassLoader 加载;被替换的匿名 Creator 由 PathClassLoader 加载 | Application 构造函数 + 守护线程 | MT-文章5★ |
| L1-2 | **CREATOR 类名比对** | 系统为 `PackageInfo$1`,代理为匿名类(LSPatch 可绕 L1-1,故此条兜底) | 同上 | MT-文章5★ |
| L1-3 | mPM/sPackageManager 类名比对 | 正常 `IPackageManager$Stub$Proxy`,代理后 `$ProxyN`(对抗旧版 MT) | 同上 | MT-文章3/5/NP-1 |
| L1-4 | Application 类名三级检测 | `getApplication()` / `ActivityThread.mInitialApplication` / LoadedApk 单例;MT 注入物 `PmsHookApplication`/`HookApplication` 继承原 Application | 构造函数 + onCreate | MT-文章3/4/5 |
| L1-5 | AppComponentFactory 检测 | 防攻击者改 factory 做初始化注入 | attachBaseContext 前 | MT-文章5 |
| L1-6 | **提前校验时机** | Application **构造函数**内手动造 Context 校验,抢在 attachBaseContext hook 之前 | Application 构造 | MT-文章3★ |
| L1-7 | SO 注入:dl_iterate_phdr 枚举 | 底层枚举已加载 SO + 白名单比对(优于只读 maps,maps 可被 magiskhide/重命名绕过) | 守护线程 | 吾爱-文章4★ |
| L1-8 | SO 注入:maps 可执行段白名单 | 白名单外 r-x/rwx 段 = 注入落点(抗改名,比黑名单字符串强一个量级) | 守护线程 | NP-文章4★ |
| L1-9 | ptrace 注入指纹 | TracerPid + `/proc/<pid>/wchan==ptrace_stop` + 全 task 遍历 | 守护线程 | 看雪-文章3 |
| L1-10 | IO 重定向初筛 | sourceDir 字符串 vs `/proc/self/maps` 本包 APK 映射路径/inode 双比对(重定向露双路径) | 守护线程 | NP-文章1/吾爱5 |
| L1-11 | 新 API 双读 | API28+ `GET_SIGNING_CERTIFICATES` vs 旧 `GET_SIGNATURES` 比对(探测只 hook 旧 API 的工具) | 守护线程 | MT-文章3 |

### L2 反调试(TracerPid / 调试端口 / ptrace 自附着 / 时间差 / 断点指令)

| # | 检测点 | 机制 | 触发时机 | 来源 |
|---|---|---|---|---|
| L2-1 | TracerPid 多文件交叉 | `/proc/self/status` + `stat`(第二字段 T)+ `wchan`(ptrace_stop),全部 svc 直读 | 守护线程 | 吾爱-文章1/2★ |
| L2-2 | fork+ptrace 自检 | fork 子进程 ptrace 父进程,读 TracerPid 是否等于子 pid(抗内核级 TracerPid 恒 0 伪装) | 守护线程 | 吾爱-文章1 |
| L2-3 | 调试端口扫描 | `/proc/net/tcp` 扫 27042(Frida)+ 23946(IDA) | 守护线程 | 吾爱-文章1/2/看雪4 |
| L2-4 | **D-Bus 协议探测** | 向监听端口发 D-Bus 认证消息,回 `REJECT` 即 frida-server(抗改端口) | 守护线程 | 看雪-文章4/NP-4★ |
| L2-5 | Frida 线程名 | task 中扫 `gum-js-loop`/`gmain`/`gdbus`/`pool-frida` | 守护线程 | 看雪-文章3/4/NP-4★ |
| L2-6 | **时间差:多 API 组合** | time/clock/gettimeofday/clock_gettime/getrusage ≥3 种并行,任一异常告警(攻击者需全 hook 才绕) | 关键路径 | 吾爱-文章1/2★ |
| L2-7 | **时间差:文件系统 st_ctime 变体** | `lstat("/sbin")` vs `lstat("/system/lib")` 读 `struct stat+0x68`(st_ctime)算差,阈值 ~1e6 秒(规避时间 API hook,兼测 root/Magisk) | 关键路径 | 吾爱-文章5★(最有价值) |
| L2-8 | 时间差:内联 syscall + 自标定基线 | `syscall(__NR_clock_gettime)` 直取(绕 PLT hook);阈值用设备启动标定基线 × N | 关键路径 | 吾爱-文章2/NP-3 |
| L2-9 | **断点指令扫描** | ARM BKPT `f0 01 f0 e7` / Thumb `10 de` / ARM64 BRK `00 00 20 D4`;模式判定(地址奇偶)+ 步进 memcmp;扫自身 .text/PLT/rtld_db_dlactivity | 守护线程 | 吾爱-文章1/2★ |
| L2-10 | **rtld_db_dlactivity 检测** | 遍历 linker/linker64 符号表定位该非导出符号,读首字节是否被写断点(调试态被改写) | 守护线程 | 吾爱-文章1/6★ |
| L2-11 | ptrace 自附着(双进程守护) | fork 子进程 ptrace 父进程占坑(优于单 PTRACE_TRACEME) | 启动 | 吾爱-文章2/NP-3 |
| L2-12 | SIGTRAP handler 执行性 | raise(SIGTRAP) 后 handler 是否执行(调试器吞信号则不执行) | 守护线程 | 吾爱-文章2 |
| L2-13 | ADB/USB 环境双端 | `__system_property_get`(init.svc.adbd/ro.debuggable)+ Java 层 BATTERY_CHANGED plugged 交叉 | 守护线程 | 吾爱-文章4 |
| L2-14 | gettid≠getpid / 进程名 | 轻量调试指纹;扫 android_server/gdbserver/lldb-server | 守护线程 | 看雪-文章4/NP-3 |

### L3 反内存 Dump(Inotify 监控 / 异常 mprotect / DEX 窗口压缩)

| # | 检测点 | 机制 | 触发时机 | 来源 |
|---|---|---|---|---|
| L3-1 | **inotify 监控 /proc/self/{mem,maps,pagemap}** | IN_OPEN 事件,常驻 detach 线程(⚠️ procfs inotify 部分内核不可靠,仅作预警层,须双保险) | 常驻线程 | 吾爱-文章2/NP-文章5★ |
| L3-2 | **异常 mprotect(rwx)检测** | 玄甲自身永不需要 rwx 常驻页(解密用 RW/RX 切换),出现 rwx 即异常 | 守护线程 | NP-文章4/6★ |
| L3-3 | 可执行段白名单轮询 | 与 L1-8 共用;白名单外 r-x/rwx 段 = dump 工具/注入落点 | 守护线程 | NP-文章4★ |
| L3-4 | **DEX 解密窗口压缩** | 按页解密 → CRC 固化 → 立即擦除明文;监控 `anon:dalvik-` 段被外部读取(加固方最大软肋) | 解密时 | 看雪-文章3★(最重要 L3 结论) |
| L3-5 | 跳板痕迹检测 | `Shared_Dirty`/`Anonymous` 4KB 异常增量(frida 写跳板痕迹,重启才消失) | 守护线程 | NP-文章4 |
| L3-6 | inotify 配额防护 | 读 `/proc/sys/fs/inotify/max_*`,防攻击者耗尽配额使监控失效 | 启动 | 看雪-文章3 |
| L3-7 | 处置:延迟 + 污染 | 检测到 dump 征兆不立即崩溃,返回垃圾数据/延迟随机破坏 | 触发时 | NP-文章5/看雪1 |

### L4 运行时完整性(SO .text CRC / DEX 内存哈希 / APK V2 签名块 / IO 重定向检测)

| # | 检测点 | 机制 | 触发时机 | 来源 |
|---|---|---|---|---|
| L4-1 | **svc 自解析 V2/V3 签名块** | 内联 svc openat 读自身 APK → EOCD(0x6054b50)→ central dir → "APK Sig Block 42" → V2 id 0x7109871a → cert;**全程不碰 PackageManager** | 启动 + 守护线程 | MT-文章7/8/9★(L4 核心蓝本) |
| L4-2 | **readlinkat 路径反查** | fd 真实路径 vs 传入路径,不等即被重定向 | 同 L4-1 | MT-文章7/9★ |
| L4-3 | **readlinkat 返回值截断检测** | 按返回长度截断 buffer——攻击者改路径忘改返回长度即露馅 | 同 L4-1 | MT-文章7/9★ |
| L4-4 | **fstat uid/gid==1000** | 确认 fd 指向系统安装 base.apk 而非私有目录副本(MT 重定向目标 `/data/user/0/<pkg>/files/base.apk`) | 同 L4-1 | MT-文章2/7/9★ |
| L4-5 | **inode vs maps 比对** | fd 的 st_ino vs `/proc/self/maps` 行中 inode(maps 倒数第二项) | 同 L4-1 | MT-文章7/9★ |
| L4-6 | **开机预开 fd 复用** | 遍历 `/proc/self/fd` readlinkat 找系统预开的 base.apk 直接解析("不走 IO 重定向逻辑,相对安全";先关 fdsan) | 启动 | MT-文章7/9★(奇兵) |
| L4-7 | libc 四入口 CRC | open/openat/fopen/syscall 前 16 字节 CRC(NP/MT 去签必 hook 点),不符即重定向环境 | 守护线程 | NP-文章1/看雪1★ |
| L4-8 | SO .text CRC | 启动基线 + 定期重算;多点调用 + 不同预期值(攻击者需逐个打表) | 守护线程 | 吾爱-文章3/5★ |
| L4-9 | inline hook 指令级检测 | 关键函数入口扫 `mov reg,#imm; br reg`(第二条指令高 16 位 0xd61f) | 守护线程 | 看雪-文章5★ |
| L4-10 | DEX 内存哈希 | ClassLoader 反射取 dex 内存地址,对 dex 头动态 CRC | 守护线程 | MT-文章5/NP-1 |
| L4-11 | IPC 直连 Binder | 反射 mPM.mRemote 手工 transact / 自实现 binder 协议(不走任何官方 Java API) | 启动 | MT-文章6/7 |
| L4-12 | 子进程调 pm | fork 子进程执行 pm(重打包工具常不 hook 子进程),父进程收结果比对 | 启动 | MT-文章6 |
| L4-13 | 多通道交叉 | PMS API / 本地证书解析(ZipFile META-INF/*.RSA)/ svc 三路取签一致才可信 | 启动 | MT-文章3/5/7 |
| L4-14 | **抗绕加固** | 比对+反制同函数内联(不经可 hook 返回值);校验对象不经指针参数传入;监控线程入口自身纳入 CRC | — | 吾爱-文章3★(由绕过反推) |

### L5 SMC(关键函数运行时解密执行 / 执行完销毁 / 抗静态 dump)

| # | 检测点/技术 | 机制 | 触发时机 | 来源 |
|---|---|---|---|---|
| L5-1 | **按函数/页粒度解密执行 + 立即擦除** | 禁整段解密;解密→执行→立即覆写明文回密文 | 运行时 | NP-文章6/看雪3★ |
| L5-2 | **权限时序零 rwx** | RW 写→解密→RX 执行→RW 擦除,全程无 rwx 页(与 L3-2 自洽) | 运行时 | NP-文章6/4★ |
| L5-3 | 解密边界模糊化 + 窗口内时间差 | 解密与执行交织、解密完即擦尾;时间差检测窗口内单步(堵"调试到解密结束点 dump") | 运行时 | NP-文章6★ |
| L5-4 | 解密密钥来自运行时环境 | 密钥 = 签名哈希/设备指纹,静态拿不到(idapython 复现不可行) | 运行时 | NP-文章6/NP-文章2 |
| L5-5 | 字符串运行时解密 | 栈上逐字节拼密文 + 多个分散解密函数(避免批量提取) | 运行时 | 看雪-文章3/吾爱5 |
| L5-6 | 核心逻辑匿名内存延迟解密 | JNI_OnLoad 经函数指针跳匿名段,执行后抹指针(off=0) | 启动 | 吾爱-文章3★ |
| L5-7 | 控制流混淆 | switch 化乱序 + 动态计算跳转地址(BR X0 间接跳转) | 编译期 | 看雪-文章3 |
| L5-8 | 花指令反 F5 | `.byte 0x00 0xBF`(Thumb NOP)/`.int 0xE1A00000`(ARM NOP)+ 分支混淆,破坏递归下降反编译 | 编译期 | 吾爱-文章2 |
| L5-9 | SO 自解密 + 偏移表间接寻址 | 函数地址经偏移表运行时计算,静态无法定位 | 启动 | 看雪-文章3 |

---

## 2. 检测算法选型(最优组合)

| 能力 | 选型 | 理由 |
|---|---|---|
| 系统调用 | **内联 svc**(ARM64 `x8=号;svc #0` / ARM `r7` / x86_64 `rax`) | 绕过 libc PLT/inline hook;攻击者 hook 不了 svc 路径 [MT-8/9] |
| 字符串比较 | **自实现 strcmp/strstr**(逐字节 + 混淆) | 防"一把梭"hook libc strstr 改返回值 [看雪4] |
| 签名校验 | **svc openat + 自解析 V2 块**(Magisk 系算法)为主干,本地证书解析 + IPC 直连为备份,三路交叉 | 完全不碰 PMS,抗 killPM [MT-7/8/9] |
| 完整性哈希 | .text 用 CRC32(快)+ 关键段 SipHash/HMAC-SHA256(多点不同预期值) | 1 秒内发现 Frida hook;多点打表成本高 [吾爱3/5] |
| 时间差 | 多时间 API 并行 + st_ctime 文件系统变体 + 内联 syscall + 设备自标定基线 | 单一 API 必被 hook 定值绕过 [吾爱1/2/5] |
| 注入检测 | dl_iterate_phdr 枚举 + 可执行段白名单(优于黑名单字符串) | 抗 magiskhide/改名 [吾爱4/NP-4] |
| Frida 检测 | D-Bus REJECT 全端口探测 + 线程名 + fd readlink + LIBFRIDA 内存扫描 + 27042 快检 | 抗改端口/改名 [看雪4/NP-4] |
| 反 dump | inotify 预警(不可靠)+ maps 白名单轮询(主)+ DEX 窗口压缩 | procfs inotify 部分内核不可靠,须双保险 [NP-5/看雪3] |

---

## 3. 对抗 NP/MT 的针对性设计

### 3.1 对抗 MT killPM(Java PMS 代理 / **CREATOR 替换**)
> 重要修正:现代 MT 的 killPM 已演进为 `PackageInfo.CREATOR` 替换(替换 CREATOR 为代理 Creator,在 createFromParcel 覆盖 signatures/signingInfo,并清除 `sPackageInfoCache`/`mCreators`/`sPairedCreators` 三处缓存);旧版 sPackageManager/mPM 代理仍并存。**防守必须双检测**。[MT-文章5]

**检测优先级**:
1. **CREATOR ClassLoader + 类名双检测**(L1-1/L1-2,对抗现代 MT/LSPatch)
2. mPM/sPackageManager 类名比对(L1-3,对抗旧版 MT)
3. Application 类名三级检测(L1-4,`PmsHookApplication`/`HookApplication` 继承特征)
4. 校验时机提前到 Application 构造函数(L1-6,使 attachBaseContext 的 hook 对首轮校验无效)
5. **釜底抽薪:取签完全不走 PMS**——svc 自解析(L4-1)/ Binder 直连(L4-11)/ 本地证书(L4-13)
6. 新 API `GET_SIGNING_CERTIFICATES` 双读(L1-11)

### 3.2 对抗 MT killOpen(IO 重定向:xhook open/openat/open64/openat64 + inline hook syscall 包装器)
1. **内联 svc openat/read/close** 打开 sourceDir 自解析 V2 块(L4-1,绕 PLT 与 inline hook)
2. **readlinkat 反查 fd 真实路径 + 返回值长度截断检测**(L4-2/L4-3)
3. **fstat uid/gid==1000**(L4-4)
4. **inode vs maps 比对**(L4-5)
5. **开机预开 fd 复用**遍历 `/proc/self/fd`(L4-6,"不走 IO 重定向逻辑")
6. **libc open 与 svc openat 双路开同一文件**,比对两 fd 的 readlinkat/inode/内容哈希(L4-7 + 推导)
7. 监控私有目录 `files/base.apk` 副本出现(MT 重定向目标特征)

### 3.3 对抗 NP proot Hook openat(系统调用层)
> NP 去签三级:Java PMS 代理 → Native inline hook(open/openat)→ **proot Hook openat 系统调用层**。[NP-文章1]

- **svc 指令字节自校验**:防 svc 指令被 patch 成 BL 跳板(检测自身 svc 机器码完整性)
- **时间差检测 seccomp 中转开销**:proot/ptrace+seccomp 拦截 syscall 有可测时延
- **此层对抗成本高**,玄甲以"检测 + 隐式破坏"为主,不追求完全阻断;声明 root+改服务端为威胁模型上限

### 3.4 反面教训(NP 注入机制)
> NP 给所有 Activity 注入同一校验方法 → 被改一处 `const v0,1; return v0` 全灭。[NP-文章2]

**玄甲对称设计**:校验点去函数化(内联展开 + 每处异构)+ 校验结果密钥化(短路即解密失败)+ Java/Native 交叉绑定(Java 结果送 native 参与 CRC,反之亦然)。

---

## 4. 性能预算(冷启动 < 50ms)

**原则**:冷启动只做廉价同步检测;昂贵检测(全内存扫描/inotify/CRC 重算/时间差长采样)放守护线程异步。

| 阶段 | 检测点 | 预算 |
|---|---|---|
| 冷启动同步(<50ms) | L1-1~6 PMS/CREATOR/Application 反射检测 | ~8ms |
| | L4-1 svc 签名校验(mmap + V2 块解析) | ~15ms |
| | L4-6 开机 fd 复用(遍历 /proc/self/fd) | ~5ms |
| | L2-3/5 端口 + 线程名快检 | ~5ms |
| | L5 字符串解密(首批关键串) | ~5ms |
| | L1-6 构造函数抢跑校验 | ~5ms |
| 守护线程异步(不占冷启动) | L2 时间差长采样 / 断点扫描 / rtld_db_dlactivity | 周期 |
| | L3 inotify 监控 / mprotect 检测 / maps 白名单轮询 | 常驻 |
| | L4 .text CRC 重算 / 四入口 CRC / inline hook 扫描 | 周期 |
| | L2-4 D-Bus 全端口探测 / L2-1 全 task TracerPid | 周期 |

**工程兼容红线**(必采,否则在部分机型崩溃/失效)[MT-文章8]:
- 华为 EMUI/vivo seccomp-bpf 会 kill 敏感 syscall——openat/read/close 在白名单可用,ptrace 类慎用
- Android 14+ 裸 svc 汇编必须加 `bti c` + `-mbranch-protection=standard`,否则 SIGILL
- NDK r25+ 默认 CFI/LTO 会内联合并 svc 代码致 CRC 失效——用 `__attribute__((noinline, visibility("hidden")))` 隔离

---

## 5. 编码规范(强制)

1. **敏感字符串运行时解密**——所有检测关键词(frida/gum-js-loop/TracerPid/路径/端口)用 X1 OBF + L5 栈拼接,静态不可见。[看雪3/吾爱5]
2. **检测逻辑分散**——分布到 `.init_array` / `JNI_OnLoad` / 多个 SO / 守护线程,每处异构,无公共校验函数。[NP-2/MT-3]
3. **校验失败渐进式降级**——不立即崩溃;延迟 + 污染(暗改非关键功能/随机延迟破坏)。[看雪1/NP-5]
4. **校验结果作密钥**——返回值参与后续解密,短路即解密失败。[NP-2]
5. **自实现底层原语**——字符串比较 + 系统调用全部自实现(svc 内联)。[看雪4/MT-8]
6. **svc 工程兼容**——seccomp 白名单 / BTI / CFI 隔离三条必采。[MT-8]
7. **多维冗余交叉**——单点不可信,每层 ≥3 检测点交叉。[全来源]
8. **抗绕加固**——比对+反制同函数内联;校验对象不经指针参数;监控线程入口纳入 CRC。[吾爱3]
9. **严禁照搬社区攻击代码**——仅借鉴检测思想,所有实现由玄甲独立重写,纳入 ADR 追溯(CLAUDE.md §10)。[合规红线]
10. **检测顺序运行时洗牌**——防攻击者定位固定检测点。[MT-7]

---

## 6. 落地分期建议

| 期 | 内容 | 依赖 |
|---|---|---|
| X4-0 基建 | svc 内联原语库(含 seccomp/BTI/CFI 兼容)+ 自实现字符串比较 + 守护线程框架 | 无 |
| X4-1 L1 反注入 | CREATOR/mPM/Application 检测 + 构造函数抢跑 + dl_iterate_phdr 枚举 + 可执行段白名单 | X4-0 |
| X4-2 L4 完整性 | svc 签名校验(六步)+ libc 四入口 CRC + .text CRC + inline hook 检测 | X4-0 |
| X4-3 L2 反调试 | TracerPid 多源 + 时间差(多 API+st_ctime)+ 断点扫描 + rtld_db_dlactivity + Frida 五件套 | X4-0 |
| X4-4 L3 反 dump | inotify 监控 + mprotect 检测 + DEX 窗口压缩 + maps 轮询 | X4-0 |
| X4-5 L5 SMC | 按页解密执行 + 零 rwx 权限时序 + 字符串解密 + 控制流混淆 | X4-0 + X1 |
| X4-6 集成验收 | 五层联动 + MT/NP 真机对抗测试(自家加固后能否被一键去签 = 验收标准) | X4-1~5 |

**验收标准**(来自 MT 官方文档原文):"如果可以被一键去除校验则需要考虑使用更安全的校验方式"——玄甲自家加固后的 demo APK 若仍能被 MT/NP 一键去签,视为 X4 不达标。[MT-文章1]
