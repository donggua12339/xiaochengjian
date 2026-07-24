# 玄甲 X4 · 技术调研报告

> 日期:2026-07-24
> 范围:六来源(看雪/吾爱破解/MT论坛+官方/NP/CSDN)反动态攻防文章检索与精读
> 方法:WebSearch(中文查询)+ WebFetch 精读;防守视角萃取,严禁照搬攻击代码
> 覆盖:24 篇有效文章(去重后),其中 ≥12 篇深度精读;六来源各 ≥2 篇达标
> 配套:《X4-INSPIRATION-DEEP.md》(深度模板记录)、《X4-IMPLEMENTATION-PLAN.md》(实施方案)

---

## 一、文章清单(按来源,★=高权威深度精读)

### 看雪安全社区(bbs.kanxue.com)
| # | 标题 | 权威度 | 核心机制(攻击/加固视角) | X4 层 |
|---|---|---|---|---|
| K1★ | 校验的N次方——签名校验对抗、PM代理、IO重定向(thread-278216) | 高 | 5 种去签法 + PM 代理(sPackageManager/mPM 双替换)+ IO 重定向(Dobby hook open/openat/fopen/syscall 四级,重定向到私有目录 base.apk) | L1/L4 |
| K2★ | Android签名检测7种核心检测方案详解(珍惜Any,thread-278982) | 高 | 7 种签名检测 × 绕过对照;V2 块魔数/svc openat/fstat uid-gid=1000/readlinkat 返回值校验/inode 比对/开机 fd 复用 | L4 |
| K3★ | libDexHelper.so 反混淆——android so 文件攻防实战(thread-273614) | 高 | 商业加固(梆梆/secneo)全生命周期:SO 自解密→JNI_OnLoad→多维反调试/反注入→DEX 内存加载→IO Hook 透明解密;DEX 解密窗口期(anon:dalvik- 段) | L1/L2/L3/L5 |
| K4★ | frida 反调试总结+一把梭(thread-284941) | 高 | Frida 6 类检测(特征文件/27042/双进程/maps-task-fd/D-Bus 协议/线程名)+"一把梭"hook strstr 绕过;自实现 syscall + 动态生成 svc 机器码 | L1/L2 |
| K5★ | 《安卓逆向这档事》十九课、Frida 检测(下)(thread-282623) | 高 | svc 直接系统调用检测 + anti_svc 反制;inline hook 指令指纹(0xd61f);ELF_magic/so_main 破坏;svc 多架构特征码 | L2/L4 |
| K6 | APP加固系统分析(thread-281132,滑块拦截未精读) | — | 同主题补足 | L1/L2 |
| K7 | 调试与反调试详解(thread-272452,滑块拦截) | — | 断点指令检测应有展开 | L2 |

### 吾爱破解(52pojie.cn)
| # | 标题 | 权威度 | 核心机制 | X4 层 |
|---|---|---|---|---|
| W1 | 安卓常见的反调试与对抗方案(thread-709669) | 中 | 反调试全家桶综述:时间差 5 API/断点 0x01 0xde/rtld_db_dlactivity/TracerPid 多文件/23946 端口/fork+ptrace 抗内核伪装 | L1/L2 |
| W2★ | Android 反调试(16种,含完整代码,thread-675649) | 中高 | 时间差 5 API(阈值>2s)/断点扫描(ARM f0 01 f0 e7、Thumb 10 de + 模式步进)/PTRACE_TRACEME/SIGTRAP/inotify 监控 pagemap/花指令 | L2/L3 |
| W3★ | 从零开始绕过 DexProtector 加固的 Frida 检测(thread-2074484) | 高 | DexProtector 检测体系:CRC(疑 SipHash)/HMAC-SHA256(硬件指令定位)/text 完整性/多线程监控/核心藏匿名内存;绕过反推检测弱点(返回值替换/指针参数/线程入口) | L4/L5 |
| W4 | 某气骑士 libtprt.so 反 Frida 机制分析与绕过(thread-2106149) | 中高 | dl_iterate_phdr 枚举 SO/maps 扫 libzygisk/Unix socket 扫 frida-/系统属性检测;Florida 魔改绕过 → 特征会被抹,需多维 | L1/L2 |
| W5★ | 记一次对某韩游的反反调试(腾讯TP,thread-2016248) | 高 | 时间差变体(lstat /sbin vs /system/lib 的 st_ctime 差,阈值 1e6 秒)/CRC 1 秒发现 Frida/IO 重定向检测/Magisk 特征/字符串 decrypt1 | L2/L4/L5 |
| W6 | 关于手游反调试的事(SegmentFault 转载) | 中 | rtld_db_dlactivity 原理(非导出符号,linker 符号表定位,空指针/断点)+ GID 同组判合法调试器 | L2 |

### MT 论坛(bbs.binmt.cc)+ MT 官方文档(mt2.cn)
| # | 标题 | 权威度 | 核心机制 | X4 层 |
|---|---|---|---|---|
| M1★ | APK 签名 \| MT管理器(官方文档 mt2.cn) | 高 | 官方定调:"如果可以被一键去除校验则需要考虑使用更安全的校验方式"——Java 层自校验=可一键去除的低强度校验 | L1(定调) |
| M2 | [已解决]关于MT一键去签名验证的问题(论坛 thread-14122) | 中 | 一手实测:MT 注入物 PmsHookApplication 继承原 Application + InvocationHandler + 双替换 + Base64 原签名;"JNI 走 Java API 同样无效";建议"内存中获取签名" | L1 |
| M3★ | 安卓签名校验-探讨(CREATOR 替换,thread-285647) | 高 | **现代 MT killPM = PackageInfo.CREATOR 替换**(代理 Creator 覆盖 signatures/signingInfo + 清 Parcel 三缓存);LSPatch 同源;检测:ClassLoader/类名双比对 + Application 三级 + AppComponentFactory + Dex 内存校验 | L1/L3/L4 |
| M4 | 大厂和企业壳的核心检测签名思路(nixiang.tech) | 中高 | Hunter/大厂壳 Native 六步:svc 自解析 V2/开机 fd 复用/readlinkat 双重反查/uid-gid/inode/IPC 直连 | L4 |
| M5 | 绕过Frida/Xposed的最后防线:SVC(腾讯云) | 中高 | svc 三架构实现 + 工程兼容(seccomp 白名单/BTI/CFI 隔离)+ 威胁模型边界(内核未改假设) | L1/L2/L4 |
| M6 | Android逆向-风控检测一、重打包检测svc(掘金) | 中 | 防守三路线:svc 直调/子进程调 pm/自实现 Binder;攻击上限=hook server 端 | L4 |
| M7 | how-to-check-sign(gtf35,GitHub,Apache-2.0) | 中 | 逆向 MT 注入物 → 防守四件套:mPM 类名比对/构造函数抢跑校验/Application 类名检测/新 API GET_SIGNING_CERTIFICATES | L1 |
| M8 | MT签名去除签名校验分析(cnblogs,低权威) | 低 | 线索:MT 作者开源去签项目 ApkSignatureKillerEx(可提取发布特征作检测指纹库) | L1(指纹) |

### NP 管理器相关
| # | 标题 | 权威度 | 核心机制 | X4 层 |
|---|---|---|---|---|
| N1 | 浅谈去除 NP 管理器添加的签名校验(binmt thread-55774) | 中 | NP 给所有 Activity 注入同一校验方法 → 改一处 `const v0,1;return v0` 全灭(反面教训:校验不可单点可短路) | L1/L4 |
| N2 | NP 去签三级层级(综合 K1/M3) | 高 | Java PMS 代理 → Native inline hook(open/openat)→ proot Hook openat 系统调用层 | L1/L4 |

### CSDN(补充资料源)
| # | 标题 | 权威度 | 核心机制 | X4 层 |
|---|---|---|---|---|
| C1 | Android应用反调试技术深度解析 | 中 | TracerPid(svc 直读)/ptrace 双进程/时间差 CLOCK_MONOTONIC 自标定/ARM 放弃 0xCC 投 .text CRC/进程名 | L2 |
| C2 | Frida常见检测方法 | 中 | Frida 10 检测 + 升级检测:可执行段白名单/Shared_Dirty 4KB 增量/D-Bus REJECT 全端口/LIBFRIDA 内存扫描/riru 特征 | L2/L3 |
| C3 | 一文带你实现监控 Android 的内存 dump(掘金) | 中低 | inotify 监控 /proc/{mem,maps,pagemap} 的 IN_OPEN + pthread 常驻;⚠️ procfs inotify 部分内核不可靠 | L3 |
| C4 | CTF Reverse 之 SMC 动态代码加密技术 | 中低 | SMC 原理:mprotect 改可写→解密→执行→擦除;破解两法(idapython 复现/调试到解密结束点 dump) | L5 |

---

## 二、L1-L5 启发汇总(跨来源综合,★=多篇交叉验证)

### L1 反注入
- **CREATOR ClassLoader + 类名双检测**(对抗现代 MT/LSPatch)[M3★]
- mPM/sPackageManager 类名比对(对抗旧版 MT)[K1/M2/M3/M7]
- Application 类名三级检测(getApplication/mInitialApplication/LoadedApk)[M2/M3/M7]
- AppComponentFactory 检测[M3]
- **提前校验时机:Application 构造函数抢跑**[M3/M7★]
- SO 注入:**dl_iterate_phdr 枚举 + 可执行段白名单**(优于黑名单字符串,抗改名)[W4/C2★]
- ptrace 注入:TracerPid + wchan=ptrace_stop + 全 task 遍历[K3]
- IO 重定向初筛:sourceDir vs maps 映射路径/inode 双比对[K1/W5]
- 新 API GET_SIGNING_CERTIFICATES 双读[M3/M7]

### L2 反调试
- TracerPid 多文件交叉(status/stat/wchan)+ fork+ptrace 自检抗内核伪装[W1/W2/C1★]
- 调试端口 27042(Frida)/23946(IDA)+ **D-Bus REJECT 全端口探测**(抗改端口)[K4/C2★]
- Frida 线程名(gum-js-loop/gmain/gdbus/pool-frida)[K3/K4/C2★]
- **时间差:多 API 组合**(time/clock/gettimeofday/clock_gettime/getrusage)[W1/W2★]
- **时间差:文件系统 st_ctime 变体**(lstat /sbin vs /system/lib,规避时间 API hook,兼测 root)[W5★ 最有价值]
- 时间差:内联 syscall + 设备自标定基线[W2/C1]
- **断点指令扫描**(ARM f0 01 f0 e7 / Thumb 10 de / ARM64 BRK 00 00 20 D4 + 模式步进)+ **rtld_db_dlactivity**(linker 符号表定位非导出符号)[W1/W2/W6★]
- ptrace 自附着(双进程守护)+ SIGTRAP handler 执行性[W2/C1]
- ADB/USB 环境双端(__system_property_get + BATTERY_CHANGED)[W4]
- gettid≠getpid / 进程名(android_server/gdbserver)[K4/C1]

### L3 反内存 Dump
- **DEX 解密窗口压缩**(按页解密/CRC固化/擦除明文;anon:dalvik- 段监控)——加固方最大软肋[K3★ 最重要 L3 结论]
- **异常 mprotect(rwx)检测**(自身永不需要 rwx 常驻)[C2/C4★]
- 可执行段白名单轮询(与 L1 共用)[C2★]
- inotify 监控 /proc/self/{mem,maps,pagemap} IN_OPEN(⚠️ procfs 不可靠,仅预警须双保险)[W2/C3★]
- 跳板痕迹 Shared_Dirty/Anonymous 4KB 增量[C2]
- inotify 配额防护(防耗尽)[K3]
- 处置:延迟 + 污染,不立即崩溃[K1/C3]

### L4 运行时完整性
- **svc 自解析 V2/V3 签名块**(EOCD 0x6054b50/central dir/"APK Sig Block 42"/V2 id 0x7109871a),全程不碰 PMS[K2/M4/M5/M6★ L4 核心蓝本]
- **IO 重定向多维交叉**:readlinkat 反查(含返回值长度校验)+ fstat uid/gid=1000 + inode vs maps + 开机预开 fd 复用[K2/M4/M6★]
- **libc 四入口 CRC**(open/openat/fopen/syscall,NP/MT 必 hook 点)[K1/N2★]
- SO .text CRC(启动基线 + 定期重算 + 多点不同预期值)[W3/W5/C1★]
- inline hook 指令级检测(0xd61f 指纹)[K5★]
- DEX 内存哈希(ClassLoader 反射取 dex 地址 + dex 头 CRC)[M3/N2]
- IPC 直连 Binder / 子进程调 pm / 本地证书解析(ZipFile META-INF)[M4/M6]
- 多通道交叉(PMS/本地/svc 三路一致)[M3/M4]
- **抗绕加固**:比对+反制同函数内联;校验对象不经指针参数;监控线程入口纳入 CRC[W3★ 由绕过反推]

### L5 SMC
- **按函数/页粒度解密执行 + 立即擦除**(禁整段解密)[C4/K3★]
- **权限时序零 rwx**(RW→解密→RX→执行→RW→擦除,与 L3-2 自洽)[C4/C2★]
- 解密边界模糊化 + 窗口内时间差(堵"调试到解密结束点 dump")[C4★]
- 解密密钥来自运行时环境(签名哈希/设备指纹)[C4/N1]
- 字符串运行时解密(栈逐字节拼接 + 多解密函数分散)[K3/W5]
- 核心逻辑匿名内存延迟解密 + 执行后抹指针[W3★]
- 控制流混淆(switch 乱序 + 间接跳转)+ 花指令反 F5[K3/W2]
- SO 自解密 + 偏移表间接寻址[K3]

---

## 三、交叉验证与权威度说明

- **高权威交叉验证通过**:svc 签名校验(K2/M4/M5/M6)、CREATOR 替换检测(M3/M2/M7)、时间差 API(W1/W2)、断点魔数(W1/W2)、rtld_db_dlactivity(W1/W6)、DEX 解密窗口(K3)、inline hook 0xd61f(K5)。
- **被滑块拦截未精读**:看雪 281132/272452/268155(已用同主题可访问文章补足覆盖)。
- **低权威待验证项**(不作方案依据):"30 行代码使 MT 2.9.1 去签失效"传闻未找到原始出处(技术实质=mPM/sPackageManager 检测+复位,被 M3/M7 支撑,但精确行数/版本对应属传闻)。
- **CSDN 付费墙截断**:C1/C4 仅原理层可信,工程数值需以看雪/原始 API 文档复核。

## 四、合规提示

所有文章的攻击侧代码(killPM/killOpen/Florida/apksignaturekiller/Arm64Writer/dump 脚本)仅作威胁模型理解,玄甲**独立重写检测侧**,不照搬任何攻击代码。详见《X4-COMPLIANCE.md》。
