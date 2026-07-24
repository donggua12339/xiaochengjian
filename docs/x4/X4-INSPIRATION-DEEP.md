# 玄甲 X4 · 启发抽取记录(深度分析)

> 日期:2026-07-24
> 说明:按文章模板结构化记录 12 篇高价值文章的核心机制与防守转化。合规红线:仅借鉴防守思想,严禁照搬攻击代码;攻击侧代码仅作机制级描述。
> 配套:《X4-RESEARCH-REPORT.md》(清单)、《X4-IMPLEMENTATION-PLAN.md》(实施方案,技术点标注文章编号)

---

## 文章 1:《libDexHelper.so 反混淆——android so 文件攻防实战》(看雪 K3)
- **来源**:看雪 thread-273614 / **权威度**:高(本次调研深度最高,商业加固完整逆向)
- **核心机制(攻击者视角)**:完整逆向某商业加固(梆梆/secneo)保护 SO 的全生命周期——SO 自解密 → JNI_OnLoad 搭环境 → 多维反调试/反注入 → 解密并内存加载 DEX → hook libart 还原指令抽取 → 装大量 IO Hook 做运行时透明解密。
- **关键代码/算法要点**:
  - 执行流程:`JNI_OnLoad@0x3EA68` 读 `/proc/pid/fd` 匹配"包名+base.apk"取路径 → 读 maps 找 libart.so r-xp → fstat base.odex 算 **MD5** 写 `.cache/classes.dve` 作环境指纹 → 进入检测链。
  - 反调试:`/proc/%d/status` TracerPid + `/proc/%d/wchan` 判 **ptrace_stop** + 全 task 遍历 + 时间差 + hook 掉 ptrace + 读 inotify 配额。
  - 反 Frida:`/proc/self/task` 找 `gum-js-loop`、`/proc/self/fd` 找 `linjector`。
  - 脱壳机检测:fart/FUPK3/Youpk/dumpclass 特征字符串。
  - **DEX 解密窗口期**:hook `art::DexFileLoader::open`/`DexFileVerifier::Verify`(返回1);DEX 加载后 maps 出现 `anon:dalvik-classes.dex extracted in memory` / `anon:dalvik-DEX data` 段即 dump 时机。
  - 字符串解密(sub_18F58):"第一字节⊕参数3最低位=key,从偏移+2 逐字节⊕key"。
- **对玄甲 X4 的启发**:
  - L1:`wchan==ptrace_stop` 是比 TracerPid 更隐蔽的调试指纹;检测 dlopen 被 hook。
  - L2:多源交叉;**反向检测自身 log 函数是否被静默 hook**(加固方会 hook android_log_* 返回0)。
  - **L3(关键)**:DEX 解密窗口期是加固方最大软肋 → 玄甲须压缩窗口(解密→加载→立即 madvise/覆写、分块流式、解密后内存自哈希监控)。
  - L5:借鉴 SO 加密 + JNI_OnLoad 解密 + 偏移表间接寻址 + 字符串栈拼接。
- **可复用技巧**:wchan 判 ptrace_stop;task 线程名检测;inotify 配额防耗尽;环境指纹(base.odex MD5)识别重打包。
- **风险提示**:含完整脱壳思路(dump anon:dalvik- 段、hook libart)——通用脱壳方法论,**仅借鉴布防与窗口期教训**,严禁他用。

## 文章 2:《Android签名检测7种核心检测方案详解》(看雪 K2,珍惜Any)
- **来源**:看雪 thread-278982 / **权威度**:高(Android 11 实测,攻防双向对照)
- **核心机制**:7 种签名检测(1 Java IPC + 5 Native svc + 1 攻击侧)× 逐一绕过,是检测方案×绕过方式对照表。
- **关键代码/算法要点**:
  - **V2 块魔数**(L4 直接可用):`"APK Sig Block 42"` / V2 id `0x7109871a` / EOCD `0x6054b50`;`read_certificate(fd)`:文件尾扫 EOCD → central_dir → 向前找 Signing Block 验 magic → 遍历 id-value 取 0x7109871a → 跳过 digest 读第一个 cert。
  - 方案①IPC 直连:反射 `IPackageManager$Stub` 的 TRANSACTION_getPackageInfo,自构 Parcel transact 后用 CREATOR 解析。
  - 方案②svc openat:`raw_syscall(__NR_openat, AT_FDCWD, path, O_RDONLY|O_CLOEXEC, 0640)`(源自 Magisk)。
  - 方案③fstat UID/GID:系统 base.apk uid/gid 均 **1000**。
  - 方案④readlinkat 反查:读 `/proc/self/fd/<n>` 目标比对;**返回值(路径长度)也要校验**(攻击者忘改返回值露馅)。
  - 方案⑤inode 一致性:maps 行倒数第二项 inode vs fd fstat inode。
  - 方案⑥遍历开机已打开 fd:找 base.apk 直接解析("不走 IO 重定向,相对安全")。
- **对玄甲 X4 的启发**:**L4 签名校验最佳实践蓝本**——svc openat 解析 V2 + fstat(uid/gid=1000)+ readlinkat(含返回值校验)+ inode 交叉 + 开机 fd,多项交叉,任一被 bypass 仍能发现。L1:检测 CREATOR.createFromParcel 被 hook、代理人 class 含 proxy。
- **可复用技巧**:全部 svc 内联替代 libc;对 svc **返回值阶段**也校验。
- **风险提示**:"核心破解/LSP 禁用系统签名验证"属系统级攻击;玄甲借鉴:不能只信读到的签名,还要校验 APK 物理完整性与安装来源。

## 文章 3:《校验的N次方——签名校验对抗、PM代理、IO重定向》(看雪 K1)
- **来源**:看雪 thread-278216 / **权威度**:高(完整可复现工程)
- **核心机制**:5 种去签路径(核心破解/一键工具/手撕/IO重定向 VA&SVC/偷 jks)+ PM 代理 + IO 重定向工程实现。
- **关键代码/算法要点**:
  - **PM 代理**:反射替换 `ActivityThread.sPackageManager` + `ApplicationPackageManager.mPM`,`Proxy.newProxyInstance` 造 IPackageManager 代理,对 getPackageInfo 返回篡改签名。
  - **IO 重定向**:DobbyHook inline hook `open/openat/fopen/syscall` 四入口;`isOrigAPK()` 判路径==sourceDir 时改读到 `/data/user/0/<pkg>/files/base.apk`;`fake_syscall` 拦截 __NR_openat;hook 前 `mprotect(RWX)` 解保护。
- **对玄甲 X4 的启发**:
  - L1(PMS 代理检测):检测 sPackageManager/mPM 对象 class 是否 Proxy、ClassLoader 是否系统、InvocationHandler 是否存在。
  - L4(IO 重定向检测):不信任 Java PM 与 libc open;svc 内联 openat 直读 + fd readlinkat/fstat/inode 交叉。
- **可复用技巧**:IO 重定向会 hook 到 syscall 层,防守必须下沉到内联 svc;mprotect rwx 可作 L3 异常信号。
- **风险提示**:点名 MT/NP/ARMPro/Modex 等通用过签工具,**仅借鉴指纹特征用于检测**,绝不集成。

## 文章 4:《〈安卓逆向这档事〉十九课、Frida 检测(下)》(看雪 K5)
- **来源**:看雪 thread-282623 / **权威度**:高(SVC/inline hook 对抗前沿)
- **核心机制**:svc 直接系统调用检测 + Frida 反制(anti_svc 扫内存 svc 指令并 hook)+ inline hook 指令特征检测。
- **关键代码/算法要点**:
  - SVC 指令特征:ARM32 `svc`=`00 00 00 EF`,ARM64 `svc #0`=`01 00 00 D4`;openat 号 ARM=322/ARM64=56。
  - **Inline hook 指令指纹**:"第一条 mov 常数到寄存器,第二条 br 寄存器",检测**第二条指令高 16 位 `0xd61f`** 判定被 inline hook。
  - syscall 号提取:ARM `=(addr-4).readS32() & 0xFFF`;ARM64 `=(addr-4).readS32()>>5 & 0xFFFF`。
  - Frida 内部检测点:hook 把 Java 方法转 native(检测方法属性);Frida attach 校验 ELF_magic(抹掉可致失败);so_main 不判空(置空可致崩)。
- **对玄甲 X4 的启发**:
  - L4(inline hook 检测):关键函数入口指令完整性扫描,发现 `mov reg,#imm; br reg`(0xd61f)即判被 hook——比 CRC 更细粒度。
  - L2/L3:玄甲检测代码用内联 svc,但需知"svc 本身可被特征码扫描定位 hook",故 svc 调用点应分散+混淆+多处冗余。
- **可复用技巧**:inline hook 0xd61f 指纹;Java→native 方法转换检测;svc 多架构特征码(ARM/ARM64 双覆盖)。
- **风险提示**:anti_svc/抹 ELF_magic/置空 so_main 是对抗 Frida 的反制技巧;玄甲**仅借鉴检测侧**,不采用"致崩 Frida"类主动破坏(防守工具应被动检测+阻断)。

## 文章 5:《frida 反调试总结+一把梭》(看雪 K4)
- **来源**:看雪 thread-284941 / **权威度**:高
- **核心机制**:Frida 检测 6 大类 + "一把梭"绕过(hook libc strstr/strcmp,凡 args[1] 含关键词即改返回值0)。
- **关键代码/算法要点**:
  - 6 类检测:`/data/local/tmp` 特征文件/默认端口 **27042**/双进程/maps-task-fd 特征/**D-Bus 协议探测**(发 D-Bus 收 reject 即 frida-server)/maps 字符串(frida/gum-js-loop/gmain/gdbus/pool-frida/linjector)。
  - 自实现 syscall 检测:`syscall(SYS_open/read/close)` 读 maps;`secure_read` 用 `gettid!=getpid` 判调试,数据 XOR 0x55 校验。
  - 动态生成 syscall 机器码:mmap(RWX)写 `mov rax,1;syscall;ret`,无固定地址可 hook。
- **对玄甲 X4 的启发**:L2 端口 27042 + D-Bus 协议 + 线程名多维;gettid≠getpid 轻量指纹。L1 maps 扫 frida/gadget/linjector。
- **可复用技巧**:**自实现字符串比较**(防 libc strstr/strcmp 被一把梭);检测分散化。
- **风险提示**:"一把梭"Frida 脚本是通用绕过工具;玄甲仅借鉴"为何被绕过"(依赖 libc 字符串函数),据此设计自实现比较+分散。

## 文章 6:《Android 反调试(16种,含完整代码)》(吾爱 W2)
- **来源**:52pojie thread-675649 / **权威度**:中高(代码密度最高)
- **核心机制**:针对 IDA/GDB/dump 的完整反调试方法库,每条有实现代码。
- **关键代码/算法要点**:
  - **时间差(5 API,阈值>2s)**:time/clock/gettimeofday/clock_gettime(CLOCK_REALTIME)/getrusage(RUSAGE_SELF)。
  - **断点扫描(完整函数)**:ARM BKPT `{0xf0,0x01,0xf0,0xe7}`(4字节)/Thumb `{0x10,0xde}`(2字节);模式判定 `mode=(u32)addr%2`,奇→Thumb(addr-1起2字节步进),偶→ARM(4字节步进),memcmp 逐指令比对。
  - ptrace 自附着:`PTRACE_TRACEME` 返回 -1 即被调试。
  - SIGTRAP:注册 handler 后 raise(SIGTRAP),被调试时 handler 不执行。
  - **Inotify 反 dump**:`inotify_add_watch(fd,"/proc/<pid>/pagemap",IN_ALL_EVENTS)`,IN_OPEN 即判 dump。
  - 其他:23946 端口、进程名 android_server/gdbserver、父进程 cmdline 含 zygote、task 数<=1 异常、反 F5 花指令。
- **对玄甲 X4 的启发**:L2 时间差用"短区间+多 API 并行",阈值做相对基线(抗 hook 定值);断点扫描函数结构可借鉴;L3 inotify 监控 pagemap/mem 是现成触发器;SIGTRAP handler 执行性判据。
- **可复用技巧**:断点扫描步进/模式判定;inotify 监听 pagemap;TracerPid 字节模式硬匹配。
- **风险提示**:防守技术合集,无攻击脚本,可直接借鉴结构。

## 文章 7:《从零开始绕过 DexProtector 加固的 Frida 检测》(吾爱 W3)
- **来源**:52pojie thread-2074484 / **权威度**:高(防守含金量最高,商业壳实战)
- **核心机制**:拆解 DexProtector 检测体系并逐层绕过——玄甲设计检测强度的"假想敌能力上限"参照。
- **关键代码/算法要点(检测方,从绕过反推)**:
  - 多维 Frida 检测:maps 扫异常/端口 27042/ptrace/CRC 哈希(疑 SipHash-2-4,三调用点)/HMAC-SHA256(ARMv8 硬件指令 SHA256SU0 定位)/text 完整性。
  - 线程监控:pthread_create 多监控线程持续检测。
  - 核心藏匿名内存:JNI_OnLoad 经函数指针跳匿名段,执行后抹指针(off=0)。
  - **攻击者绕过(反推弱点)**:CRC hook 在 onLeave 用 lr 定位替换返回值(**弱点:比对与返回分离、单点返回值**);text 校验在校验函数 onEnter 把 args[1] 指向原始副本(**弱点:校验对象由指针参数传入**);线程监控往入口写 RET(**弱点:线程入口未被完整性保护**)。
- **对玄甲 X4 的启发**:
  - L4:CRC/哈希比对**不返回单一 bool/数值**(会被 onLeave 替换);"计算+比对+反制"封同一内联函数,反制不经可 hook 返回值。
  - L4:text 校验**不经指针参数传被校验区域**,改函数内取自身地址(`&&label`/`__builtin_return_address`)。
  - L4:监控线程**入口自身纳入 CRC** + 心跳互检(对抗入口写 RET)。
  - L5:核心逻辑匿名内存延迟解密、执行后抹指针 = SMC 范式。
  - L2/L4:检测多维冗余,单维必被 Zygisk Gadget 绕过。
- **可复用技巧**:ARMv8 硬件加密指令特征自证算法未被替换;哈希多点调用+不同预期值(攻击者需逐个打表)。
- **风险提示**:**含完整 Frida 攻击脚本**(打表/Arm64Writer 写 RET/dump 匿名段),**仅借鉴检测弱点,绝不复制脚本**。

## 文章 8:《记一次对某韩游的反反调试》(吾爱 W5,腾讯TP)
- **来源**:52pojie thread-2016248 / **权威度**:高(偏移/阈值/字符串全实测)
- **核心机制**:拆解夜鸦(UE5)腾讯 TP 保护并逐项绕过。
- **关键代码/算法要点**:
  - **时间差(巧妙变体,不依赖时间 API)**:对 `/sbin` 和 `/system/lib` 调 `lstat`,从 `struct stat+0x68`(ARM64 st_ctime)取时间戳算差,超 `0xF4240`(1e6 秒≈11.57天)触发 exit。原理:Magisk/shamiko 隐藏 root 刷新 /sbin 造成 ctime 异常——**用文件系统时间戳间接测环境,规避时间 API hook**。
  - CRC 校验:Frida 注入约 1 秒被发现崩溃。
  - IO 重定向检测:base.apk fd 检测后读 .apk 解析 AndroidManifest。
  - Magisk 特征:APK 权限组合 + 伪装包名。
  - 字符串 decrypt1 运行时解密。
  - 攻击者绕过:hook lstat 改 stat+0x68、hook popen 换 "which su"、hook openat 重定向、清 FLAG_DEBUGGABLE。
- **对玄甲 X4 的启发**:
  - **L2(重点)**:时间差**跳出时间 API**,用 lstat 读关键目录 st_ctime 做差——攻击者 hook 时间 API 的通用绕过失效,需逐个 hook 文件系统调用,成本陡增。**本次调研最值得落地的 L2 创新点**。
  - L4:CRC 检测 hook 痕迹实测有效(1秒内)→ .text CRC 高频+多线程;IO 重定向检测(fd 真实路径)直接对应 L4。
  - L5:敏感字符串运行时解密。
- **可复用技巧**:lstat + stat+0x68(st_ctime)双目录时间差;fd 真实路径校验反 IO 重定向。
- **风险提示**:含 Frida 绕过脚本,**仅借鉴检测机制,严禁复制**。

## 文章 9:《安卓签名校验-探讨》(看雪 M3,CREATOR 替换)
- **来源**:看雪 thread-285647 / **权威度**:高(信息密度最高,MT/LSPatch 源码逐行分析)
- **核心机制(重要修正)**:现代 MT 的 killPM **不是**(或不仅是)sPackageManager 代理,而是 **`PackageInfo.CREATOR` 替换**——反射替换 CREATOR 为代理 Creator,在 createFromParcel 先调原 Creator 再覆盖 signatures[0]/signingInfo;**同时清除三处系统缓存**(sPackageInfoCache/mCreators/sPairedCreators);用 HiddenApiBypass 绕隐藏 API。原文明确"MT 早期版本是对 mPM 替换"——**新旧两代机制并存,防守必须双检测**。LSPatch 同源(`setStaticObjectField(PackageInfo,"CREATOR",proxiedCreator)` + native inline hook __openat)。MT killOpen 实证:xhook PLT hook openat64/openat/open64/open 四件套。
- **关键代码/算法要点(防守全套)**:
  - checkPMProxy:mPM 类名==`IPackageManager$Stub$Proxy`?(旧 MT)
  - **checkCreator3(现代 MT/LSPatch,最关键)**:法一 ClassLoader 比对(系统 BootClassLoader vs 替换后 PathClassLoader);法二 CREATOR 类名比对(系统 `PackageInfo$1` vs 匿名类,LSPatch 可绕法一故需法二兜底);法三 检测被 hook 时切反射其他属性交叉。
  - Application 检测:`ActivityThread.mInitialApplication` 类名(比 getApplication 更底层);LoadedApk 单例。
  - AppComponentFactory 检测。
  - Dex 内存校验:ClassLoader 反射取 dex 地址(JNI 指针+1),dex 头动态 CRC。
  - 本地证书解析:ZipFile 读 META-INF/*.RSA/DSA/EC X509(不经 PMS)。
  - 调用链实证:getPackageInfo → IPackageManager$Stub$Proxy → Parcel.readTypedObject → PackageInfo$1.createFromParcel。
- **对玄甲 X4 的启发**:
  - L1:① mPM 类名(旧)② **CREATOR ClassLoader+类名双检测(新,必做)** ③ Application/mInitialApplication/LoadedApk 三级 ④ AppComponentFactory ⑤ 攻击者清 Parcel 缓存可作辅助指纹。
  - L3:Dex 内存地址提取 + dex 头 CRC 动态校验。
  - L4:本地 ZipFile 证书解析作 svc 方案备份(仍走 sourceDir,需与 svc 交叉防 IO 重定向)。
- **可复用技巧**:同一签名取 3 条独立路径(PMS/本地/svc)交叉,三者一致才可信;攻击调用链每层都是独立检测锚点。
- **风险提示**:**含 MT/LSPatch 去签完整代码,绝对禁止入库**,仅 CREATOR/ClassLoader 检测侧参考重写;LSPatch 能绕 ClassLoader 检测提醒单点必被绕,须多锚点交叉。

## 文章 10:《大厂和企业壳的核心检测签名思路》(MT M4,Hunter 思路)
- **来源**:nixiang.tech / **权威度**:中高(拆解 Hunter 检测框架,与 K2 互证)
- **核心机制**:root 下"核心破解/LSP Cemiuiler 禁用系统签名验证安装"是降维打击(签名文件未变,读到的还是原签);Native 六步纵深 getApkSign。
- **关键代码/算法要点(Native 六步)**:
  1. svc openat 打开已安装 APK + 自解析 V2 块(Magisk 系):EOCD(0x6054b50)→ central_dir → "APK Sig Block 42" 双 block_sz 互验 → 遍历 id-value 取 0x7109871a → 取第一个 cert。
  2. **遍历已打开 fd 取签**:系统启动已打开 base.apk,遍历 /proc/self/fd readlinkat 命中即解析("不走 IO 重定向,相对安全");先 `android_fdsan_set_error_level` 关 fdsan。
  3. readlinkat 路径反查:fd 真实路径 vs 传入路径。
  4. **readlinkat 返回值截断检测**:按返回长度截断——"攻击者只改路径忘改返回值"即露馅。
  5. fstat uid/gid==1000:确认系统安装文件而非私有目录副本。
  6. inode 比对:fd st_ino vs maps 行 inode。
  - 全部走 raw_syscall 内联 svc。Java 补充:IPC 直连(反射 mRemote 手工 transact)。
- **对玄甲 X4 的启发**:**L4 核心蓝图**——六步全可纳入:svc 自解析(主干)+ 开机 fd 复用(奇兵)+ readlinkat 双重反查 + uid/gid + inode 三角;任何一步失败标记重打包风险。
- **可复用技巧**:攻击方 bypass(fstat 出口 hook/隐藏 fd/getdents64 过滤/close 触发 fdsan)已明示 → 多步串联判定,检测顺序运行时洗牌。
- **风险提示**:"所有检测都可被绕过",价值在抬高成本;代码源自 Magisk/Hunter,需自研差异化。

## 文章 11:《浅谈去除 NP 管理器添加的签名校验》(NP N1)
- **来源**:binmt thread-55774 / **权威度**:中(一手拆解 NP 注入机制)
- **核心机制(反面教材)**:NP 给他人 APK 在 dex 层向**所有继承 Activity 的类**的 onCreate 插入校验调用;去签者发现"只删启动 Activity 调用会致其他界面闪退",改为直接改校验方法体开头 `const v0,1; return v0` 一次性通杀。
- **关键代码/算法要点**:NP 注入位置 = Java/Smali 层(非 Native),覆盖面 = 全部 Activity 子类;去签 = 方法首插 `const v0,1; return v0` 短路。
- **对玄甲 X4 的启发**:
  - L1/L4 反面教材:玄甲**绝不能**把校验做成"一个可被 return true 短路的单一 Java 方法"。设计约束:① 校验逻辑多点内联展开(每点独立代码,无公共函数)② 返回值不作布尔——用校验结果**参与运算**(解密下一段代码的密钥=签名哈希),短路导致后续解密失败而非简单通过 ③ Native 与 Java 校验点交叉绑定。
  - "注入到所有 Activity"思路防守化复用:校验编织进多个生命周期点,但每处代码异构。
- **可复用技巧**:校验结果作密钥(防 smali 短路)是最低成本手段;校验代码去函数化(内联+每处变形)。
- **风险提示**:smali 补丁手法,仅借鉴"单点校验为何脆弱",不涉及攻击工具。

## 文章 12:《Frida常见检测方法》(CSDN C2)
- **来源**:CSDN / **权威度**:中(覆盖面全,含绕过-反绕过升级链)
- **核心机制**:10 种 Frida 检测 + 4 类绕过及升级检测。
- **关键代码/算法要点**:
  - 基础:maps 扫 frida-agent.so/re.frida.server;/proc/net/tcp 端口;connect 127.0.0.1:27042。
  - **D-Bus 协议探测(抗改端口)**:遍历监听口发 D-Bus 认证消息,**回 REJECT 即 frida-server**。
  - 线程名:task status Name 找 gmain/gdbus/gum-js-loop/pool-frida。
  - fd:readlink /proc/self/fd/* 与 task fd。
  - 内存:全内存扫 LIBFRIDA(抗 strongR-frida 改名)。
  - **升级检测(最有价值)**:① 预加载可信 SO 做**可执行内存段白名单**,白名单外可执行段→终止;② libstagefright 的 Shared_Dirty/Anonymous 异常多 4KB(frida 跳板痕迹,重启才消失);③ riru 特征文件 libmemtrack.so。
- **对玄甲 X4 的启发**:
  - L2 反 Frida 五件套:D-Bus REJECT 全端口探测 + task 线程名白名单 + fd readlink + LIBFRIDA 内存扫描 + 27042 快检;全部 svc 直发读 /proc。
  - **L3 核心武器 = 可执行段白名单**:玄甲运行时本就知道哪些段该 r-x(自家+系统 SO),白名单外 r-x/rwx = 注入/dump 落点,一招覆盖 SO 注入/frida gadget。
  - 异常 mprotect(rwx):自家代码永不需要 rwx 页(解密用逐页 rx 切换),出现即异常。
- **可复用技巧**:白名单比黑名单字符串强一个量级(抗改名);Shared_Dirty 增量是冷门有效的跳板痕迹检测;检测顺序先廉价(端口)后昂贵(全内存)。
- **风险提示**:纯防守清单,无风险;strongR-frida 仅为绕过方命名。

---

## 交叉验证小结
- **高置信(多篇互证)**:svc 签名校验六步(K2/M4/M6)、CREATOR 替换检测(M3/M2/M7)、时间差多 API(W1/W2)、st_ctime 变体(W5)、断点魔数(W1/W2)、rtld_db_dlactivity(W1/W6)、DEX 解密窗口(K3)、inline hook 0xd61f(K5)、可执行段白名单(C2/W4)。
- **待补强**:D-Bus 具体报文格式;svc 被 anti_svc 特征扫描后的加固对策(K5 暴露风险未给解法,需自研 svc 调用点混淆);断点指令检测的 ARM64 BRK 完整实现(被拦截的 K7 应有)。
- **合规**:所有攻击侧代码仅作机制级理解,玄甲独立重写检测侧。
