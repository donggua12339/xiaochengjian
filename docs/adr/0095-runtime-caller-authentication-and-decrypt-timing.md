# ADR 0095 · 运行时调用者鉴别与解密时序加固(防 MT/NP 沙箱一键解密)

- 状态:**proposed**(2026-07-26;同日真机验证 MT 加强版 + NP 全开双杀,待决策者 accepted)
- 日期:2026-07-26
- 决策者:小城笺项目
- 层次:安全 / 功能
- 关联:ADR 0088(defender-sdk)、ADR 0092(X0 SO 加密)、ADR 0093(X4 反动态)、ADR 0094(X0 密钥 CFF 加固)

## 背景

2026-07-25/26 攻防实测,MT 管理器「加强版解密」与 NP 全开的执行模型被完整观测到(子进程日志铁证):

1. MT 为解密 **fork 独立子进程** `bin.mt.plus:d`,把我们 APK 的 so **复制**到 `/data/data/bin.mt.plus/cache/decrypt/lib/` 后加载,而非从 `/data/app/` 加载。
2. 该子进程 **原样执行我们的整条自举链**:`loadLibrary("xcj_loader")` → `bootstrap` → memfd 解密 → defender `JNI_OnLoad` → `RegisterNatives`,使 `Application.onCreate`、X4 守护线程全部在 MT 进程里跑起来。
3. MT 用 **LSPlant**(`liblsplant`,ART 层 hook 框架)在 ART 内部拦截 const-string,**根本不调用**我们的 native 解密函数 `p8gi6jmb`——它从 so 的 .rodata / 内置引擎自取 key 做 XOR。
4. MT 在解密完成后立即 `System.exit(0)`,抢在异步检测 kill 之前逃生。

由此暴露前几轮(0092/0094 及本轮早期尝试)的两个**威胁模型错误**:

- **错误 A**:"把解密挪到 native / 用代码自跑出来的上下文(daemon 线程、magic 全局变量、`/proc/self/cmdline`)做绑定"。失效原因:MT 原样执行我们代码,这些"自跑上下文"在 MT 进程里同样成立;且 cmdline 在 MT 子进程里是 `bin.mt.plus:d`,与黑名单不匹配。**结论:任何"我们代码自己算出来的成功标志"做放行条件都是死路**——能执行我们代码的对手,必算出同样的 true。
- **错误 B**:用 `LOGE` 探针观测 MT 进程特征。失效且危险:MT 能读自身 logcat,探针等于把"我们在查 maps/调用栈"暴露给对手;且探针若忘记关,Release 包持续泄露(NDEBUG 不砍 LOGE)。

## 决策

### 1. 运行时调用者鉴别(主墙,JNI_OnLoad 最早期)

在 defender.so 的 `JNI_OnLoad` 第一行扫描 `/proc/self/maps`,命中以下**系统外部、用户态不可伪造**的特征即 `raise(SIGABRT); _exit(137)`,不给解密窗口:

- **so 加载路径鉴别**:映射行含 `libxcj_loader`/`libxcj_defender` 但路径在 `/data/data/` 而非 `/data/app/` → 判定被第三方工具从 cache 加载(真 app 的 so 必在 `/data/app/`)。
- **ART hook 框架特征**:maps 含 `lsplant`/`liblsplant`。
- **逆向工具路径特征**:maps 含 `bin.mt`/`.mt.plus`/`cache/decrypt` 等。

> 这是物理事实鉴别:MT 必须把 so 复制到 cache 才能加载,而它改不了"自己进程 maps 里 so 路径不在 /data/app/"这一系统记录。

### 2. 解密时序加固(堵逃生窗口)

- **同步首轮校验**:`validator_core_init_guard` 在启动守护线程**之前**,于 JNI_OnLoad 同步执行一次方案 A+B;失败直接 `raise(SIGABRT); _exit(137)`。MT 重签 APK → hash 不匹配 → 同步死,连 `Application.onCreate` 都跑不到。
- **kill delay 0–1s**:守护线程触发 kill 的延迟从 3–15s 改为 0–1s;守护线程初始延迟从 3–8s 改为 0–1s。MT 来不及 `System.exit(0)`。

### 3. 威胁模型与探针方法论修正

- **不信任"代码自跑上下文"**做绑定;只信任系统外部不可伪造特征(加载路径、ART 框架痕迹)。
- **探针验证即删**:任何 `LOGE`/logcat 探针,观测使命完成当锤删除,不留 `#if 0` 死开关(死开关诱导"下次忘关"二次泄露)。观测能力靠方法论记录(memory)保留,不靠源码死代码。
- **观测与押注并行**:观测锤同时塞"押最可能真值的初版防御",一轮顶两轮,不空转、不只靠推理。

### 4. 归位(本 ADR 仅记决策,cross-ref 实现)

| 实战加固 | 归位 | 实现位置 |
|---|---|---|
| cache 路径 + LSPlant + 工具路径鉴别 | X4 运行时调用者鉴别层(本 ADR §1) | `defender_jni.c` JNI_OnLoad |
| 同步首轮校验 + kill delay 0 | 方案 A 时序加固(本 ADR §2) | `validator_core.c` / `trigger_scheduler.c` |
| CFF 密钥派生 / 碎片重建 | X0 加固 | ADR 0094,`xcj_loader.c` |
| Hikari Java 字符串 native 化(XcjObfStr external fun) | X1 增强(SDK 自身 dex,不改用户代码) | `java_obf.py` + `xcj_loader.c` |
| 数字混淆(阈值/hex 常量→运行时表达式) | X1 配套 | `native_cff.py` + `score_weights.h` |

## 被弃路线(诚实记录,防重蹈)

- **`/proc/self/cmdline` 黑名单**:降为**边际纵深**(保留于 `native_str_decrypt`,仅覆盖"直连 jadx/apktool 且 invoke 到 native 解密"路径;零泄露/零误杀/零开销)。对 MT/NP 加强版**无效**(它们不 invoke 本函数),不作主墙。
- **押注双来源 apk 映射检测**(maps 同行含外部前缀+.apk):删除。对 MT 无效(MT 不 invoke),且有误杀边缘(真 app 若 mmap 了 /sdcard 下某 .apk 会被误判)+ 每次解密读 maps 开销。
- **LOGE 探针**:删除(见 §3)。

## 已知边界(留天衍/服务端)

- 攻击者**自起名字干净的进程 + 不把 so 复制到 cache**(如直接内存注入已加载的 so)可绕 cache 路径检测;LSPlant 改名/去符号可绕特征串匹配。
- 彻底堵此边界需 **APK 安装签名经 PackageManager 校验 + 服务端白名单 + 绕过演练**,归天衍(ADR 0091 业务层 / 远期 T10)。玄甲免费 SDK 不能强制集成方配包名,故默认走"加载路径 + ART 框架痕迹"零配置鉴别,接受上述边界。

## 合规

全部为 **SDK 自身 native 行为**(读自身进程 maps、校验自身 APK hash、自身解密时序),**不修改用户 DEX 字节码**,不产出通用脱壳/去签能力,符合 ADR 0077 守城边界与玄甲功能边界(ADR 0091)。Hikari Java 字符串 native 化仅改写 SDK 自身 dex 内字符串调用形式(`external fun` 在 SDK 自己 dex),不动用户代码,**不触发 ADR 0090 律师门**。

## 验证(2026-07-26 真机,marble / Magisk Delta)

- MT 加强版解密:子进程 `bin.mt.plus:d` 在 `bootstrap` 内 cache 路径检测处 **SIGABRT**,crash 堆栈 `libxcj_loader.so (Java_..._bootstrap+1788)`,NOTE 行自证 `/data/data/bin.mt.plus/cache/decrypt/lib/libxcj_loader.so`;MT 重试三次全崩。
- NP 全开:解密沙箱同样崩溃,无法成功运行。
- 真 app 自检:进程 ALIVE,方案 A 哈希匹配,X4 `score=0`,**无误杀、无误报**。

*下一步:决策者确认 accepted;R4(defender.so 主体切自实现 Linker,见 ADR 0089/0092 待办)与 R5(玄甲 P0 真空白 X3 生命周期劫持等)并行开新战线。*
