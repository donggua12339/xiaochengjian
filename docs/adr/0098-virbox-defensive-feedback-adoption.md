# ADR 0098: 玄甲防守能力增强——Virbox Styler 样本红蓝对抗防守反哺采纳

- **状态**: proposed
- **日期**: 2026-08-06
- **决策者**: 用户(项目所有者)
- **关联**: ADR 0088(defender-sdk)、ADR 0092(X0 SO 加密)、ADR 0093(X4 反动态引擎)、ADR 0096(反 Frida 12 层)
- **输入文档**: 桌面《防守反哺_玄甲天衍可抄清单.md》(2026-08-05,深思数盾 Virbox 样本 Styler 3.10.0.2 红方渗透复盘),配套《L4_检测行为画像.md》《路线C_patch目标清单.md》《路线C_patch执行手册.md》

## 背景

2026-07-31 ~ 08-05 以深思数盾 Virbox 商业壳(Styler 3.10.0.2)为样本做红蓝对抗校准。红方边界已探明(对"可运行重签分发"目标不可达,五层墙:L1 签名/L2 文件完整性/L3 VMP+壳接管/L4 运行时痕迹检测/L5 反调试),产出防守反哺清单:**可抄 10 项 + 规避 6 项**。

按 CLAUDE.md §10,反哺清单是**决策输入**,采纳与否须走 ADR。本 ADR 即采纳决议。

**合规定位**:输入是对商业壳防御机制的逆向研究知识(防守设计输入),本项目不复制、不引入任何第三方代码与逆向中间产物,仅参考机制**自研实现**到自有 defender-sdk。不触碰守城军规Ⅰ-Ⅳ:全部落地项均为自有资产的纯防守增强,无任何脱壳/重打包/越界能力。

## 现状复核(2026-08-06,对当前代码实测,纠正过期记忆)

| 反哺项                   | 代码现状                                                                                                                                   | 结论                                        |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------- |
| #17 Canary 防短路        | `canary_guard.h` 已实现,`validator_core.c` 3 处 check 已接入,`trigger_scheduler.c` 校验 canary                                             | **已实现**(2026-07-26 改进清单"待做"已过期) |
| fd readlink 扫描         | `patch_env_detect.c` 已有 `/proc/self/fd` readlinkat 扫描(base.apk 路径异常检测)                                                           | **部分存在**(环境检测维度)                  |
| 自检读取路径 fd 来源校验 | `mmap_reader.c` 用 svc openat+mmap(规避 IO 重定向 hook),但**未对所用 fd 做 readlinkat 反解比对**                                           | **缺口**(P0-A)                              |
| 检出后降级反制           | `defender_response.c` 仅 kill(SIGABRT/_exit)+ warn 两档,检出即崩=给红方信号灯                                                              | **缺口**(P0-B)                              |
| GC 根巡检(VisitRoots)    | 全代码库无 art VisitRoots/SweepJniWeakGlobals                                                                                              | **缺口**(P0-D)                              |
| #13 VM 自引用 CRC        | `vm_engine.c` 无 dispatch .text 自校验                                                                                                     | **缺口**(P0-C)                              |
| findLoadedClass          | Kotlin 侧检测走 maps/调用栈/ClassLoader 链遍历,未用 FindClass 探测(hook 留痕问题已天然规避);native 侧类探测若新增须用 findLoadedClass 语义 | 约束记录,不立项                             |

## 决策

### 1. P0 采纳(本轮实现)

1. **P0-A 自检读取路径 fd 真实路径校验**(反哺 §1.1,玄甲最大单项缺口)
   `mmap_reader.c` svc openat 成功后,`readlinkat(AT_FDCWD, "/proc/self/fd/N")` 反解 fd 真实路径,与预期 base.apk 路径(sourceDir)比对;不一致计入强证据。X0 memfd 加载路径按既有 `memfd:` 例外语义放行(自身加载路径本就匿名,校验对象是 APK 文件读取,不冲突)。

2. **P0-B 检出后降级反制通道**(反哺 §1.2,理念级升级)
   response_chain 在 kill/warn/none 之外新增 **countermeasure(静默反制)档**:Xposed/LSPosed 类检出命中时,优先反射置 `XposedBridge.disableHooks=true` 使对方 hook 静默失效,不崩不报;kill 保留给"强证据/屡犯/高危"档。把"检出"从报警升级为反制,红方难以归因。

3. **P0-C VM 自引用 CRC**(改进清单 #13 提级,反哺 §2.2 印证)
   Virbox Class A 教训:纯叶子检测函数入口两条指令即可桩废。玄甲对策 = 检测/校验逻辑入 VM 后,**字节码执行期对 dispatch loop 所在 .text 区段做 CRC 自校验**(构建期 `build_vm_bytecode.py` 嵌入预期值),patch dispatch 恒真即检出。与已有 canary(#17)互补:canary 防"函数级短路",VM CRC 防"引擎级 patch"。

4. **P0-D GC 根巡检**(反哺 §1.3,用户状态判定列为三差距之一)
   native 解析 art 符号 `JavaVMExt::VisitRoots`/`SweepJniWeakGlobals`,自定义 visitor 遍历全部 JNI 全局根,识别 BaseDexClassLoader 注入链/Xposed 类引用——类名隐藏也暴露。符号解析失败(API/厂商差异)优雅降级不计分,不崩。接入 XposedDetector 打分。

### 2. P1 采纳(后续排期,不在本轮)

- 预期值/hash 运行时虚拟供给(反哺 §1.5,把预埋答案从静态可读变仅运行时可得,天衍优先)
- 检测多态化 per-build(=改进清单 #14,与 #5 T3 段接入联动)
- findLoadedClass 约束落到 native 类探测代码规范

### 3. P2 记录(设计原则,排期另议)

- 双管线冗余 + 检测/解密耦合(§1.6,注意别把正常初始化耦死)
- 关键状态多槽冗余,禁单指针槽单 choke(§2.1)
- 自毁死值去特征化/honeypot 假归因(§2.5)
- 配置 blob 上下文绑定(/proc/self/cmdline)+ 白盒 S-box 替代单字节 XOR(§2.4,=#12)

### 4. 不采纳/边界说明

- 全对象扫描(art NewLocalRef hook,每个 jobject 过 IsInstanceOf):性能开销大且与玄甲架构耦合深,**天衍增强项**,本轮不做。
- 反哺清单中涉及"如何打穿"的具体路径描述仅作为规避依据存档,不转化为本项目任何代码能力。

## 后果

- defender-sdk 新增/修改:cpp 侧 `mmap_reader.c`、`defender_response.c`/`response_chain.c`、`vm_engine.c`、新增 GC 根巡检模块;Kotlin 侧 XposedDetector 接入降级反制。
- 构建脚本:`build_vm_bytecode.py` 增加 dispatch CRC 嵌入步骤。
- 攻击者成本:文件重定向伪造、hook 短路、dispatch patch、藏类名注入四条红方路径均被正面封堵;检出不再给红方崩溃信号。
- 风险:GC 根巡检依赖 art 内部符号,跨 ROM 兼容性须真机矩阵验证;降级反制若反射失败必须回退到原响应档,不得静默吞掉检出。

## 验证计划

1. host 端 C 单测:VM CRC(正常字节码通过/dispatch 被 patch 检出)、canary 回归。
2. fd 校验与降级反制逻辑走 dry-run 模式可观测(log 分级)。
3. defender-sdk gradle build 全绿;后端 CI 不受影响。
4. 真机验证(用户侧):LSPosed 环境下确认 disableHooks 反制生效且不崩;GC 根巡检在目标 ROM 符号可解析。

## 实现记录(2026-08-06 落地)

### P0-A fd 真实路径校验

- `mmap_reader.c`:新增 `mr_readlinkat`(arm64 svc 直调/arm32 syscall/host fallback);
  `mr_verify_fd_path` 在构造器首次 open 与回退 openat 后立即反解 fd 真实路径与
  maps 定位路径严格比对(容忍 " (deleted)" 后缀),不符置 `g_fd_redirect_flag`;
  强证据查询入口每轮对缓存 fd 主动复查。
- 强证据框架 5→7 条:⑥`check_apk_fd_redirect`(score_weights 编译锁同步更新);
  config_loader 开关表同步扩展。

### P0-B 检出后降级反制

- 新增 `XposedCountermeasure.kt`:反射置 `XposedBridge.disableHooks=true`,
  多 ClassLoader 尝试 + 回读确认(防 setter 被 hook 成 no-op)+ 全程 catch 不崩。
- `DefenderConfig.XposedConfig` 新增 `countermeasure`(默认 true,JSON 可配)。
- `DefenderResponse.silentReport`:限流记录+HTTP 上报,无 Toast 无信号。
- `DefenderInitProvider`:红色命中先反制,成功→静默监控;失败→回退原 kill/warn 档。

### P0-C VM 自引用 CRC(#13)

- `vm_engine.c`:dispatch/执行/校验代码入 `vmself_code` 专用段
  (`-ffunction-sections+--gc-sections` 下布局保证),执行期对
  `[__start_vmself_code, __stop_vmself_code)` 全段算 CRC-32/IEEE 与 .rodata
  占位符("VMSREF01"+8hex)比对;占位符全 0=未 patch 跳过,非 ELF 平台优雅降级。
- `scripts/patch_vm_self_ref.py`:CMake POST_BUILD 定位区段写 CRC(幂等锚点);
  占位符在段外(.rodata),写入自洽,与 X0 加密流程兼容(整 SO 加密解密字节不变)。
- **三个实测踩坑(已修,勿重蹈)**:
  1. **-O2 常量折叠吃掉占位符**:`-O2` 下编译器把 `parse_expected` 读到的占位符
     当编译期常量("00000000")折叠成恒 `return 0`,引用消失后 `--gc-sections`
     连占位符一起回收(实测 anchor=0)。**修**:占位符声明 `volatile const`,
     逐字节 volatile 读,禁止折叠。
  2. **lld 把孤儿段 `vmself_code` 并进 `.text`**:按节名找段不可靠(段头里没了)。
     **修**:patch 脚本改用 `.symtab` 的 `__start_/__stop_vmself_code` 符号定位
     (与运行时同一范围),节名仅作回退。连带要求:CMakeLists 去掉 `-Wl,-s`
     (会抹 .symtab),release strip 交给 Gradle stripReleaseDebugSymbols(POST_BUILD 之后)。
  3. **VM 引擎在当前 Android 接线里是死代码**:调 `vm_execute` 的 t3/t4 函数无
     JNI 调用方(改动前就被 `--gc-sections` 回收,非本 ADR 引入)。故 Android release
     里 patch 脚本找不到区段 → **优雅跳过(exit 0)**,运行时占位符全 0 自动关闭自引用。
     待天衍 t3/t4 接线后本防护自动激活。
- **已验证**:①WSL host(GNU ld)`-O2`:单测 10/10,patch 后重跑全绿(真实 CRC
  生效自洽),篡改段内 1 字节→全部 VM 执行被检出中止;②NDK arm64(lld,
  `-ffunction-sections -fdata-sections --gc-sections` 同项目参数):符号定位成功、
  CRC 正确写入,证明 lld 路径成立;③Android assembleRelease 全绿(VM 死代码时
  patch 优雅跳过,Kotlin P0-B/D 类正常编入 AAR)。

### P0-D GC 根巡检(v1 保守版)

- `x4_gc_roots.c`:libart `JavaVMExt::VisitRoots` mangled 候选解析 + 伪造
  RootVisitor(Itanium vtable)+ sigsetjmp 全程守护;两条与类名无关的物理事实:
  ①根对象落在非堆/非镜像映射区 ②全局根总数超阈值(20000);API 26-35 门控,
  任何失败返回 0 优雅降级。JNI `X4Native.gcRootScan()` 以 ×10 弱权重并入
  XposedDetector 置信度(单独不达阈值,防误杀)。
- **诚实边界**:Virbox 级"按版本偏移表解析对象类名"未做,列天衍增强;
  v1 须真机验证 VisitRoots ABI 兼容性后方可倚重。

### 已知限制与后续

- P0-B/P0-D 真机验证未完成(需 LSPosed 环境),ADR 状态保持 proposed 待真机回归后
  转 accepted。
- P1/P2 项(虚拟供给/多态检测/多槽冗余等)不在本轮,按 §决策 排期。
