# 小城笺 · 接手交接文档(2026-07-27 全量加固+攻击成本提升轮)

> **元信息**
> - 日期:2026-07-27。本文覆盖 **2026-07-26 晚 → 07-27 凌晨** 这一轮。
> - 与前序交接文档的关系:仓库根 `HANDOVER-PROMPT-2026-07-24.md` 是更早快照;
>   2026-07-26 红蓝对抗轮的交接文档通过 `/redblue-hardening-verify` skill 内联传入,未独立落盘。
>   **接手人以本份为准**。本份覆盖了本轮全部 23 个新 commit(含玄甲 X0-X9 全套 + 天衍 T1-T6 全套 + 攻击成本提升 6 项)。
> - 阅读顺序建议:§0(30 秒)→ §5 待办 → 需要时查 §2/§3/§4。

---

## 0. 接手人必读(30 秒)

**项目定位**:小城笺 = 独立开发者的私有应用攻防与遗产维护工具,开源 + SaaS 双模式。加固产品线:**玄甲**(开源免费,X0-X9) + **天衍**(付费,T1-T6)。

**守城红线**:纯防守向。四条军规不变(禁通用脱壳/禁非授权重打包/禁越界输出/禁伪装身份)。
DEX 字符串加密经 ADR 0090 律师授权(accepted),仅限自有 APK 语义保持型修改。

**当前 working tree 状态**:
- 分支 `main`,与 `origin/main` **同步**(0 ahead,0 behind)。
- 2 个 untracked 文件(`HANDOVER-PROMPT-2026-07-24.md` + `xcj_project_handover.md`)为旧交接文档,未入库。
- 密钥/构建产物隔离已生效(.gitignore 挡 x0_*.h / cff_params.h / xcj_payload.bin)。
- **commit 前断言闸同前轮**(§4 脚本 B)。

**接手第一动作(三条)**:
1. `git status` + `git log --oneline -5` 确认同步。
2. 读 `CLAUDE.md` §1/§2 红线。
3. 四步构建流水线出包 + 装机验 X0-X9 全绿(§4)。

---

## 1. 本轮(07-26 晚 → 07-27 凌晨)做了什么

### 1.1 接手核验 + 玄甲加固全套提交

- 接手时 staged 65 文件 + unstaged 13(全 backend lint) + untracked 2。
- 逐批提交:玄甲加固全套(e688ae4) → LOGE 脱敏(a4108d0) → backend lint(75a666a)。

### 1.2 X3 生命周期劫持检测 + R4 T1 切 cl

- `X3LifecycleGuard.kt`:Application 类名 / ComponentFactory / LoadedApk.mApplication 三项检测。
- `xcj_loader.c`:cl_dlopen_mem 优先 + memfd 降级(双路径)。
- `self_integrity.c` / `self_verify.c`:setter 模式推送 cl base/size(独立 .so 不能互相 extern)。

### 1.3 T1 真机修复(自引用符号 + namespace 穿越)

**三个根因**:
1. defender 内部函数指针(ABS64 reloc)通过 dlsym(RTLD_DEFAULT) 找不到 → 加自身 symtab 回退。
2. libz 等系统库因 Android 7+ linker namespace 隔离不可见 → 显式 dlopen 缓存 handle。
3. 以上统一封装为 `cl_resolve_sym()` 三级回退。

### 1.4 ADR 0090 落盘 + T4 DEX 字符串加密

- 法律意见书确认 DEX 字符串加密合法(《著作权法》§49/§53 技术措施保护)。
- ADR 0090 accepted + 旧 0090-dex-modification 标 superseded。
- `DexStringEncryptor.kt`:dexlib2 读 DEX → const-string → XOR 加密 → invoke-static DexStringDecryptor.get(I)。
- `t4_str_decrypt.c`:JNI 实现,从 XcjEncStringTable.DATA 取密文 → VMP/白盒解密 → 用后清零。
- 真机验证:6035 个唯一字符串加密成功。

### 1.5 X5/X6/X8/X9 实现 + 真机验证

- X5 `VpnProxyDetector.kt`:tun/ppp/wg + proxyHost + /proc/net/tcp + Settings.Global。
- X6 `DualAppDetector.kt`:uid%100000 + 多用户目录 + 虚拟框架路径 + 已知包名 + dataDir 异常。
- X8 `x8_anti_fart.c`:data 目录散落 dex + maps 非标准映射 + fd 异常 + /data/local/tmp。
- X9 `x9_odex_detect.c`:odex 时间对比 + vdex 大小异常 + oat 目录异常文件。
- X6 MIUI 误报修复(移除系统级分身包名)。

### 1.6 天衍 T2/T3/T5/T6 实现

- T2:VM_BC_xor_decrypt[79B] + 后来扩展到 [110B](含行为自检)。inner_verify_hash 已由前任 VMP 化[120B→151B]。
- T3:`t3_segment_str.c` + `build_t3_segments.py`(24 关键词 → 269B 段池)。
- T5:`HardenCommand.kt` CLI + JSON 配置 + defender-config 生成。
- T6:`QualityReportCommand.kt` 5 维评分 + JSON 报告(实操 C 70%)。

### 1.7 攻击成本提升六项

1. **白盒密钥**:`build_whitebox_key.py` → 16 个 256-entry S-box(4096B,无连续密钥模式)。`t4_str_decrypt.c` 条件编译 `__has_include("wb_sbox.h")`。
2. **VM 行为自检(路线 C)**:每段 bytecode 头部插入 MOV→COPY→XOR→验零序列。若 dispatch 被 patch,V14≠0 → JNZ → return -1。抗 -O3/LTO。
3. **ELF 假 magic 擦除**:`JNI_OnLoad` 完成后 mprotect RW → 写 `\x7fPRV` + garbage → 恢复 R。只擦 e_ident 16 字节(首页 r--p,直写会 SIGSEGV)。
4. **Canary 防短路**:`canary_guard.h` + `validator_core.c` 每次 check 后 CANARY_UPDATE + `trigger_scheduler.c` 验证 canary_expected()。hook return 0 不更新 canary → 识破。
5. **VM handler 洗牌**:`build_vm_bytecode.py` 每构建随机 opcode_xor_key → 字节码全字节 XOR → `vm_engine.c` fetch8 时 VM_DEC 解码。IDA 每次看到不同字节。
6. **admin-web 加固配置页**:`HardenConfig.vue` + 侧边栏导航 + 路由 `/harden-config`。

### 1.8 Bug 修复

- **乱码**:`native_str_decrypt` 的 `plain[plen]` 缺 `'\0'` → `NewStringUTF` 读越界 → 尾部垃圾字符。
- **ELF 擦除崩溃**:第一次写 64 字节覆盖 PT_LOAD 有效数据 → SIGSEGV;第二次直写 r--p 页 → SIGSEGV。最终 mprotect + 只擦 16 字节。
- **dexlib2 格式错误**:const/16 用 21s 非 11n;move-result-object 用 11x;invoke-static 寄存器>15 用 3rc。

### 1.9 反 Frida 9 层纵深

**E 层改造**:硬编码 6 文件名 → 遍历 `/data/local/tmp/` 读前 4KB 检查特征字符串 + 降权交叉验证。

**新增 5 层(F-J)**:
- **F+G D-Bus 协议探测**:被动读 /proc/net/tcp 找 LISTEN 端口 → 发 `\x00AUTH\r\n` → 响应含 REJECTED/EXTERNAL = Frida。杀手锏,改协议栈才绕过。
- **H seccomp-bpf**:拦截 process_vm_readv/writev(syscall 270/271)。内核级,用户态 hook 无效。
- **I 多进程交叉**:fork 子进程读父进程 maps + status。子进程不受 hook 影响。
- **J rwxp 匿名映射**:扫描 maps 找 rwxp,排除 code_cache/dalvik-jit。inline hook 痕迹。

### 1.10 截屏保护

- `defender-config.json` 改 `secureScreen.enabled: true`。
- `MainActivity.kt` 手动 `window.setFlags(FLAG_SECURE)`(demo 不走 DefenderInitProvider)。
- 验证:screencap 返回 0 字节黑图 = 生效。

---

## 2. 玄甲 / 天衍 功能完成度(诚实表 · 2026-07-27 更新)

### 玄甲 X0–X9

| # | 功能 | 代码 | 真机 | 诚实状态 |
|---|------|:----:|:----:|---------|
| X0 | SO 本体加密 | ✅ | ✅ | **完成**(RC4+memfd+T1 cl 匿名) |
| X1 | 字符串多态加密 | ✅ | ✅ | **完成**(obfstr_poly+java_obf native化+CFF+Hikari) |
| X2 | 日志保护 | ✅ | ✅ | **完成**(LOGI/LOGW 砍+LOGE 脱敏 30 条) |
| X3 | 生命周期劫持检测 | ✅ | ✅ | **完成**(X3LifecycleGuard 三项) |
| X4 | 反动态五层 L1-L5 | ✅ | ✅ | **完成+超配**(响应链+Xposed+KeyAttestation+PlayIntegrity) |
| X5 | VPN 代理检测 | ✅ | ✅ | **完成**(score=0 真机) |
| X6 | 双开/分身检测 | ✅ | ✅ | **完成**(score=30<50 不报,误报已修) |
| X7 | 私人端口保护 | ✅ | ✅ | **完成**(IDA 23946+Frida 9 层) |
| X8 | FART 脱壳扫描 | ✅ | ✅ | **完成**(score=0 真机) |
| X9 | ODEX 修补检测 | ✅ | ✅ | **完成**(score=0 真机) |

**玄甲 v1.0:10/10 完成 ✅**

### 天衍 T1–T6

| # | 功能 | 代码 | 真机 | 诚实状态 |
|---|------|:----:|:----:|---------|
| T1 | 自实现 Linker | ✅ | ✅ | **完成**(cl 匿名映射,自引用+namespace 修复) |
| T2 | VMP 保护解密函数 | ✅ | ✅ | **完成**(verify_hash 151B + xor_decrypt 110B,含行为自检) |
| T3 | 字符串分段散列+清零 | ✅ | 待集成 | **代码就位**(t3_segment_str.c+构建脚本;未接入检测路径) |
| T4 | DEX 字符串加密 | ✅ | ✅ | **完成**(6035 字符串加密验证;流水线脚本 build_t4_pipeline.py) |
| T5 | 定制化加壳策略 | ✅ | ✅ | **完成**(CLI+admin-web 页面) |
| T6 | 加固质量报告 | ✅ | ✅ | **完成**(5 维评分 C 70%) |

**天衍 v1.0:6/6 代码就位 ✅**(T3 运行时集成待做)

### 攻击成本提升项

| # | 项 | 状态 |
|---|---|:----:|
| 白盒 S-box | ✅ 工具+条件编译集成 |
| VM 行为自检(路线 C) | ✅ 真机通过 |
| ELF 假 magic 擦除 | ✅ 真机通过 |
| Canary 防短路 | ✅ 构建通过+真机存活 |
| VM handler 洗牌(opcode XOR) | ✅ 真机通过 |
| 反 Frida 9 层(A-J) | ✅ 真机 9 层全绿 |

---

## 3. 关键文件地图(本轮新增/修改)

### defender-sdk/src/main/cpp(新增)

| 文件 | 功能 |
|------|------|
| `t4_str_decrypt.c` | T4 DEX 字符串解密(VMP/白盒双路径) |
| `t3_segment_str.c` | T3 分段散列运行时组装+清零 |
| `x8_anti_fart.c` | X8 FART 脱壳四维扫描 |
| `x9_odex_detect.c` | X9 ODEX 修补三维检测 |
| `canary_guard.h` | Canary 防短路宏+验证函数 |

### defender-sdk/src/main/java/com/xcj/defender/(新增)

| 文件 | 功能 |
|------|------|
| `X3LifecycleGuard.kt` | X3 生命周期劫持三项检测 |
| `VpnProxyDetector.kt` | X5 VPN/代理四维检测 |
| `DualAppDetector.kt` | X6 双开/分身五维检测 |
| `DexStringDecryptor.kt` | T4 运行时解密入口(external fun get) |

### sdk-android/defender-sdk/scripts/(新增)

| 文件 | 功能 |
|------|------|
| `build_t4_pipeline.py` | T4 五步自动化(密钥→构建→加密→hash) |
| `build_t3_segments.py` | T3 分段散列构建工具 |
| `build_whitebox_key.py` | 白盒 S-box 生成 |

### injector/src/main/kotlin/(新增)

| 文件 | 功能 |
|------|------|
| `dexstring/DexStringEncryptor.kt` | T4 DEX const-string 加密器 |
| `dexstring/EncryptStringsCommand.kt` | T4 CLI 命令 |
| `harden/HardenCommand.kt` | T5 定制化加壳 CLI |
| `harden/QualityReportCommand.kt` | T6 质量报告 CLI |

### admin-web/src/views/(新增)

| 文件 | 功能 |
|------|------|
| `HardenConfig.vue` | 加固配置可视化页面 |

### ADR(本轮)

| ADR | 状态 | 内容 |
|-----|:----:|------|
| 0090-authorization | **accepted** | 律师意见书确认 DEX 加密合法 |
| 0090-dex-modification | **superseded** | 旧版 proposed,被 authorization 替代 |
| 0092 | **accepted** | X0 SO 加密设计 |
| 0093 | **accepted** | X4 五层反动态 |
| 0094 | **accepted** | X0 密钥 CFF 加固 |
| 0095 | **accepted** | 运行时调用者鉴别 |

---

## 4. 构建与出包流水线

**标准四步(无 T4)**:
1. `sdk-android/defender-sdk` → `./gradlew assembleRelease`
2. `python scripts/build_x0_pack.py --so <arm64 libxcj_defender.so>`
3. `sdk-android/defender-demo` → `./gradlew assembleRelease`
4. `python scripts/patch_x0.py --apk <demo apk> --so <so> --key-hex <hex>`

**T4 完整流水线(五步)**:
```
python scripts/build_t4_pipeline.py [--key-hex <hex>] [--skip-build]
```
自动执行:生成密钥→写 t4_str_key.h→构建(T4_ENABLED)→encrypt-strings→patch_x0。

**密钥/产物红线**:不变。commit 前断言闸:
```bash
PAT='x0_key\.h|x0_derive\.h|x0_str_key|x0_jni_names\.h|cff_params\.h|_str_key_hex|xcj_payload\.bin|/build/|/\.cxx/|local\.properties|\.apk$|\.aab$'
HIT=$(git diff --cached --name-only | grep -E "$PAT" || true)
[ -n "$HIT" ] && { echo "!!! ABORT: $HIT"; exit 1; } || echo "CLEAN"
```

---

## 5. 待办(分级)

**P0(收尾)**
- **T4 端到端实跑**:`build_t4_pipeline.py` 已写好但未完整跑过(encrypt-strings 单跑通过,五步串联未验)。跑一次确认 app 正常。
- **T3 运行时集成**:`t3_segment_str.c` 基建就绪,需将 anti_frida/root_check 的关键词逐步从 obfstr_poly 切换到 T3 分段存储。

**P1(攻击成本)**
- **反 Frida K 层(时间侧信道)**:`clock_gettime(CLOCK_MONOTONIC)` 测 NOP 执行时间,traced 时 10x+ 延迟。~30 行代码,ROI 最高。
- **多态检测路径**:per-build 随机化检测顺序/阈值/分支。与 opcode XOR 洗牌配合,通用 bypass 脚本失效。
- **Honeypot 解密路径**:假解密成功 + 错误数据,浪费攻击者数天。

**P2(产品化)**
- **admin-web 功能深化**:质量报告可视化 + 加固历史 + 一键构建触发。
- **反 Frida L/M 层**:inotify maps + 行为启发式(mmap 模式/线程数/空 comm)。
- **x86/x86_64 支持**(PRODUCT v1.1)。
- **交接文档**:本文(task #215,已完成)。

---

## 6. 本轮踩过的坑(接手人必读)

1. **独立 .so 不能互相 extern**:xcj_loader 和 xcj_defender 是两个独立 SHARED library,链接时互相不可见。解法:setter 模式(加载方主动推送 base/size)。
2. **Android linker namespace 隔离**:`dlsym(RTLD_DEFAULT)` 看不到系统库(libz 等)。解法:显式 `dlopen` 缓存 handle,作为 `cl_resolve_sym` 第三级回退。
3. **ELF 首页是 r--p**:直写 ELF header 会 SIGSEGV。必须先 `mprotect(page, 4096, PROT_READ|PROT_WRITE)` → 写 → 恢复 `PROT_READ`。
4. **只擦 e_ident 16 字节**:第一个 PT_LOAD 与 ELF header 重叠,擦 64 字节会破坏 .rodata 有效数据。
5. **`NewStringUTF` 需要 null-terminated**:`plain[plen]` 必须写 `'\0'`,否则读越界 → 乱码。
6. **dexlib2 指令格式**:`CONST_16` = Format21s(非 11n);`MOVE_RESULT_OBJECT` = Format11x(非 11n);`INVOKE_STATIC` 寄存器>15 用 `INVOKE_STATIC_RANGE`(Format3rc)。
7. **MIUI/华为系统分身不算双开**:`com.miui.securitycenter` / `com.pwrd.hzwgbjx` 是系统级功能,不应触发 X6 误报。
8. **E 层文件残留 ≠ 活跃注入**:`/data/local/tmp/frida-server` 存在但没运行 → 降权为弱信号,不单独 kill。改名版(.fs176/.hluda1656)需内容扫描。

---

## 7. 本轮沉淀的纪律资产

- **auto memory** 新增:
  - `project_xiaochengjian_next_improvements`:18 项安全深化方向。
  - `project_xiaochengjian_anti_frida_todo`:K/L/M 层待做。
- **全局 skill** `redblue-hardening-verify`:不变,继续作为加固验证 SOP。
- **设计-代码对账纪律**:每次大功能合入后读 PRODUCT 功能表 → grep 验证 → 更新诚实状态列。

---

*本文事实层经 git log + 真机 logcat + 构建验证核验。叙述层为本轮亲历。接手人若发现某处与磁盘不符,以磁盘为准。祝顺利。🛡️*
