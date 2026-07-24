# ADR 0089 · 小城笺加固引擎技术架构（v0.1-v0.3）

- 状态: accepted（代码实现完成，2026-07-24 真机验证通过）
- 日期: 2026-07-24
- 决策者: 小城笺项目
- 层次: 安全 / 架构
- 关联 ADR: 0088（xcj-defender-sdk 基础架构）、0081（Packer 注入机制）

## 背景

ADR 0088 定义了 xcj-defender-sdk 的防守模块体系（签名校验/反调试/反 Hook 等），但所有校验逻辑直接编译在外壳 `libxcj_defender.so` 中，存在三个结构性弱点：

1. **静态分析暴露**：MT/IDA Pro 打开 .so 即可看到全部校验函数，定位后 patch 返回指令即可绕过
2. **PLT/GOT hook 有效**：SRPatch Lv.2-3 通过 hook libc 的 open/read/mmap 拦截所有文件操作
3. **系统 Linker 依赖**：`dlopen`/`dlsym` 走系统 Linker，PLT hook 框架（Frida/SRPatch）可拦截符号解析

此外，SRPatch Lv.4（SVC Hook）在内核 syscall 入口拦截所有 `svc #0` 指令，包括我们的 inline syscall，使纯客户端文件校验理论上可被完全绕过。

## 决策

在 ADR 0088 的防守模块体系之上，新增**三层加固引擎**，形成"壳中壳 + 自实现加载 + 代码虚拟化"的纵深防御架构。

### v0.1：SO 中藏 SO（inner_defender）

- 核心校验逻辑提取为独立 `inner_defender.c`，编译为独立 .so
- 用 16 字节 XOR 密钥加密后嵌入外壳 .rodata 段（`inner_defender_enc.h`）
- 运行时 `.init_array` 阶段解密 → 加载 → 调用 → 清零解密数据
- inner .so 用 `-nostdlib` 编译（自实现 strlen/strstr/memset），不链接 libc
- **对抗效果**：IDA 打开外壳只看到加密数据；inner 不落盘，无法被提取/patch

### v0.2：自实现 Linker（custom_linker）

- 纯 C 实现 ELF 加载器，完全不依赖系统 `dlopen`/`dlsym`
- 五步加载流程：
  1. `ReserveAddressSpace`：匿名 mmap 预留地址空间
  2. `LoadSegments`：从内存 memcpy PT_LOAD 段 + mprotect 设权限
  3. `ParseDynamic`：定位 PT_DYNAMIC → 解析符号表/重定位表/构造函数
  4. `Relocate`：处理 R_AARCH64_RELATIVE / GLOB_DAT / JUMP_SLOT / ABS64
  5. `ProtectSegments`：恢复 .text 为 R-X 权限
- 外部符号解析用 `dlsym(RTLD_DEFAULT)` 回退（安全：hook 框架不改 dlsym 返回值）
- **对抗效果**：PLT/GOT hook 全部失效；匿名 mmap 在 /proc/self/maps 中无 .so 文件名

### v0.3：代码虚拟化 VM（vm_engine）

- 定义 22 个操作码的自定义 VM 指令集（MOV/ADD/XOR/CMP/JMP/LOAD/CALL_EXT/RET 等）
- 16 个 64 位虚拟寄存器 V0-V15
- 离线翻译：`build_vm_bytecode.py` 将关键 C 函数翻译为 VM 字节码
- 运行时解释：dispatch loop（switch-case 分发表）执行字节码
- 仅对 `inner_verify_hash`（hash 比较）做 VMP 保护，不全量虚拟化
- **对抗效果**：IDA 反编译看到巨大 switch-case，无法还原比较逻辑；GDB 单步效率极低

### 通用绕过检测（patch_env_detect + PatchToolDetector）

- **Native 层**（`patch_env_detect.c`）：三源交叉验证
  - `/proc/self/maps` 扫描：检测 `/data/data/` 或 `/data/user/` 下的 .apk 映射
  - `dl_iterate_phdr`：遍历 Linker 内部模块列表，检测非标准路径 .apk
  - `/proc/self/fd` + `readlinkat`：用 inline syscall 扫描 fd 指向的真实路径
- **Java 层**（`PatchToolDetector.kt`）：行为特征检测
  - data/cache 目录 .apk 文件存在性
  - `packageCodePath`/`sourceDir`/`nativeLibraryDir` 路径异常
  - ClassLoader 链异常 + DEX 元素数量异常
- **设计原则**：正向匹配（只标记应用私有目录），不维护系统路径排除列表，任何厂商/ROM 零误报

### 方案 C 客户端集成（ServerGateClient）

- 服务端公开端点 `POST /v1/integrity/client-verify`（无需开发者 JWT）
- 客户端流程：native 计算 APK hash → Java POST → 服务端比对白名单 → 颁发 JWT token → 存入 native 缓存
- serverUrl 为空时自动跳过；配置后后台线程校验，失败触发 kill
- **对抗效果**：SRPatch Lv.4 全 syscall hook 无法伪造服务端签名——唯一不可绕过的防线

## 加载时序

```
zygote fork
  → Application.attachBaseContext()
    → System.loadLibrary("xcj_defender")      ← 外壳 .so 加载
      → JNI_OnLoad
        → self_integrity_init()               ← .text CRC 缓存
        → validator_core_init_guard()         ← 守护线程启动
        → inner_loader_load() [.init_array]
          → XOR 解密 inner .so
          → cl_dlopen_mem() [自实现 Linker]
            → ReserveAddressSpace (匿名 mmap)
            → LoadSegments (memcpy + mprotect)
            → ParseDynamic + Relocate
            → ProtectSegments (恢复 R-X)
          → cl_call_constructors()
          → cl_dlsym() [4 个函数绑定]
          → 清零解密数据
  → ContentProvider.onCreate()
    → runV211Validator() [方案 A+B 校验]
    → PatchToolDetector.detect() [行为检测]
    → ServerGateClient.verify() [方案 C, 后台线程]
  → 守护线程: 5-15s 周期校验 → 异常 → SIGABRT
```

## 构建流程

```
1. python scripts/build_vm_bytecode.py    → vm_bytecode.h (VMP 字节码)
2. python scripts/build_inner_so.py       → inner_defender_enc.h (加密 inner .so)
3. ./gradlew assembleRelease              → libxcj_defender.so (外壳, 含加密 inner)
4. python scripts/patch_apk_hash.py --in-apk  → 两轮 patch APK hash + .text CRC
5. adb install                            → 真机部署
```

## 对抗能力矩阵

| 攻击手段 | 防御层 | 效果 |
|---------|--------|:----:|
| MT 重签名 | 方案 A (mmap + V2 hash) | 拦截 |
| MT 去签名校验 | 通用检测 + 行为检测 | 拦截 |
| LSPatch 签名绕过 | 路径检测 + 行为检测 | 拦截 |
| SRPatch Lv.1-3 (PLT hook) | 自实现 Linker + inline svc | 拦截 |
| SRPatch Lv.4 (全 SVC hook) | 行为检测 + 方案 C | 拦截 |
| IDA 静态分析 inner | XOR 加密 + 自实现 Linker | 不可见 |
| IDA 静态分析 VMP 函数 | VM dispatch loop | 不可还原 |
| GDB 单步 VMP 函数 | 每条指令 ~10 次 dispatch | 效率极低 |
| dump inner .so | 内存加载后清零 + 不落盘 | 窗口极小 |
| 全客户端绕过 | 方案 C 服务端 gate | 不可绕过 |

## 性能影响

| 组件 | 开销 | 说明 |
|------|------|------|
| 自实现 Linker | 一次性 ~1ms | .init_array 阶段执行，不影响运行时 |
| VMP (inner_verify_hash) | 每次调用 ~0.01ms | 120 字节字节码，循环 64 次 |
| 通用绕过检测 | 每次 ~2ms | maps + dl_iterate + fd 扫描 |
| 方案 C HTTP 请求 | 后台线程，不阻塞主线程 | 8s 超时 |

VMP 仅保护 1 个关键函数，符合 360 官方原则"只保护关键函数/类，不全量保护"。

## 合规性

- 加固引擎仅保护**自有 APK**（ADR 0077 三重校验前置）
- 不提供通用加固服务（不对外输出加固工具）
- inner .so / VM 字节码均为防守逻辑，不含进攻性代码
- 与 ADR 0088 的守城军规完全兼容

## 未来演进

- **v0.4**：inner 交叉验证接入守护线程（inner 与外壳互相校验）
- **v0.5**：更多函数 VMP 化（inner_env_check / 方案 A hash 计算核心）
- **v1.0**：Packer 集成加固选项 + admin-web UI + 产品化（"小城笺加固"）
- **v2.0**：完整代码虚拟化（LLVM pass 级别，需独立编译器后端）
