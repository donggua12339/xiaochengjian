# 对手执行模型卡 · 2026-07-28 更新

> **SOP 阶段**: S1 威胁建模
> **更新理由**: 本轮新增反 Frida 12 层 + Honeypot + 白盒 + 多态,需更新对手能力矩阵和防线覆盖。
> **核心问题**: *我的放行/鉴别条件,在对手原样执行我代码时,是否仍成立?*

---

## 1. 对手分类(5 类)

| ID | 对手类型 | 工具/能力 | 攻击目标 | 自动化程度 |
|----|---------|----------|---------|:---------:|
| **A1** | 脚本小子 | MT 管理器默认功能、Frida 默认配置 | 一键解密字符串、attach 调试 | 全自动 |
| **A2** | 中级逆向 | MT 加强版、Frida + 脚本、Xposed/LSPosed | LSPlant hook const-string、绕检测 | 半自动 |
| **A3** | 高级逆向 | hluda-frida(字符串混淆)、Frida Stalker、IDA/Ghidra + 插件 | 绕 A-E 层检测、trace VM dispatch、静态 devirtualize | 手动+脚本 |
| **A4** | 专业团队 | 定制 Frida gadget、内存 dump + 离线分析、通用 devirtualizer | dump 运行时内存、离线还原 VM 字节码、白盒密钥提取 | 手动 |
| **A5** | 自动化平台 | 云手机农场 + 批量脱壳服务 | 规模化破解 | 全自动 |

---

## 2. 对手执行模型(每类的关键行为)

### A1 脚本小子
```
1. MT 打开 APK → 一键字符串解密 → 搜索关键词
2. Frida -U -l script.js → attach 默认端口 27042
3. 期望: 直接拿到明文字符串 / hook 成功
```

### A2 中级逆向
```
1. MT 加强版 → fork 子进程 → 复制 .so 到 cache/decrypt/ → 原样执行自举链
2. LSPlant hook const-string → 从 .rodata 自取 key 做 XOR(不调用我方解密函数)
3. System.exit(0) 抢在检测前逃生
4. 期望: 绕过文件路径检测 + 逃逸 kill 窗口
```

### A3 高级逆向
```
1. hluda-frida(字符串混淆版) → maps 中无 "frida" 关键词
2. 改名 frida-server 为 .fs176 / 改端口为非标准
3. Frida Stalker → trace 每条 ARM 指令(JS 引擎处理)
4. IDA + VM 插件 → 尝试 devirtualize dispatch loop
5. 期望: 绕 A-E 层 + trace VM + 静态还原字节码
```

### A4 专业团队
```
1. 定制 Frida gadget 嵌入 APK → 无 server 进程/端口
2. gameguardian / Frida Memory.scan → dump 运行时内存
3. 离线分析 dump: 找 ELF magic → 还原 .text → 反编译
4. 白盒 S-box 差分分析(cache-timing / 代数攻击)
5. 通用 devirtualizer: 模式匹配 dispatch loop → 还原原始指令
6. 期望: 绕过所有运行时检测 + 离线还原全部保护
```

### A5 自动化平台
```
1. 云手机批量安装 → 自动 Frida attach + dump
2. 通用脱壳服务 → 输入 APK → 输出解密 DEX
3. 期望: 规模化、无需人工干预
```

---

## 3. 防线覆盖矩阵(12 层 + 3 增强 × 5 类对手)

| 防线 | A1 脚本 | A2 中级 | A3 高级 | A4 专业 | A5 自动 | 备注 |
|------|:------:|:------:|:------:|:------:|:------:|------|
| **A** maps 关键词 | ✅ 杀 | ❌ 绕 | ❌ 绕 | ❌ 绕 | ✅ 杀 | 基础层 |
| **B** 端口 connect | ✅ 杀 | ⚠️ 改端口绕 | ❌ 绕 | ❌ 绕 | ✅ 杀 | 基础层 |
| **C** 线程名 | ✅ 杀 | ⚠️ 改名绕 | ❌ 绕 | ❌ 绕 | ✅ 杀 | 基础层 |
| **E** 文件内容扫描 | ✅ 杀 | ✅ 杀 | ⚠️ 混淆绕 | ❌ 绕 | ✅ 杀 | 降权,不单独 kill |
| **F+G** D-Bus 探测 | ✅ 杀 | ✅ 杀 | ✅ 杀 | ⚠️ 改协议绕 | ✅ 杀 | **杀手锏** |
| **H** seccomp-bpf | ✅ 拦 | ✅ 拦 | ✅ 拦 | ✅ 拦 | ✅ 拦 | **内核级,不可绕** |
| **I** 多进程交叉 | ✅ 杀 | ✅ 杀 | ✅ 杀 | ⚠️ hook 子进程绕 | ✅ 杀 | 子进程不受 hook |
| **J** rwxp 检测 | — | ✅ 杀 | ✅ 杀 | ✅ 杀 | ✅ 杀 | inline hook 痕迹 |
| **K** 时间侧信道 | — | — | ✅ 杀 | ⚠️ 校准绕 | — | Stalker 10x 延迟 |
| **L** maps 快照 | — | ✅ 杀 | ✅ 杀 | ⚠️ 匿名注入绕 | ✅ 杀 | r-xp 增长检测 |
| **M** 线程行为 | — | ✅ 杀 | ⚠️ 清 comm 绕 | ⚠️ 绕 | ✅ 杀 | 空 comm + 突增 |
| **Honeypot** | ✅ 误导 | ✅ 误导 | ✅ 误导 | ⚠️ 识别绕 | ✅ 误导 | 浪费分析时间 |
| **多态顺序** | — | — | ✅ 干扰 | ⚠️ 全排列绕 | — | 8 排列/构建 |
| **cache-timing 对抗** | — | — | — | ⚠️ 部分对抗 | — | prefetch 抹平 |
| **ELF 擦除** | — | — | — | ✅ 干扰 | — | 无 magic 定位失败 |
| **VM 行为自检** | — | — | ✅ 拦 | ✅ 拦 | — | patch dispatch 即暴露 |
| **Canary** | — | ✅ 拦 | ✅ 拦 | ✅ 拦 | — | hook ret 0 即暴露 |
| **opcode XOR** | — | — | ✅ 干扰 | ⚠️ 已知 key 绕 | — | 每构建不同 |
| **白盒 S-box** | — | — | — | ⚠️ 代数攻击 | — | 无连续密钥字节 |
| **T1 cl 匿名** | — | — | — | ✅ 干扰 | — | maps 无文件名 |
| **X3 生命周期** | — | ✅ 杀 | ✅ 杀 | ✅ 杀 | — | 劫持即 kill |
| **同步首轮** | — | ✅ 杀 | ✅ 杀 | ✅ 杀 | — | 不给 escape 窗口 |

**图例**: ✅=有效拦截 ⚠️=可绕但成本高 ❌=无效 —=不适用

---

## 4. 关键设计原则验证

> *我的放行/鉴别条件,在对手原样执行我代码时,是否仍成立?*

| 原则 | 验证结果 |
|------|---------|
| 不依赖代码自跑上下文 | ✅ 全部基于系统外部特征(maps/端口/进程/D-Bus) |
| 运行时调用者鉴别 | ✅ cl 加载路径 + maps 匿名 + ELF 擦除 |
| 探针验证即删 | ✅ CL_DEBUG 已删,LOGE 脱敏 |
| 关键词最短前缀 | ✅ "frida-agent" 非 "frida-agent-64.so" |
| 不观测不宣布成立 | ✅ 每层均有真机 logcat 验证 |

---

## 5. 已知盲区(待 S4 实战验证)

| # | 盲区 | 影响对手 | 缓解计划 |
|---|------|---------|---------|
| 1 | hluda-frida 完全混淆 maps 字符串 | A3 | F+G D-Bus 仍可检测(协议不变) |
| 2 | Frida Stalker 时间校准(减慢自身) | A3 | K 层阈值可调 + 多次采样 |
| 3 | 通用 VM devirtualizer 模式匹配 | A4 | opcode XOR 每构建变 + handler 洗牌(待做) |
| 4 | 白盒 S-box 代数攻击(DCA/DFA) | A4 | bitslice 实现(待做)或 T2 VMP 包解密函数 |
| 5 | T4 DEX 加密 ART 兼容性 | 全部 | dexlib2 writer bug 待修 |
| 6 | 子进程也被 ptrace/hook | A4 | I 层可加 seccomp 保护子进程 |

---

## 6. 下一步 S4 对抗演练计划

1. **hluda-frida 16.x 全开** → 验证 F+G 层是否仍命中
2. **Frida Stalker trace** → 验证 K 层时间检测阈值
3. **MT 加强版重测** → 验证三刀 + 同步校验 + cl 匿名组合
4. **IDA 静态分析加固 .so** → 评估 opcode XOR + Honeypot 实际干扰效果
5. **内存 dump 离线** → 验证 ELF 擦除 + SMC + 分段散列效果

*本卡为 S1 产出,S4 回包后进入 S5 对账。*
