# ADR 0096: 反 Frida 12 层纵深架构 + 攻击成本提升矩阵

- **状态**: accepted
- **日期**: 2026-07-28
- **决策者**: 用户 + Claude
- **关联**: ADR 0093(X4 五层反动态), ADR 0095(运行时调用者鉴别), THREAT_MODEL_2026-07-28.md

## 背景

X4 五层反动态(L1-L5)在 Tier1 对抗测试中被 hluda-frida(字符串混淆版) + Frida Stalker 部分绕过。需要扩展检测维度，覆盖 5 类对手(脚本小子→专业团队→自动化平台)。

## 决策

### 1. 12 层检测架构(A-M)

在 X4 L1-L5 基础上，anti_frida.c 扩展为 12 层独立检测 + 3 项增强：

| 层 | 检测方式 | 对抗目标 | 绕过成本 |
|----|---------|---------|---------|
| A | maps 关键词扫描 | 默认 frida | 低(改名) |
| B | 端口 connect(27042-27045) | 默认端口 | 低(改端口) |
| C | /proc 线程名(gum-js-loop/gmain) | 默认线程名 | 中(改线程名) |
| E | /data/local/tmp 文件内容扫描 | 改名残留 | 中(混淆二进制) |
| F+G | D-Bus AUTH 协议探测 | **所有 Frida 变体** | **高(改协议栈)** |
| H | seccomp-bpf 拦截 process_vm_readv/writev | 内存读写 | **不可绕(内核级)** |
| I | fork 子进程交叉检测 | 父进程 hook | 高(hook 子进程) |
| J | rwxp 匿名映射检测 | inline hook | 中(改 hook 方式) |
| K | clock_gettime NOP 计时 | Stalker trace | 中(时间校准) |
| L | maps r-xp 快照对比 | 运行时注入 | 中(匿名注入) |
| M | 线程行为启发式(突增/空comm/可疑名) | 魔改 Frida | 中(清 comm+控制线程数) |

### 2. 多态检测顺序

- `ANTI_FRIDA_POLY_SEED` 构建期随机(CMake timestamp XOR)
- 8 种排列 × 9 层检测 = 每次构建不同执行顺序
- 命中即停(attack 者无法预测哪层先触发)
- 通用 bypass 脚本需覆盖所有排列 → 成本指数级上升

### 3. 攻击成本提升增强项

| 增强 | 技术 | 对抗效果 |
|------|------|---------|
| Honeypot 诱饵 | 假 API key/URL/RSA header 植入 .rodata | 浪费攻击者数小时验证假数据 |
| 白盒 S-box | XOR key 熔入 16×256 查找表 | .rodata 无连续密钥字节 |
| cache-timing 对抗 | 查表前 prefetch 全 256 entry | 差分 cache 分析失效 |
| opcode XOR 洗牌 | VM 字节码全字节 XOR(每构建不同 key) | IDA 每次看到不同字节 |
| VM 行为自检 | 字节码头部 MOV→COPY→XOR→验零 | patch dispatch 即暴露 |
| Canary 防短路 | 检测函数累积 canary,调用方验证 | hook return 0 即识破 |
| ELF 假 magic | cl 加载后 e_ident 写 \x7fPRV+garbage | 匿名页扫描定位失败 |

### 4. 降级策略

- E 层降权:文件存在≠活跃注入,不单独 kill(score+10 而非 kill)
- K 层阈值可调:5000ns 默认,对抗时间校准可提高到 20000ns
- 多态排列不含 H 层:seccomp 只装一次,不参与排列(装后不可卸载)

### 5. 已知盲区(待 S4 验证)

1. hluda 完全混淆 maps 字符串 → F+G D-Bus 仍可检测
2. Stalker 时间校准(减慢自身) → K 层多次采样对抗
3. 通用 VM devirtualizer → opcode XOR + handler 洗牌(待做)
4. 白盒代数攻击(DCA/DFA) → bitslice 实现(待做)
5. 子进程被 ptrace → I 层可加 seccomp 保护(待做)

## 后果

- 正面: 5 类对手中 A1/A2/A5 被完全覆盖,A3 被大部分覆盖,A4 成本显著提升
- 负面: anti_frida_check 执行时间增加(~5ms/轮,可接受)
- 风险: K 层在低性能设备/虚拟机上可能误报(阈值需真机调优)

## 验证计划

S4 对抗演练(2026-07-28 晚):
1. hluda-frida 16.x 全开 → 验证 F+G 层
2. Frida Stalker trace → 验证 K 层
3. MT 加强版重测 → 验证三刀+同步校验+cl 匿名
4. IDA 静态分析 → 评估 opcode XOR + Honeypot 干扰效果
5. 内存 dump 离线 → 验证 ELF 擦除 + SMC + 分段散列
