# X4 五层反动态响应链 · 编码完成报告

> 完成日期: 2026-07-25
> 对应 ADR: 0093(玄甲 X4 五层反动态分析引擎)
> 对应规格: xcj_x4_encoding_prompt.md(Q1-Q5 拷问定稿的可编码 spec)

---

## 一、文件清单(22 个文件 / 2095 行)

### 编译期锁定层
| 文件 | 行数 | 职责 |
|---|---|---|
| `score_weights.h` | 102 | 阈值/衰减/存在感/强证据编号 + 全部 `_Static_assert` |
| `weak_signals.h` | 59 | L1/L2/L3 权重表 + 每条权重的编译期断言 |

### 强证据通道(5 条)
| 文件 | 行数 | 职责 |
|---|---|---|
| `strong_evidence.h` | 70 | 5 条强证据检测函数声明 + strong_enabled 开关 |
| `strong_evidence.c` | 255 | ① 签名hash ② CREATOR CL ③ 23946 LISTEN ④ frida-agent maps ⑤ state=T∧TracerPid |
| `strong_evidence_classloader.c` | 19 | CREATOR JNI 桥接占位(真机走 Java 层) |

### 弱信号通道(L1/L2/L3)
| 文件 | 行数 | 职责 |
|---|---|---|
| `weak_detector.h` | 47 | L3/L2/L1 检测函数声明 + 基线初始化 |
| `weak_detector.c` | 367 | L3 inotify/L2 seccomp+rwx+时间差+CREATOR-sysCL/L1 memfd+anon:dalvik+frida子串+zygisk |
| `weak_detector_jni.c` | 16 | CREATOR 弱信号 JNI 桥接占位 |

### 衰减累计引擎
| 文件 | 行数 | 职责 |
|---|---|---|
| `score_engine.h` | 45 | 三通道状态查询接口 + 软豁免清零 |
| `score_engine.c` | 197 | 三通道独立 + 衰减 0.7 + 底噪 0.3 + N=5 + last_max_round_hit 注释纪律 |

### 三通道响应链
| 文件 | 行数 | 职责 |
|---|---|---|
| `response_chain.h` | 37 | 优先级链声明 + onViolation 枚举 |
| `response_chain.c` | 155 | dry-run > 强证据 > 有效分kill > 有效分warn > 存在感 + trigger_kill/warn |

### 配置加载
| 文件 | 行数 | 职责 |
|---|---|---|
| `config_loader.h` | 64 | 5 字段 config + strongEvidenceSwitches 结构 |
| `config_loader.c` | 119 | 单向开关写入(只关不开)+ softExempt/hardExempt 查询 |
| `config_loader_jni.c` | 18 | config JNI 桥接占位(真机走 DefenderConfig.kt) |

### dry-run 四级优先级链
| 文件 | 行数 | 职责 |
|---|---|---|
| `dry_run.h` | 36 | is_enabled / set_override / log_decision 接口 |
| `dry_run.c` | 76 | override > config > Gradle默认 > fallback + 决策链日志 |

### 日志上报
| 文件 | 行数 | 职责 |
|---|---|---|
| `telemetry.h` | 31 | 日志结构 + 上报接口 |
| `telemetry.c` | 108 | 位图+哈希+枚举字段 + dry-run 全量/enforce 仅告警上报 |

### 客户端自愈
| 文件 | 行数 | 职责 |
|---|---|---|
| `auto_rollback.h` | 32 | 三条件触发 + 紧急回滚接口 |
| `auto_rollback.c` | 133 | model kill spike + lone strong evidence + repeat victim |

### 主入口
| 文件 | 行数 | 职责 |
|---|---|---|
| `x4_core.c` | 109 | init 顺序 + 守护线程注册 + 每轮调度 |

---

## 二、编译期断言验证

### 正向验证 ✅
默认值全部通过:
```
KILL_THRESHOLD = 70  (60 ≤ 70 ≤ 80)  ✅
WARN_THRESHOLD = 40  (30 ≤ 40 ≤ 50)  ✅
gap = 70 - 40 = 30 ≥ 20             ✅
SAFETY_MARGIN = 20 ≥ 15             ✅
MAX_WEAK_WEIGHT = 50               ✅
DECAY_FACTOR = 0.7                  ✅
FLOOR_NOISE_FACTOR = 0.3            ✅
ZERO_ROUNDS = 5                     ✅
FLOOR_DECAY_ROUNDS = 3              ✅
PRESENCE_ALERT = 10                 ✅
STRONG_EVIDENCE_COUNT = 5           ✅
9 条弱信号权重全部 ≤ 50            ✅
```

### 反向验证 ✅
3 个反向测试均被拦截:
| 测试 | 输入 | 拦截结果 |
|---|---|---|
| `X4_KILL_THRESHOLD_OVERRIDE=30` | kill 阈值过低 | `static assertion failed: "killThreshold too low, L1 may become single-hit kill"` |
| `X4_KILL_THRESHOLD_OVERRIDE=90` | kill 阈值过高 | `static assertion failed: "killThreshold too high, real attacks may slip"` |
| 试图外部 `#define W_L3_INOTIFY_MEM 60` | 覆盖弱信号权重 | 被 `weak_signals.h` 内部 `#define 50` 自动覆盖,无法绕过 |

**结论**: 硬约束从"文档约定"升级为"编译器强制",任何开发者想"临时调到 60 试试"会直接编译失败。

---

## 三、Q1-Q5 定稿逐条对照表

### Q1 根决策(硬/软二分 + 独立 hardKill + dry-run 总闸)
| 定稿 | 落地 | 文件:行 |
|---|---|---|
| 三通道独立 | score_engine 三通道分离(round_score/presence/strong) | `score_engine.c:96-180` |
| 独立 hardKill | response_chain 第二优先级直接 kill,无视 onViolation | `response_chain.c:71-76` |
| dry-run 总闸 | response_chain 第一优先级短路 | `response_chain.c:60-66` |

### Q2 强证据 5 条
| 强证据 | 实现 | 文件:行 |
|---|---|---|
| ① 签名 hash 不匹配 | 复用 `sig_verify_check_b()` | `strong_evidence.c:62-77` |
| ② CREATOR 应用 CL 代理 | 委托 Java 层 + JNI 桥接 | `strong_evidence.c:83-91` + `strong_evidence_classloader.c` |
| ③ 23946 LISTEN | svc 直读 /proc/net/tcp + tcp6 | `strong_evidence.c:108-159` |
| ④ frida-agent maps 精确匹配 | svc + x4_strstr(自实现) | `strong_evidence.c:164-185` |
| ⑤ state=T ∧ TracerPid≠0 双条件 | svc + 双条件同时判定 | `strong_evidence.c:195-228` |

### Q3 衰减动力学
| 定稿 | 落地 | 文件:行 |
|---|---|---|
| (C) 衰减累计 | score = round_score + score × 0.7 | `score_engine.c:159-162` |
| (X) 每轮加权重 + 衰减 | round_has_hit 时加分 + 衰减 | `score_engine.c:159-162` |
| Q3.3.a state=T 升强集双条件 | 见 Q2⑤ | `strong_evidence.c:195-228` |
| Q3.3.b 权重硬约束 + _Static_assert | 9 条断言 + MAX_WEAK_WEIGHT=50 | `score_weights.h:80-94` + `weak_signals.h:50-58` |
| Q3.3.c L1/L2/L3 三级权重表 | L3=50/L2=40/L1=30 | `weak_signals.h:18-32` |
| Q3.3.d 衰减 0.7 + 底噪 0.3 + N=5 | 全部 _Static_assert 锁死 | `score_weights.h:38-44` + `score_engine.c:138-180` |
| Q3.3.e L1 不计入有效分但计入存在感 | L1 命中只 `round_presence++`,不 `round_score +=` | `score_engine.c:139-156` |
| Q3.3.f 底噪 last_max_round_hit 永不下降 | 取 max 不取覆盖 | `score_engine.c:39-56` + `score_engine.c:159-162` |
| 底噪 N 轮后按 0.7 衰减 3 轮归零 | g_floor_decay_counter 计数 | `score_engine.c:166-176` |

### Q4 config 字段设计
| 定稿 | 落地 | 文件:行 |
|---|---|---|
| Q4.1 阈值硬编码 + 构建期覆盖带编译锁 | X4_KILL_THRESHOLD_OVERRIDE 宏 + [60,80] 断言 | `score_weights.h:56-67` |
| Q4.2 onViolation 只控有效分通道 | response_chain 第三/四优先级按 onViolation 分支 | `response_chain.c:78-103` |
| Q4.3 exempt 拆 softExempt/hardExempt | 两字段独立 + hardExempt 二次确认(占位) | `config_loader.h:21-29` + `config_loader.c:46-67` |
| Q4.4 dryRun 四级优先级 + 决策链日志 | override > config > Gradle > fallback | `dry_run.c:33-50` + `dry_run.c:60-67` |
| last_max_round_hit 注释纪律 | 详细不变量注释 | `score_engine.c:39-56` |

### Q5 灰度发布
| 定稿 | 落地 | 文件:行 |
|---|---|---|
| Q5.4 dry-run 期全量上报 | telemetry_log_round dry-run 全量分支 | `telemetry.c:74-84` |
| Q5.5 三条件自动回滚 | model spike + lone strong + repeat victim | `auto_rollback.c:33-89` |
| Q5.5 紧急 dry-run 回滚兜底 | x4_auto_rollback_emergency | `auto_rollback.c:117-120` |
| Q5.6 strongEvidenceSwitches 单向 | apply_strong_switch 只关不开 | `config_loader.c:81-95` |

---

## 四、与现有 X4 模块的集成关系

本次新增的响应链模块**复用**了已有的 X4-0/1/2/3/4/5 基建,不重复实现:

| 已有模块 | 本次复用方式 |
|---|---|
| `x4_svc.c` (svc 内联系统调用) | strong_evidence / weak_detector 全部用 svc 直读 /proc |
| `x4_str.c` (自实现字符串) | 防 libc hook strstr,所有 maps/status 解析都用 x4_strstr |
| `x4_daemon.c` (守护线程框架) | x4_core 注册 x4_round_check 回调 |
| `x4_anti_dump.c` (L3 反 dump) | 复用 `x4_check_memfd_count` / `x4_check_inotify_triggered` |
| `sig_verify.c` (方案 A/B/C) | 强证据① 复用 `sig_verify_check_b` |
| `X4InjectionDetector.kt` (Java 层 CREATOR 检测) | strong_evidence② / weak_detector L2-4 通过 JNI 委托 |

**集成方式**: 新增模块通过 extern 声明引用已有接口,不修改已有代码。Gradle CMakeLists.txt 需要把 10 个新 .c 文件加入构建列表(后续 PR)。

---

## 五、合规声明

1. **守城军规**: 所有检测作用于"我的 APP 进程自身",不读其他进程数据,符合 ADR 0077 边界
2. **隐私合规**: telemetry 字段全部是位图/哈希/枚举,无用户业务数据(Q5.4)
3. **不照搬攻击代码**: 所有实现独立重写,参考文献标注于 ADR 0093 与 docs/x4/
4. **不承诺 100% 防御**: 目标"让一键攻击失效,迫使攻击者升级到手动逆向 + 多工具组合"

---

## 六、已知限制与未来优化方向

### 当前限制
1. **JNI 桥接占位**: CREATOR ClassLoader 检测 / config 加载 / MDM 探测的 JNI 实现仍是占位(返回 false / 默认值),需后续 PR 接通 Java 层
2. **host gcc 只做语法验证**: 真机 arm64 完整链接需 Gradle NDK 构建(host mingw 缺 `sys/syscall.h` 等 Linux 头,无法链接成 .so)
3. **strong_evidence ① 签名 hash**: 依赖 `g_x4_apk_path` / `g_x4_expected_hash` 全局变量,需 Java 层在 `attachBaseContext` 时通过 JNI 填充
4. **telemetry 上报通道**: `x4_telemetry_send` 是 extern 声明,真机实现需后续 PR 接通服务端
5. **auto_rollback 持久化**: 当前 kill 计数仅在内存,App 重启后清零,需后续 PR 接 SharedPreferences 持久化

### 未来优化方向(P1-P3)
- **P1**: 接通 5 处 JNI 桥接(CREATOR 强 / CREATOR 弱 / config 加载 / MDM 探测 / telemetry 上报)
- **P1**: 守护线程周期接 X4 完整 5 层检测(当前仅 onCreate 一次)
- **P1**: seccomp 检测读 /proc/self/status Seccomp 字段(红方脚本 37 启发)
- **P2**: Gradle CMakeLists.txt 加入 10 个新文件
- **P2**: Tier1 脚本篡改对抗测试(错 key 重签 / zip 改字节 → 验证方案 A kill)
- **P2**: Tier2 真机 MT/NP/LSPatch 对抗测试
- **P3**: Linker 抹 Section Header + 多 PT_DYNAMIC 迷惑
- **P3**: VMP handler 洗牌

---

## 七、自检清单

- [x] 10 个模块文件全部按 spec 第 719 行顺序实现
- [x] 每个文件 `gcc -fsyntax-only` 零警告零错误
- [x] 编译期 _Static_assert 全部生效(正向通过 + 反向拦截)
- [x] Q1-Q5 定稿逐条落地(对照表见第三节)
- [x] last_max_round_hit 注释纪律按 Q3 收尾要求写死
- [x] 优先级链注释按 Q4.2 要求写进 response_chain.c
- [x] 不修改已有 X4 代码,通过 extern 复用
- [x] host 测试目录已清理,不入库
- [x] 合规声明明确(ADR 0077 边界 + 隐私合规 + 不照搬攻击代码)
- [x] 已知限制如实列出,后续 P1-P3 优化方向明确

---

## 八、下一步建议

1. **立即**: 把 10 个新 .c 文件加入 `CMakeLists.txt`,跑一次 Gradle arm64 构建,确认 NDK 工具链下完整链接通过
2. **接通 JNI**: 5 处 JNI 桥接占位补真机实现(CREATOR / config / MDM / telemetry)
3. **真机验证**: 干净设备跑一次,score 应=0(与现有 X4-1~5 真机验证一致)
4. **Tier1 对抗测试**: 错 key 重签 → 验证强证据① 命中 → kill
5. **Tier2 对抗测试**: 装 frida → 验证强证据③④ 命中 → kill;装 MT/NP → 验证强证据①② 命中 → kill

X4 响应链从这一刻起,从"设计文档"变成"已编码的可执行 spec"。
