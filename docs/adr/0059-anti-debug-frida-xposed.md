# ADR 0059 · 反调试深化:Frida 高级 + Xposed 检测

- 状态:accepted
- 日期:2026-07-14
- 层次:安全

## 背景

M2 实现了基础反调试(TracerPid + Frida 端口 + 模拟器)。需深化。

## 决策

**+ Frida 高级检测 + Xposed 检测,不做 Root**

- Frida 高级:扫描 frida-gadget 特征 + 内存扫描
- Xposed/LSPosed:扫描加载的 so 模块名
- 不做 Root 检测(ADR 0024 已定,误报率高)
- 检测到异常不崩溃,延迟上报(记录 Redis,下次验证拒绝)

## 备选方案

| 方案 | 检测项 | 不选原因 |
|---|---|---|
| 当前基础 | TracerPid+Frida端口+模拟器 | 不够深 |
| + Frida 高级(本方案) | + 内存扫描 | 合理 |
| + Root | + Magisk/su | 误报高(ADR 0024 排除) |

## 影响

- 正面:Frida/Xposed 检测提升逆向难度
- 负面:内存扫描性能开销
- 误报:模拟器开发场景,开发者后台可配"允许模拟器"

## 关联

- 关联 ADR:0024(反调试策略)
