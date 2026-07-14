# ADR 0057 · 安全披露:邮箱 + GitHub Security Advisory

- 状态:accepted
- 日期:2026-07-14
- 层次:安全

## 背景

开源后需明确安全漏洞披露渠道。

## 决策

**邮箱 + GitHub Security Advisory 双渠道**

- 邮箱:security@xcj.dev(或 QQ 邮箱)
- GitHub Security Advisory:GitHub 原生功能(私密披露 + CVE 申请 + 修复后公开)
- SECURITY.md 文件说明披露流程
- 响应 SLA:48 小时确认 + 7 天修复 + 90 天公开

## 备选方案

| 方案 | 渠道 | 不选原因 |
|---|---|---|
| 公开 Issue | 任何人可见 | 漏洞修复前暴露 |
| 私密邮箱 | 仅你可见 | 单渠道风险 |
| GitHub Security Advisory | GitHub 原生 | 单渠道 |
| 邮箱 + Advisory(本方案) | 双渠道 | 合理 |

## 影响

- 正面:双渠道,负责任披露鼓励
- 负面:需及时响应(48 小时)
- 关键:不鼓励公开漏洞(修复前)

## 关联

- 关联 ADR:0042(安全公开边界)
