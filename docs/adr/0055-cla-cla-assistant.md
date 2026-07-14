# ADR 0055 · CLA 流程:cla-assistant.io

- 状态:accepted
- 日期:2026-07-14
- 层次:工程

## 背景

ADR 0004 定了"需要 CLA",需明确签署流程。

## 决策

**cla-assistant.io 一次性签署**

- 贡献者首次 PR 时,cla-assistant.io 自动检查
- 点链接签署 CLA(个人 / 企业)
- 签署后后续 PR 自动通过

## 备选方案

| 方案 | 流程 | 不选原因 |
|---|---|---|
| 无 CLA | Apache 2.0 默认 | 商业风险 |
| CLA 一次性(本方案) | cla-assistant | 合理 |
| DCO | 每次 commit -s | 易忘 |

## 影响

- 正面:一次性签署,门槛低
- 负面:需配置 cla-assistant.io(GitHub App)
- CLA 模板:docs/cla.md(M0 已写)

## 关联

- 关联 ADR:0004(协作)、docs/cla.md
