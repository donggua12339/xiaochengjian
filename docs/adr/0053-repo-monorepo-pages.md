# ADR 0053 · 仓库结构:单仓库 + GitHub Pages

- 状态:accepted
- 日期:2026-07-14
- 层次:工程

## 背景

ADR 0036 已定 Monorepo,开源时确认是否拆分。

## 决策

**单仓库 Monorepo(当前)+ GitHub Pages 文档站**

- 仓库:xiaochengjian/xiaochengjian(当前 Monorepo)
- 文档:docs/ 用 GitHub Pages 部署(免费)

## 备选方案

| 方案 | 结构 | 不选原因 |
|---|---|---|
| 单仓库(本方案) | Monorepo | 合理 |
| 拆分核心 + 文档 | 双仓库 | 同步麻烦 |
| 按子项目拆分 | 多仓库 | 碎片化 |

## 影响

- 正面:issue/PR 集中,贡献门槛低
- 负面:仓库大(含 Rust/Kotlin/TS/部署)
- 关键:各子项目有独立 README,根 README 作为门面

## 关联

- 关联 ADR:0036(Monorepo)、0054(README)
