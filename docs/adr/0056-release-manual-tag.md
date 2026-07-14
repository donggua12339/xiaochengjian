# ADR 0056 · 版本管理:GitHub Actions + 手动 tag

- 状态:accepted
- 日期:2026-07-14
- 层次:工程

## 背景

ADR 0034 定了 GitHub Actions CI,需明确 Release 流程。

## 决策

**手动打 tag 触发 GitHub Actions Release**

- 开发者手动打 tag(如 v1.0.0)
- GitHub Actions 自动:构建镜像 + AAR + 注入工具 jar
- 发布到 GitHub Release + Docker Hub + 私有 Maven
- Release 频率:双周(功能)+ 紧急 hotfix

## 备选方案

| 方案 | 触发 | 不选原因 |
|---|---|---|
| 手动 tag + Actions(本方案) | 手动 | 合理 |
| semantic-release 自动 | 每次 merge | 版本号跳太快 |
| Renovate 全自动 | 自动 | 不适合 SaaS(需稳定版本) |

## 影响

- 正面:版本可控,用户有稳定版本
- 负面:手动打 tag 易忘
- 版本号:语义化(MAJOR.MINOR.PATCH),MVP 是 v1.0.0

## 关联

- 关联 ADR:0034(CI/CD)、0035(版本发布)
