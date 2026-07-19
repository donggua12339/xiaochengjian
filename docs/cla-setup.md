# CLA 配置指南(cla-assistant.io)

> 本文档说明如何为小城笺项目配置 cla-assistant.io 自动化 CLA 签署流程。
> 详见 [ADR 0055](adr/0055-cla-cla-assistant.md) · CLA 流程:cla-assistant.io。

**最后更新**:2026-07-19

## 1. 现状

当前 CLA 流程是**手动签署**(见 [docs/cla.md](cla.md)):
- 贡献者在 PR 描述中填入签署信息
- 项目方手动核对
- 签署记录分散,难追溯

ADR 0055 决策改用 **cla-assistant.io** 自动化:
- 首次 PR 自动检查 CLA 签署状态
- 点链接电子签署(个人 / 企业)
- 签署后后续 PR 自动通过
- 签署记录集中管理

**⚠️ 实际接入需仓库 owner 在 GitHub 操作,工程师无法代劳(且本项目约束禁止访问 GitHub donggua12339)。本文档提供完整接入步骤,由用户自行执行。**

## 2. 接入前提

| 项 | 要求 |
|---|---|
| GitHub 仓库 | 公开(public) |
| 仓库 owner 权限 | 必需(安装 GitHub App) |
| CLA 文本 | 已有(见 [docs/cla.md](cla.md)) |
| cla-assistant.io 账号 | 用 GitHub 登录即可 |

## 3. 接入步骤(用户操作)

### 步骤 1:登录 cla-assistant.io

1. 访问 https://cla-assistant.io/
2. 点击 **Sign in with GitHub**
3. 授权 cla-assistant 访问你的 GitHub 账号

### 步骤 2:添加仓库

1. 在 cla-assistant 控制台点击 **Add Repository**
2. 选择 `donggua12339/xiaochengjian`(或你的 fork)
3. 授权 cla-assistant GitHub App 访问该仓库
   - 需要权限:Pull requests(读写)、Issues(读)

### 步骤 3:配置 CLA

1. 在 cla-assistant 控制台选择刚添加的仓库
2. 点击 **Configure**
3. **CLA 名称**:`小城笺个人 CLA`
4. **CLA 文本**:粘贴 [docs/cla.md](cla.md) 的"个人 CLA"全文
5. **签署链接**:cla-assistant 自动生成
6. **存储方式**:
   - 推荐:GitHub Issue(在仓库内开一个 issue 存签署记录,公开可追溯)
   - 备选:cla-assistant 数据库(私有)
7. **触发条件**:所有 PR(包括首次 + 后续)
8. **失败时阻止 PR 合并**:✅ 启用(未签 CLA 的 PR 不能合并)

### 步骤 4:测试

1. 用另一个 GitHub 账号(或让贡献者)提一个测试 PR
2. cla-assistant bot 会自动在 PR 评论:
   ```
   ⚠️ CLA Not Signed
   Please sign the CLA by visiting: <link>
   ```
3. 贡献者点链接,电子签署
4. 签署后 bot 更新评论:
   ```
   ✅ CLA Signed
   Thank you for signing the CLA!
   ```
5. PR 可合并

### 步骤 5:更新 CLA 文本

如需修改 CLA 条款:

1. 在 cla-assistant 控制台编辑 CLA 文本
2. cla-assistant 自动通知已签 CLA 的贡献者重新签
3. 更新 [docs/cla.md](cla.md) 同步

## 4. 企业 CLA

ADR 0055 决策"个人 CLA + 企业 CLA 两种":

- **个人 CLA**:cla-assistant.io 自动化(本指南)
- **企业 CLA**:企业员工贡献属于职务作品,需企业签署企业 CLA
  - 模板:`cla@xcj.dev` 索取(当前是 `cla@xiaochengjian.example`,待改)
  - 流程:企业签署 PDF -> 邮件回复 -> 项目方存档
  - cla-assistant 支持企业 CLA,但需企业 GitHub Org 认证(较复杂,MVP 阶段手动)

## 5. 备选方案

如 cla-assistant.io 不可用(如网络问题),备选:

| 方案 | 优点 | 缺点 |
|---|---|---|
| cla-assistant.io(推荐) | 自动化、免费、GitHub 原生集成 | 依赖第三方服务 |
| CLA assistant(自部署) | 完全可控 | 需服务器 + 维护 |
| DCO(Developer Certificate of Origin) | 简单,git commit -s 即可 | 易忘,法律效力弱于 CLA |
| 手动 PR 描述签署(当前) | 无依赖 | 体验差,难追溯 |

## 6. CLA vs DCO 对比

| 项 | CLA | DCO |
|---|---|---|
| 法律效力 | 强(明确授权) | 弮(声明 origin) |
| 签署频率 | 一次 | 每次 commit |
| 商用授权 | 明确 | 模糊 |
| 专利授权 | 明确 | 无 |
| 适合场景 | 双模式(开源+SaaS)商用 | 纯开源项目 |

小城笺是开源 + SaaS 双模式,**需要 CLA**(ADR 0004/0055)确保所有贡献可商用。

## 7. 常见问题

**Q: cla-assistant.io 是否收费?**
A: 公开仓库免费,私有仓库收费。小城笺是公开仓库,免费。

**Q: 贡献者签署后能撤销吗?**
A: 可以,在 cla-assistant 控制台撤销。但已合并的贡献不可撤回授权。

**Q: CLA 文本变更后,已签的贡献者需重新签吗?**
A: 取决于变更内容。小变更(如联系方式)不需重签;大变更(如授权范围)需重签。cla-assistant 会自动判断并通知。

**Q: 贡献者拒绝签 CLA 怎么办?**
A: PR 不能合并。建议在 CONTRIBUTING.md 明确"PR 必须签 CLA",避免贡献者白做工。

## 8. 接入验证清单

接入完成后,确认:

- [ ] cla-assistant.io 控制台显示仓库已连接
- [ ] CLA 文本已配置(与 docs/cla.md 一致)
- [ ] 触发条件:所有 PR
- [ ] 失败时阻止合并:启用
- [ ] 测试 PR 已验证 bot 自动评论
- [ ] 签署链接可访问
- [ ] 签署后 PR 状态更新为可合并
- [ ] CONTRIBUTING.md 已更新,说明 CLA 要求

## 9. 更新 CONTRIBUTING.md

接入 cla-assistant 后,在 [CONTRIBUTING.md](../CONTRIBUTING.md) 添加 CLA 说明:

```markdown
## CLA 要求

所有 PR 必须签署 [小城笺个人 CLA](cla.md)。

首次 PR 时,cla-assistant bot 会自动评论签署链接。
签署一次后,后续 PR 自动通过。

企业贡献者请邮件 `cla@xcj.dev` 索取企业 CLA 模板。
```

## 10. 关联文档

- [ADR 0004](adr/0004-collaboration-and-open-source-governance.md) · 协作模式与开源治理
- [ADR 0055](adr/0055-cla-cla-assistant.md) · CLA 流程:cla-assistant.io
- [docs/cla.md](cla.md) · CLA 文本
- [CONTRIBUTING.md](../CONTRIBUTING.md) · 贡献指南(待补 CLA 说明)
