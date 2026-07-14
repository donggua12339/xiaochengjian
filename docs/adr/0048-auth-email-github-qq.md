# ADR 0048 · 注册方式:邮箱 + GitHub OAuth + QQ OAuth

- 状态:accepted
- 日期:2026-07-14
- 层次:功能

## 背景

M1.2 已实现邮箱 + 2FA。需决定是否加第三方登录。

## 决策

**邮箱(当前)+ GitHub OAuth(SaaS 上线后)+ QQ OAuth**

- 邮箱 + 2FA:已实现,主登录方式
- GitHub OAuth:开发者偏好,一键登录
- QQ OAuth:国内用户习惯

## 备选方案

| 方案 | 登录方式 | 不选原因 |
|---|---|---|
| 仅邮箱 | 邮箱+2FA | 缺第三方登录 |
| 邮箱 + GitHub(本方案扩展) | + GitHub + QQ | 合理 |
| 手机短信 | 手机+短信 | 短信贵(¥0.05/条) |

## 影响

- 正面:GitHub 吸引开发者,QQ 覆盖国内用户
- 负面:OAuth 配置复杂(GitHub/QQ 各需申请)
- 开发量:GitHub OAuth 1 天,QQ OAuth 1 天

## 关联

- 关联 ADR:0027(2FA)、M1.2(认证模块)
