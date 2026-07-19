# ADR 0074 · 第三方 OAuth 集成:GitHub + QQ(代码框架,待 OAuth app 配置)

- 状态:proposed(代码框架已就绪,待 OAuth app 配置后启用)
- 日期:2026-07-19
- 决策者:小城笺项目
- 层次:功能

## 背景

ADR 0048 决策"注册方式:邮箱 + GitHub OAuth + QQ OAuth":
- 邮箱 + 2FA:已实现(ADR 0027),主登录方式
- GitHub OAuth:开发者偏好,一键登录
- QQ OAuth:国内用户习惯

当前状态:
- 邮箱 + 2FA ✅ 已实现
- GitHub OAuth ❌ 未实现
- QQ OAuth ❌ 未实现

## 决策

### 实现范围(本 ADR)

**代码框架已就绪**:
- `backend/src/auth/oauth.controller.ts` - OAuth 路由(GET /auth/oauth/:provider + /callback)
- `backend/src/auth/oauth.service.ts` - OAuth 业务逻辑(获取 token + 获取用户信息 + 查找/创建 developer)
- `backend/prisma/schema.prisma` - Developer 表加 `githubId` / `qqOpenId` 字段(可空,用于 OAuth 关联)
- `deploy/.env.example` - 加 OAuth 配置项(client_id / client_secret / callback_url)
- admin-web 登录页加 "GitHub 登录" / "QQ 登录" 按钮(待实现,本 ADR 不含)

**待用户操作(本 ADR 不含)**:
- GitHub OAuth App 注册:https://github.com/settings/developers
  - 创建 OAuth App,获取 client_id + client_secret
  - Authorization callback URL:`https://your-domain/v1/auth/oauth/github/callback`
- QQ 互联注册:https://connect.qq.com
  - 创建应用,获取 APP_ID + APP_Key
  - 回调地址:`https://your-domain/v1/auth/oauth/qq/callback`
- 服务器 `.env` 配置实际 credentials(不入库)
- 跑 Prisma migration 加字段

### OAuth 流程

```
1. 用户点击 "GitHub 登录"
   GET /v1/auth/oauth/github
   -> 重定向到 https://github.com/login/oauth/authorize?client_id=...&redirect_uri=...&scope=user:email

2. 用户在 GitHub 授权
   GitHub 重定向回 /v1/auth/oauth/github/callback?code=xxx

3. 后端用 code 换 access_token
   POST https://github.com/login/oauth/access_token
   -> { access_token: "..." }

4. 后端用 access_token 拉用户信息
   GET https://api.github.com/user
   -> { id: 12345, email: "...", login: "..." }
   GET https://api.github.com/user/emails(若 user.email 为空)
   -> [{ email: "...", primary: true, verified: true }]

5. 查找/创建 developer
   - githubId 已存在 -> 登录(签发 JWT)
   - githubId 不存在 + email 已注册 -> 绑定(关联 githubId)
   - githubId 不存在 + email 未注册 -> 创建新 developer(无密码,只能 OAuth 登录)

6. 签发 JWT + 重定向到前端(带 token)
   重定向到 https://your-domain/oauth/callback?access_token=...&refresh_token=...
   前端拿 token 存 localStorage,跳转 dashboard
```

QQ 流程类似,区别:
- 端点:`https://graph.qq.com/oauth2.0/authorize` / `https://graph.qq.com/oauth2.0/token` / `https://graph.qq.com/user/get_user_info`
- 用户标识:`openid`(从 `/oauth2.0/me` 获取)+ `unionid`(可选)

### Developer 表字段扩展

```prisma
model Developer {
  // 现有字段...
  githubId    String?  @unique  // GitHub 用户 ID
  qqOpenId    String?  @unique  // QQ openid
  qqUnionId   String?  @unique  // QQ unionid(跨应用唯一,可选)
  // ...
}
```

**密码可空**:OAuth 注册的 developer 无密码,`passwordHash` 可空(只能 OAuth 登录)。

### 安全考量

1. **state 参数防 CSRF**:GET /auth/oauth/:provider 生成随机 state,存 Redis(5 分钟),回调时校验
2. **回调 URL 严格匹配**:OAuth app 配置的回调 URL 必须与后端配置一致
3. **OAuth 用户无密码**:OAuth 注册的 developer `passwordHash` 为 null,不能通过邮箱+密码登录
4. **绑定流程需登录**:已注册 developer 绑定 OAuth 需先登录(避免他人用 OAuth 抢占邮箱)
5. **client_secret 不入库**:OAuth credentials 走 `.env`,不入库(与 JWT 密钥同级)

### 与现有邮箱登录的共存

| 场景 | 邮箱登录 | OAuth 登录 |
|---|---|---|
| 邮箱注册 | ✅ | ❌(需先登录后绑定) |
| OAuth 注册 | ❌(无密码) | ✅ |
| 邮箱注册 + 绑定 OAuth | ✅ | ✅ |
| OAuth 注册 + 设置密码 | ✅ | ✅ |

### admin-web 登录页改动(待实现,本 ADR 不含)

Login.vue 加两个按钮:
```vue
<NButton @click="oauthLogin('github')">GitHub 登录</NButton>
<NButton @click="oauthLogin('qq')">QQ 登录</NButton>

<script>
function oauthLogin(provider: string) {
  window.location.href = `/v1/auth/oauth/${provider}`;
}
</script>
```

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| A. 不实现 OAuth | 简单 | 开发者偏好未满足 | 违反 ADR 0048 |
| B. 仅 GitHub OAuth | 开发者偏好 | 缺 QQ | 国内用户不便 |
| C. GitHub + QQ OAuth(本方案) | 覆盖国内外 | 配置复杂 | 合理 |
| D. 加微信 OAuth | 国内主流 | 需企业资质 | 个人开发者不可用 |

## 影响

- **正面(待 OAuth app 配置后):**
  - 开发者一键登录(GitHub)
  - 国内用户习惯(QQ)
  - 降低注册门槛,提升转化
- **负面:**
  - 需维护 OAuth 集成(GitHub/QQ API 变更需跟进)
  - OAuth app 审核周期(QQ 互联需审核)
  - 回调 URL 需 HTTPS(生产环境前置)
- **风险:**
  - OAuth provider 故障(GitHub/QQ 不可用)-> 用户无法 OAuth 登录,需邮箱登录兜底
  - 缓解:保留邮箱 + 2FA 作为主登录方式(ADR 0048)

## 实施前置条件

本 ADR 标为 `proposed`,实际启用需:
1. GitHub OAuth App 注册(用户操作)
2. QQ 互联应用注册(用户操作)
3. 服务器 `.env` 配置 OAuth credentials(不入库)
4. 跑 Prisma migration:`npx prisma migrate dev --name add_oauth_fields`
5. admin-web Login.vue 加 OAuth 按钮(P5.1 后续)

## 关联

- **关联 ADR:**
  - 0027(服务端安全基线,2FA + JWT)
  - 0048(注册方式:邮箱 + GitHub + QQ)
- **关联代码:**
  - `backend/src/auth/oauth.controller.ts`(框架,待实现)
  - `backend/src/auth/oauth.service.ts`(框架,待实现)
  - `backend/prisma/schema.prisma`(加 githubId / qqOpenId 字段)
  - `deploy/.env.example`(加 OAuth 配置项)
  - `admin-web/src/views/Login.vue`(加 OAuth 按钮,待实现)
- **关联文档:** `docs/handover.md` P5.1 待办
