# ADR 0075 · WM 发卡网 API 对接设计(代码框架,待 WM API 配置)

- 状态:proposed(代码框架待实现,需 WM API 文档 + 配置后启用)
- 日期:2026-07-19
- 决策者:小城笺项目
- 层次:商业

## 背景

ADR 0044 决策"支付对接:发卡网(WM)+ 会员激活码模式":
- 用 WM 发卡网卖会员激活码
- 小城笺后台加"会员激活码兑换"接口(已实现,见 `backend/src/membership/`)
- 用户购买激活码后,在小城笺后台兑换会员

ADR 0051 决策"WM 发卡不稳定兜底方案":
- WM 可用时:自动发卡,用户自助兑换
- WM 不可用时:用户扫码付款 + 备注邮箱 + 管理员手动开通

当前状态:
- ✅ 会员激活码生成 + 兑换接口已实现(`backend/src/membership/membership.service.ts`)
- ✅ 管理员后台可批量生成激活码
- ✅ 开发者可兑换激活码升级会员
- ❌ WM 发卡网 API 自动对接未实现(当前管理员手动生成 + 手动发货)
- ❌ WM webhook 自动发货未实现

## 决策

### 实现范围(本 ADR)

**本 ADR 仅做设计 + 配置预留,实际代码框架待 WM API 文档提供后实现**:

1. **配置项已就绪**:`deploy/.env.example` 加 `WM_API_BASE` / `WM_API_KEY` / `WM_MERCHANT_ID` / `WM_WEBHOOK_SECRET`
2. **代码框架待实现**:
   - `backend/src/wm/wm.service.ts` - WM API 客户端(创建商品 / 查询订单 / 验证 webhook)
   - `backend/src/wm/wm.controller.ts` - WM webhook 回调端点
   - `backend/src/wm/wm.module.ts` - 模块注册
3. **admin-web 改动待实现**:
   - 管理员后台加"WM 发卡网"配置页(配 API key + 商品 ID 映射)
   - 自动发货开关(开启后新订单自动发货)

**待用户操作(本 ADR 不含)**:
- WM 发卡网注册 + API key 申请
- 提供 WM API 文档(我看不到 WM API,无法实现实际 HTTP 请求)
- 配置 webhook URL(WM 后台填 `https://your-domain/v1/webhooks/wm/order-paid`)

### WM 对接流程(自动发货)

```
1. 管理员在小城笺后台批量生成 N 个会员激活码
2. 管理员调用 WM API 上架商品(基础版月度 / VIP 月度 / VIP 终身)
   - WM 商品关联小城笺激活码池(batchId)
3. 用户在 WM 发卡网下单 + 付款
4. WM 通过 webhook 通知小城笺:
   POST /v1/webhooks/wm/order-paid
   body: { orderId, productId, quantity, customerEmail, signature }
5. 小城笺验证 webhook 签名(HMAC-SHA256,WM_WEBHOOK_SECRET)
6. 小城笺从激活码池取 N 个 UNUSED 码,标记为 SOLD
7. 小城笺返回激活码给 WM(WM 自动发给用户),或直接邮件发给 customerEmail
8. 用户拿到激活码,在小城笺后台兑换
```

### 兜底流程(WM 不可用,ADR 0051)

```
1. 用户扫码付款(微信/支付宝个人收款码)+ 备注邮箱
2. 管理员收到款后,在小城笺后台手动生成激活码
3. 管理员邮件发激活码给用户
4. 用户兑换
```

### 数据模型扩展(待实现时)

```prisma
model WmOrder {
  id            String   @id @default(uuid())
  wmOrderId     String   @unique  // WM 订单号
  productId     String             // WM 商品 ID
  membershipLevel String          // VIP / BASIC
  durationDays  Int                // 30 / 365 / -1(永久)
  quantity      Int                // 购买数量
  customerEmail String
  status        String   @default("PENDING")  // PENDING / FULFILLED / FAILED
  activationCodeIds String[]      // 关联的激活码 ID 列表
  paidAt        DateTime
  fulfilledAt   DateTime?
  createdAt     DateTime @default(now())
}
```

### API 端点(待实现)

| 端点 | 方法 | 用途 | 鉴权 |
|---|---|---|---|
| `/v1/admin/wm/products` | POST | 创建 WM 商品(关联激活码池) | ADMIN |
| `/v1/admin/wm/products` | GET | 列出 WM 商品 | ADMIN |
| `/v1/admin/wm/orders` | GET | 列出 WM 订单 | ADMIN |
| `/v1/webhooks/wm/order-paid` | POST | WM 支付回调 | HMAC 签名 |

### 安全考量

1. **webhook 签名验证**:WM webhook 用 HMAC-SHA256 签名,`WM_WEBHOOK_SECRET` 校验
2. **幂等处理**:同一 wmOrderId 多次回调只发货一次(数据库唯一约束)
3. **激活码池防超卖**:取码时用 `UPDATE ... WHERE status='UNUSED' LIMIT N` 原子操作
4. **失败重试**:发货失败时标记 status=FAILED,管理员手动处理
5. **WM API key 不入库**:`WM_API_KEY` 走 `.env`,不入库

### 与现有 membership 模块的关系

| 模块 | 职责 | 状态 |
|---|---|---|
| `membership.service.ts` | 激活码生成 + 兑换 | ✅ 已实现 |
| `wm.service.ts`(待实现) | WM API 对接 + webhook 处理 | ⏳ 本 ADR |
| `wm.controller.ts`(待实现) | WM webhook 端点 | ⏳ 本 ADR |

WM 模块调用 membership 模块的 `generate()` 补充激活码池,不重复实现激活码逻辑。

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| A. 不对接 WM(纯手动) | 简单 | 不可规模化 | 违反 ADR 0044 |
| B. WM API 自动对接(本方案) | 自动发货 | 需 WM API 文档 | 合理(待文档) |
| C. 接独角数卡(自建发卡) | 完全可控 | 需自建发卡系统 | 推迟到 v2(ADR 0051) |
| D. 接支付宝当面付 | 官方 | 需企业资质 | 个人不可用 |

## 影响

- **正面(待 WM API 配置后):**
  - 自动发货,7x24 不需管理员介入
  - 用户自助购买 + 兑换,体验好
  - WM 不稳定时手动兜底(ADR 0051)
- **负面:**
  - 依赖 WM 服务可用性
  - 需维护 WM API 集成(WM API 变更需跟进)
- **风险:**
  - WM webhook 漏发 -> 用户付款未收到码
  - 缓解:WM 后台可查订单,管理员手动补发
  - 激活码池耗尽 -> 新订单无法发货
  - 缓解:监控激活码池数量,< 10 时告警 + 自动补生成

## 实施前置条件

本 ADR 标为 `proposed`,实际实现需:
1. WM 发卡网注册 + API key 申请(用户操作)
2. WM API 文档(用户提供,我看不到 WM API)
3. 服务器 `.env` 配置 WM credentials(不入库)
4. Prisma migration 加 WmOrder 表
5. admin-web 加 WM 配置页(管理员)

## 关联

- **关联 ADR:**
  - 0044(支付对接:发卡网 + 会员激活码)
  - 0051(WM 发卡不稳定兜底)
  - 0047(定价档位)
  - 0043(商业化定价:订阅制)
- **关联代码(待实现):**
  - `backend/src/wm/wm.service.ts`
  - `backend/src/wm/wm.controller.ts`
  - `backend/src/wm/wm.module.ts`
  - `backend/prisma/schema.prisma`(加 WmOrder 表)
  - `deploy/.env.example`(WM 配置项已加)
  - `admin-web/src/views/WmConfig.vue`(待实现)
- **关联文档:** `docs/handover.md` P5.2 待办
