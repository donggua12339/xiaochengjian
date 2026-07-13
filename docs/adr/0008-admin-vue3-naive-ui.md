# ADR 0008 · 管理后台:Vue3 + Naive UI

- 状态:accepted
- 日期:2026-07-13
- 决策者:小城笺项目
- 层次:技术栈

## 背景

管理后台供开发者管理应用、卡密、设备、统计。需要响应式、TS 类型友好、组件丰富。

## 决策

### 前端技术栈
- **框架**:Vue 3(Composition API + `<script setup>`)
- **UI**:Naive UI
- **构建**:Vite 5
- **状态**:Pinia
- **路由**:Vue Router 4
- **类型**:TypeScript 5 strict
- **HTTP**:axios + OpenAPI 生成客户端
- **图表**:ECharts 5(统计概览)
- **测试**:Vitest + Vue Test Utils

### 关键约束
- 所有文案走 `vue-i18n`(MVP 仅中文,预留 i18n key)
- 错误码英文(`CARD_NOT_FOUND` 等),不本地化
- 所有 API 调用走生成的客户端,禁手写 fetch
- 响应式:PC 优先,手机适配(开发者 90% 在 PC 操作)

### 功能模块
- 登录 / 2FA
- 应用管理(CRUD)
- 卡密管理(生成 / 批量 / 模板 / 查询 / 禁用 / 解绑)
- 设备管理(查看 / 解绑)
- 统计概览(激活量 / 验证量 / 失败率)
- 注入工具入口(SaaS 独占,跳转安卓 APP 或上传 APK)
- 账户设置(订阅 / VIP / 安全)

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| Vue3 + Element Plus | 国内主流 | 类型弱、设计陈旧 | 维护慢 |
| Vue3 + Naive UI(本方案) | TS 友好、设计现代 | 生态比 Element 小 | 类型化重要 |
| React + Ant Design | 国际化 | 学习成本 | 国内开发者不熟 |

## 影响

- 正面:TS 类型贯通,开发体验好
- 负面:Naive UI 生态比 Element Plus 小,部分组件需自己实现
- 风险:Naive UI 维护节奏,需关注上游

## 关联

- 关联 ADR:0005(NestJS)、0035(i18n)、0039(文档)
- 关联代码:`admin-web/`
