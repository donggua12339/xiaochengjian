# 默认签名功能规约

> 状态: draft | 日期: 2026-08-02

## 1. 需求

加固流程当前要求每次上传 Keystore 文件 + 填写密码/别名。开发/测试阶段频繁加固时体验差。

**目标**: 提供"默认签名"选项——服务端预配置一个开发者自有 Keystore，前端勾选后免上传直接加固。

**合规说明**: 默认 Keystore 为开发者自有签名(非共享/非第三方)，符合守城军规Ⅳ"自备合法签名"。仅为省去重复上传，不改变签名归属。

## 2. 配置

### 环境变量

| 变量                      | 说明                  | 默认值  |
| ------------------------- | --------------------- | ------- |
| `DEFAULT_KS_ENABLED`      | 是否启用默认签名      | `false` |
| `DEFAULT_KS_PATH`         | Keystore 文件绝对路径 | (无)    |
| `DEFAULT_KS_PASSWORD`     | Keystore 密码         | (无)    |
| `DEFAULT_KS_ALIAS`        | 密钥别名              | (无)    |
| `DEFAULT_KS_KEY_PASSWORD` | 密钥密码              | (无)    |

### configuration.ts 新增

```typescript
defaultKeystore: {
  enabled: process.env.DEFAULT_KS_ENABLED === 'true',
  path: process.env.DEFAULT_KS_PATH ?? '',
  password: process.env.DEFAULT_KS_PASSWORD ?? '',
  alias: process.env.DEFAULT_KS_ALIAS ?? '',
  keyPassword: process.env.DEFAULT_KS_KEY_PASSWORD ?? '',
}
```

### 本地开发 .env 示例

```env
DEFAULT_KS_ENABLED=true
DEFAULT_KS_PATH=D:\Text_Box\Key\Keystore\donggua16600.jks
DEFAULT_KS_PASSWORD=@YYM148075
DEFAULT_KS_ALIAS=donggua16600
DEFAULT_KS_KEY_PASSWORD=620753
```

## 3. API 变更

### POST /v1/hardening/harden

Body 新增可选字段:

| 字段             | 类型     | 说明                                                                       |
| ---------------- | -------- | -------------------------------------------------------------------------- |
| `useDefaultSign` | `string` | `"true"` 时使用服务端默认 Keystore，此时 keystore 文件/密码/别名字段可省略 |

**行为**:

- `useDefaultSign !== "true"` → 现有逻辑不变(必须上传 keystore + 填密码)
- `useDefaultSign === "true"`:
  1. 检查 `DEFAULT_KS_ENABLED === true`，否则 400 `"默认签名未启用"`
  2. 检查 `DEFAULT_KS_PATH` 文件存在，否则 400 `"默认 Keystore 文件不存在"`
  3. 使用配置中的 path/password/alias/keyPassword
  4. 仍走 preflight `validateKeystore` 校验
  5. ADR 0097 审计日志标注 `signMethod=default`

### GET /v1/hardening/default-sign-status (新增)

返回默认签名是否可用:

```json
{ "enabled": true, "alias": "donggua16600" }
```

或:

```json
{ "enabled": false }
```

前端据此决定是否显示"使用默认签名"选项。**不返回密码**。

## 4. 前端变更

### HardenUpload.vue

Step 3 (Keystore 区域) 新增:

1. 顶部增加 `NCheckbox`: "使用默认签名 (donggua16600)"
2. 勾选后:
   - 隐藏 Keystore 文件上传 + 密码/别名输入框
   - 提交时 `useDefaultSign=true`，不传 keystore 相关字段
3. 未勾选: 现有逻辑不变
4. 组件 `onMounted` 调 `GET /default-sign-status`，`enabled=false` 时隐藏 checkbox

### admin-web/src/api/hardening.ts

`hardenApk` 参数变更:

```typescript
export async function hardenApk(params: {
  fileId: string;
  useDefaultSign?: boolean; // 新增
  keystoreFile?: File; // 改为可选
  keystorePassword?: string; // 改为可选
  keyAlias?: string; // 改为可选
  keyPassword?: string; // 改为可选
  config: HardeningRequestConfig;
  analysisJson: string;
}): Promise<{ taskId: string }>;
```

`useDefaultSign=true` 时不 append keystore 相关 FormData 字段。

新增:

```typescript
export async function getDefaultSignStatus(): Promise<{
  enabled: boolean;
  alias?: string;
}>;
```

## 5. 安全约束

1. **密码不落代码**: 所有凭据走环境变量，`.env` 已在 `.gitignore`
2. **opt-in**: `DEFAULT_KS_ENABLED` 默认 `false`，生产环境不启用则功能不可见
3. **审计**: ADR 0097 日志区分 `signMethod=upload` vs `signMethod=default`
4. **状态接口不泄露密码**: `/default-sign-status` 只返回 `enabled` + `alias`
5. **Keystore 文件权限**: 服务器端建议 `chmod 600`

## 6. 测试计划

| 测试                                | 类型 | 验证点                              |
| ----------------------------------- | ---- | ----------------------------------- |
| 默认签名配置加载                    | 单元 | env 解析、enabled 默认 false        |
| controller useDefaultSign 分支      | 单元 | 无文件+useDefaultSign=true → 用配置 |
| controller 默认签名未启用           | 单元 | enabled=false 时 400                |
| controller 无 useDefaultSign 无文件 | 单元 | 现有逻辑 400                        |
| preflight 默认 keystore 校验        | 集成 | keytool 验证通过                    |
| 前端 checkbox 显隐                  | 手动 | enabled=false 时不显示              |
| 端到端默认签名加固                  | 手动 | 勾选默认签名 → 加固成功             |

## 7. 影响范围

| 文件                                            | 变更                                                           |
| ----------------------------------------------- | -------------------------------------------------------------- |
| `backend/src/config/configuration.ts`           | 新增 `defaultKeystore` 配置段                                  |
| `backend/src/hardening/hardening.controller.ts` | harden 方法支持 useDefaultSign + 新增 default-sign-status 端点 |
| `admin-web/src/api/hardening.ts`                | hardenApk 参数可选化 + getDefaultSignStatus                    |
| `admin-web/src/views/HardenUpload.vue`          | 默认签名 checkbox + 条件显隐                                   |
| `backend/.env.example`                          | 新增 DEFAULT_KS_* 示例                                         |
