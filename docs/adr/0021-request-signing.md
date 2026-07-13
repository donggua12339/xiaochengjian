# ADR 0021 · 请求签名与防重放

- 状态:accepted
- 日期:2026-07-13
- 决策者:小城笺项目
- 层次:安全

## 背景

HTTPS 可被 Frida 绕过,应用层加密可被中间人篡改。需请求签名 + 防重放保证请求真实性与唯一性。

## 决策

### 请求签名:HMAC-SHA256 + nonce + 服务器时间同步

### 签名算法
```
signature = HMAC-SHA256(
  key = dynamicSecret,  // 服务端动态下发,不长期固定
  message = method + path + timestamp + nonce + bodyHash
)
```

### 防重放
- **nonce**:UUID,每次请求唯一
- **Redis 缓存 nonce 5 分钟**,5 分钟内重复 nonce 拒绝
- **timestamp**:客户端时间不可信,服务端对比 `server_timestamp`,偏差 > 60s 拒绝

### 时间同步
- 客户端启动调 `/time` 接口获取服务器时间
- 本地维护 `serverTimeOffset = serverTime - clientTime`
- 后续请求 `timestamp = clientTime + serverTimeOffset`

### 密钥管理
- **HMAC secret**:服务端动态下发,不长期固定
- 每次启动重新协商(与 AES 密钥一同)
- 服务端缓存 1 小时,过期重新协商

### 签名校验流程(服务端)
```
1. 解密请求体(AES)
2. 提取 signature / timestamp / nonce
3. 校验 timestamp 偏差 < 60s
4. 校验 nonce 未在 Redis 中(5 分钟内)
5. 重新计算 HMAC,对比 signature
6. 全部通过 -> 处理请求,写入 nonce 到 Redis
7. 任一失败 -> 拒绝,记录安全日志
```

### 不选纯 HTTPS 的原因
- HTTPS 可被 Frida 绕过
- 应用层签名是必须的

## 备选方案

| 方案 | 强度 | 不选原因 |
|---|---|---|
| 无签名 | 低 | 易被篡改 |
| HMAC + nonce | 中 | 无时间同步 |
| HMAC + nonce + 时间同步(本方案) | 高 | 合理 |

## 影响

- 正面:防重放 + 防篡改
- 负面:每次请求需查 Redis(nonce),增加延迟 ~5ms
- 风险:客户端时间偏差大导致正常请求被拒,需 `/time` 接口兜底

## 关联

- 关联 ADR:0020(通信加密)、0007(Redis)、0022(防爆破)
- 关联代码:`sdk-android/rust/src/signing.rs`、`backend/src/auth/signing.guard.ts`
