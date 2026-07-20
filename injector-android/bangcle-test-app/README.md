# 梆梆加固测试 APP

> 用途:给用户上梆梆官网加固后,用小城笺"自有 APK 诊断"功能的梆梆自检模式(ADR 0078)做端到端验证。

## 构建 APK

```bash
cd injector-android
./gradlew :bangcle-test-app:assembleRelease
```

产物路径:`injector-android/bangcle-test-app/build/outputs/apk/release/bangcle-test-app-release-unsigned.apk`

## 加固流程

### 1. 注册应用(小城笺 admin-web)

登录 admin-web(https://xcj.winmelon.cn),在"应用管理"创建新应用:
- 应用名称:梆梆加固测试 APP
- 包名:`com.xcj.bangcletest`

### 2. 配置签名 hash 白名单

用你将用来重签的 keystore,计算签名 SHA-256:

```bash
# 提取证书 SHA-256
keytool -printcert -jarfile your-app.apk | grep SHA256
# 或从 keystore 直接算
keytool -list -v -keystore your.jks -alias your_alias | grep SHA256
```

在 admin-web 应用详情页,把签名 hash 加入 `signHashAllowList`。

### 3. 上梆梆官网加固

1. 访问 https://www.bangcle.com 注册账号
2. 上传 `bangcle-test-app-release-unsigned.apk`
3. 选择"加固"-> 等待加固完成
4. 下载加固后的 APK

### 4. 重签(用自有 keystore)

```bash
# 用 apksigner 重签(V1+V2+V3)
apksigner sign \
  --ks your.jks \
  --ks-pass pass:your_ks_pass \
  --ks-key-alias your_alias \
  --key-pass pass:your_key_pass \
  --v1-signing-enabled true \
  --v2-signing-enabled true \
  --v3-signing-enabled true \
  --out bangcle-test-app-resigned.apk \
  bangcle-test-app-hardened.apk
```

### 5. 验证(用小城笺梆梆自检)

#### 方式 A:injector-android APP

1. 在手机上装 injector-android(debug 版)
2. 登录(用 admin-web 账号)
3. 进入"自有诊断"Tab
4. 点"查看并接受 EULA"(锁 B 前置)
5. 选择加固 + 重签后的 APK
6. 点"执行梆梆自检"

#### 方式 B:CLI

```bash
# 先接受 EULA
injector audit bangcle-eula \
  --server-url https://xcj.winmelon.cn \
  --token <admin-jwt> \
  --accept

# 执行梆梆自检
injector audit analyze \
  --apk bangcle-test-app-resigned.apk \
  --app-id <app-id> \
  --hardener bangcle \
  --server-url https://xcj.winmelon.cn \
  --token <admin-jwt>
```

### 6. 期望结果

报告应含:
- `hardener: "bangcle"`(锁 A 检测到梆梆)
- `soFiles`:含 `libSecShell.so` / `libDexHelper.so` / `libNative.so` 中至少一个
- `signatures`:V1/V2/V3 签名状态
- 不含反编译源码(锁 C)

## 注意事项

- **加固后签名失效**:梆梆加固会替换签名,必须用自有 keystore 重签
- **包名不变**:加固不改变包名,`com.xcj.bangcletest` 仍匹配 admin-web 注册
- **三重校验**:包名白名单 + 签名 hash 比对 + 目录隔离,任一失败拒绝
- **锁 A 严格**:检测到非梆梆加固(360/爱加密/乐固等)会拒绝,不支持其他厂商
- **锁 B 前置**:未接受 EULA 不能执行梆梆自检
- **锁 C 限定**:只输出完整性报告,不脱壳不反编译不输出源码
