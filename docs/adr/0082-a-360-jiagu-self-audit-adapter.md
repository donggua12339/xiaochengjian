# ADR 0082-A · 360 加固保自检适配器(V1.5b)

- 状态:proposed(律师前置,代码未实现)
- 日期:2026-07-21
- 决策者:小城笺项目
- 层次:功能 / 安全 / 合规
- 关联 ADR:0078(梆梆适配器,锁 A 扩展)

## 背景

ADR 0078 锁 A 原文:"仅梆梆一家,360 / 爱加密 / 乐固 / 腾讯乐固等其他加固方案明确不支持"。

V1.5 阶段扩展加固自检范围,基于市场调研(CSDN Android 加固平台横评),国内独立开发者加固使用率 Top 3 为:梆梆、360 加固保、腾讯乐固,合计覆盖约 90% 目标用户。

本 ADR 扩展 ADR 0078 锁 A 的支持范围,增加 360 加固保。

## 决策

### 360 加固保特征

| 特征 | 值 |
|---|---|
| so 文件 | libjiagu.so(360 加固标志) |
| Application 类名前缀 | com.qihoo.* / com.ijiami.* |
| EULA | 需律师确认第 4.1 条是否禁止反向工程 |

### 锁 A 扩展(本 ADR)

ADR 0078 锁 A 从"仅梆梆"扩展为"梆梆 + 360 加固保"。其他锁(B/C + ADR 0081 锁 7)不变。

### 检测规则

```typescript
// 360 加固保 so 特征(从 UNSUPPORTED 列表移到支持列表)
const QIHOO_360_SO_PATTERNS = [
  /^lib\/[^/]+\/libjiagu\.so$/i,
];

const QIHOO_360_APP_PREFIXES = ['com.qihoo.', 'com.ijiami.'];
```

### EULA 前置(锁 B)

360 加固保独立 EULA 文本(`docs/compliance/audit-eula-360.md`,待起草),开发者备案时强制勾选。

### 完整性报告(锁 C)

输出字段与梆梆适配器一致(soFiles / entryClass / signatures / suspiciousCalls / scanVersion / scanTime),不含源码。

## 前置合规检查(强制)

**ADR 0082-A 进入开发阶段前,必须完成律师咨询**,重点确认:

1. **360 加固保 EULA 第 4.1 条**:是否明确禁止"反向工程"?
   - 如果禁止:本 ADR 熔断,状态改 rejected,不开发
   - 如果不禁止:本 ADR 改 accepted,可开发
2. **"对加固层做完整性扫描"是否构成"反向工程"**:需律师界定
3. **360 加固保 so 文件(libjiagu.so)的版权**:扫描 so 文件 SHA-256 是否侵犯 360 著作权

## 风险熔断

若律师评估 360 加固保风险不可控,本 ADR 自动失效,HardenerDetector 继续把 libjiagu.so 列为 UNSUPPORTED_HARDENER。

## 关联

- 0078(梆梆适配器,锁 A 扩展)
- 0079(部分取代 0067,360 场景同样适用)
- 0077(自有 APK 诊断,三重校验)
- 0082-B(腾讯乐固,并行)
- 0082-C(爱加密,V2 评估)
