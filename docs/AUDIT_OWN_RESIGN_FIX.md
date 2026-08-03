# audit-own 文件上传装饰器修复报告

> 状态: in-progress | 日期: 2026-08-02 | 优先级: P0-1

## 1. 问题

`audit-own.controller.ts` 两个文件上传端点的参数装饰器损坏，导致：

1. **`resign` 端点编译/运行双坏**：
   - 用了只支持单字段的 `FileInterceptor('apk')`，但端点需要 `apk` + `keystore` 两个文件字段
   - `@Body('keystore') keystoreFile` —— keystore 是文件不是 body 字段
   - `file: Express.Multer.File` —— 无任何装饰器，运行时注入为 `undefined`
   - 其 spec 还停在 M16 重构前的旧契约（5 参数 + base64 返回），**编译不过**，拖垮 `test:cov`，导致 CI 80% 覆盖率门槛崩溃

2. **`analyze` 端点潜伏 bug**：
   - `file: Express.Multer.File` 同样无 `@UploadedFile()` 装饰器
   - 单测直接调方法（`controller.analyze(..., file)`）绕过了装饰器注入，所以测试通过
   - 但真实 HTTP 请求下 `file` 为 `undefined` → 每次都抛 `APK_FILE_REQUIRED`
   - **整个自有 APK 诊断功能在运行时是坏的**，单测全绿掩盖了它

## 2. 根因

M16 重构（base64 → streaming 二进制）时改了 controller 返回方式，但：

- 装饰器没配对（多文件场景应用 `FileFieldsInterceptor` + `@UploadedFiles()`）
- spec 没同步更新
- 单测"直接调方法"的模式天然绕过了装饰器，无法发现注入类 bug

这是"写了不跑"的典型：单测绿 ≠ 运行时可用。

## 3. API 契约（前端 `admin-web/src/api/audit.ts` 为真相源）

### POST /v1/audit/resign

**请求**（multipart/form-data）:

| 字段               | 类型 | 说明                          |
| ------------------ | ---- | ----------------------------- |
| `apk`              | file | 待回填 APK                    |
| `keystore`         | file | 自有 keystore(.jks/.keystore) |
| `keystorePassword` | text | keystore 密码                 |
| `keyAlias`         | text | key 别名                      |
| `keyPassword`      | text | key 密码                      |
| `originalName`     | text | 原始文件名                    |

**响应**:

- Body: 重签后的 APK 二进制流（`Content-Type: application/vnd.android.package-archive`）
- Header: `X-Task-Id` / `X-Old-Hash` / `X-New-Hash` / `X-Apk-Size`

### POST /v1/audit/analyze

**请求**: `apk` 单文件 + `originalName`(body) + `hardener`(query, 可选)

## 4. 修复方案

### resign

```typescript
@UseInterceptors(
  FileFieldsInterceptor(
    [
      { name: 'apk', maxCount: 1 },
      { name: 'keystore', maxCount: 1 },
    ],
    { limits: { fileSize: 200 * 1024 * 1024 } },
  ),
)
async resign(
  @CurrentDeveloper() developerId: string,
  @Req() req: AuthenticatedRequest,
  @Res({ passthrough: true }) res: Response,
  @Body() body: {...},
  @UploadedFiles() files: { apk?: Express.Multer.File[]; keystore?: Express.Multer.File[] },
) {
  const file = files?.apk?.[0];
  const keystoreFile = files?.keystore?.[0];
  ...
}
```

### analyze

补 `@UploadedFile() file: Express.Multer.File` 装饰器（spec 兼容，修运行时）。

### spec

重写 resign 4 个用例：新签名（res mock + files 对象）+ 断言返回二进制 Buffer + 断言 `res.set` 设置了 header。

## 5. 合规

签名回填属 ADR 0077 例外 A（自有 APK + 自备 keystore + V1+V2+V3），本次仅修装饰器 bug，不改变合规边界。

## 6. 测试计划

| 测试                               | 验证点               |
| ---------------------------------- | -------------------- |
| resign 缺 apk → 400                | 文件校验             |
| resign 缺 keystore → 400           | 文件校验             |
| resign 缺凭证 → 400                | 凭证校验             |
| resign 正常 → 返回 Buffer + header | M16 契约             |
| analyze 既有 3 用例不回归          | 装饰器改动 spec 兼容 |

**运行时验证（单测无法覆盖）**: 需真实 HTTP multipart 请求验证 `@UploadedFiles()` 注入生效——这是单测盲区，须手动/集成测试补。

## 7. 修编译后暴露的 3 个预存失败（同根因：特性加了没更新测试）

修好 resign 编译错误后，整个 controller spec 首次能运行，暴露出被掩盖的失败。定性后**三处都是测试过时、生产代码正确**，不改生产代码：

| #   | 测试                                           | 根因                                                                                                                                                             | 处置                                                              |
| --- | ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| A   | controller `hardener=unknown 应走普通 analyze` | `UNSUPPORTED_HARDENER` 是 commit「参数校验」里有意加的校验（supportedHardeners 白名单 + cause），代码正确；测试期望 fall-through 已过时                          | 改测试：断言抛 `UNSUPPORTED_HARDENER`                             |
| B   | service resign ×2（ENOENT work-copy.apk）      | M17 新增 `computeNonMetaInfHash(workCopyPath)`（校验重签只动 META-INF）在 apksigner 前读工作副本；测试没 mock 该私有方法，copyFile 又是 mock 未真建文件 → ENOENT | 改测试：spy `computeNonMetaInfHash` 返回一致 hash                 |
| C   | bangcle `sha256` = "unknown"                   | 适配器用 yauzl 从 apkBuffer 读真实 .so 算 hash（正确实现）；测试传 `Buffer.from('fake-apk-content')` 假 buffer，yauzl 解不开 → fallback "unknown"                | 改测试：spy `extractFileFromZip` 返回确定 buffer，断言对应 sha256 |

共同病根：**重构/加特性（M16/M17/yauzl/参数校验）时没同步更新单测**，与本项目"写了不跑"教训同源。单测直接调方法绕过装饰器/真实 fs，掩盖了这些漂移。

## 8. 最终结果

后端测试套件**全绿**：49 套件 / 623 用例 / 0 失败。期间还修了第 5 个预存编译错误（`packer-validators.spec.ts` 缺 `defenderProviderAdded` 字段，接口 ADR 0088 扩展后测试未同步）。

### 新暴露的健康问题：覆盖率门槛与现实不符

编译错误修好后 `test:cov` 首次能产出覆盖率：**Lines 62.37%**，而 CI（ci.yml）与 CLAUDE.md §5 要求后端 **≥80%**。此前编译崩溃让覆盖率根本测不出，掩盖了 18 个百分点的缺口。

两个选项（需决策）：

- **(a) 补测试到 80%**：工作量大，但符合章程承诺
- **(b) 下调门槛到现实值（如 60%）+ 设逐步提升计划**：诚实，但需改 CI 与 CLAUDE.md

## 9. 选 (a)：覆盖率已补到 80%+

用户选 (a)。按"缺口从大到小"补了 11 个测试文件，Lines 覆盖率 **62.37% → 80.36%**（2653/3301），62 套件 / 727 用例全过，CI ≥80% 门槛达成。

新增测试（按回收行数）：

| 文件                             | 覆盖内容                                                  |
| -------------------------------- | --------------------------------------------------------- |
| hardening-pipeline.spec          | runHarden 全流程 + 私有 helper（mock child_process/fs）   |
| apk-analyzer.service.spec        | analyze + 纯 helper（detectAbis/detectHardener/推荐配置） |
| hardening.service.spec           | Redis 任务管理 + startAnalysis/runAnalysis                |
| defender-config-generator.spec   | generate + validateInput 全分支                           |
| dex-injector.spec                | detectMultidex/injectDex/patchManifest/repackApk          |
| integrity.service.spec           | HMAC token 颁发/验证 + RSA/base64 解密                    |
| so-injector.spec                 | 30 池随机名/AAR 提取/注入/白名单校验                      |
| harden.service.spec              | 配置 CRUD + 质量报告 + 所有权校验                         |
| metrics.interceptor/service.spec | Prometheus 指标记录                                       |
| multer-exception.filter.spec     | 错误码映射                                                |
| developer-rate-limit.guard.spec  | 限流守卫                                                  |

**踩到的坑（值得记）**：`jest.mock('child_process')` 会丢掉 `execFile` 的 `promisify.custom` 符号，`promisify(execFile)` 退化为只取回调第一个参数 → 解构 `{stdout}` 得 undefined。修法：mock 回调把 `{stdout,stderr}` 对象作为第一个结果参数传入。

## 10. P0-2：CI 7 阶段本地实跑结果

| 阶段        | 本地结果                          | 说明                                                                                                                  |
| ----------- | --------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| 1 lint      | ✅ 修绿                           | backend 141 错 + admin-web 354 错全修(prettier --fix + no-any 类型化 + tsconfig.eslint.json 含 spec)                  |
| 2 Rust      | ✅ fmt/clippy/58 测试             | 修了 cargo fmt 格式 + 3 个新 clippy lint(is_multiple_of/byte_char_slices/contains)。tarpaulin 覆盖率 Linux-only,CI 跑 |
| 3 backend   | ✅ 80.36% ≥80%                    | 见 §9                                                                                                                 |
| 4 admin-web | ✅ lint+typecheck+39 测试+build   | 修 QualityReport/HardenConfig 的 any + audit.spec resign 与 M16 脱节                                                  |
| 5 SDK build | ⚠️ 未本地跑                       | 长 Gradle/NDK 构建,Android SDK 已在,CI ubuntu 跑                                                                      |
| 6 安全扫描  | ❌ pnpm audit 34 漏洞(1 critical) | 依赖安全债,需专门依赖升级;trivy/cargo-audit 本地未装,CI 跑                                                            |
| 7 集成 e2e  | ⚠️ 本地缺 Postgres/Redis          | 需 CI service 容器                                                                                                    |

**结论**：lint/backend/admin-web/Rust 四大代码关已绿。剩余红的三关(依赖漏洞、SDK 构建、e2e)都属环境/依赖治理,非代码 bug。

## 11. P1/P2 收尾

- **P1-1 HardenUpload 组件测试**:新增 `HardenUpload.spec.ts`(NSteps current=currentStep+1 映射 + 默认签名 onMounted 降级)+ `api/hardening.spec.ts`(downloadHardenedApk 延迟 revoke 静默失败修复 + getDefaultSignStatus)。前端 10 文件 47 用例全过。
- **P1-2 管线 CI 冒烟**:`hardening-pipeline.spec.ts` 以 mock 工具链(child_process/fs)驱动 runHarden 全 12 步(preflight→strip→config→dex→so→apktool_d→manifest→apktool_b→zipalign→sign→done),随 jest 进 CI。真实 apktool/zip 二进制的 e2e 走 scripts/test-harden-flow.mjs(需 Docker 环境)。
- **P2-1 dexlib2 说法统一**:CLAUDE.md §4 改为"3.0.7 读改 + binary patch 必接";learnings 追加 LRN-20260803-003 更正"切 2.5.2"的错误结论。
- **P2-2 启动 env 校验**:configuration.validate() 增加 DEFAULT_KS_ENABLED=true 时 PATH/PASSWORD/ALIAS/KEY_PASSWORD 齐全校验(fail fast),+4 用例。

## 12. 最终绿态

| 层                   | 结果                               |
| -------------------- | ---------------------------------- |
| backend lint         | ✅ 0 错(修 141)                    |
| backend typecheck    | ✅                                 |
| backend 测试         | ✅ 62 套件 / 731 用例              |
| backend 覆盖率       | ✅ 80.36%(≥80% 门槛)               |
| admin-web lint       | ✅ 0 错(修 354)                    |
| admin-web typecheck  | ✅                                 |
| admin-web 测试       | ✅ 10 文件 / 47 用例               |
| admin-web build      | ✅                                 |
| Rust fmt/clippy/test | ✅ 58 测试(修 fmt + 3 clippy lint) |
