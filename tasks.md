# 小城笺 · 任务看板 (Task Board)

> 更新: 2026-08-05 | 格式: [状态] 描述 (负责方)

## 状态图例

- 🔴 阻塞 | 🟡 进行中 | 🟢 完成 | ⚪ 待做 | 🔵 验证中

---

## P0 — 本轮必须完成

- [🟢] T4 DEX 加密 encrypt-strings 逻辑 (AI)
- [🟢] T4 真机端到端验证 (AI,08-06 r5 真机通过:进程稳定+守护校验过)
- [🟢] 加固流水线后端: 异步分析+Redis 持久化+实时进度 (AI)
- [🟢] 加固流水线前端: HardenUpload 轮询+HardenTasks 列表 (AI)
- [🟢] 前后端联调: 上传 APK → 分析 → 加固 → 下载 全链路 (AI,08-08 API 链路+浏览器流程均验证)
- [🟢] 方案 A hash 预埋接入后端管线 (AI,08-08 sidecar 调 patch_apk_hash.py,预埋 hash 对账通过)
- [🟢] 重复加固拒绝闸门 (AI,08-08 识别 xcj-defender 特征+服务端复检)
- [🟢] Dockerfile aapt/gcompat 修复 (AI)
- [🟢] admin-web 部署到生产 (AI)
- [🔵] 生产环境全链路验证 (需浏览器)
- [🔵] 后端管线产物真机启动验证 (需设备重连)

## P1 — 近期完成

- [🟡] 编码规范补齐: .editorconfig/.eslint/.prettier/clang-format (AI)
- [🟡] CLAUDE.md §4 扩充编码范式 (AI)
- [🟢] husky pre-commit + lint-staged 启用 (AI,2026-08-04 起生效,含 ktlint/clang-format)
- [🟢] spec.md / plan.md / tasks.md / CHANGELOG.md (AI)
- [🟢] CI/CD: GitHub Actions lint+test+build (已有 ci.yml 7 阶段:lint/Rust≥90%/后端≥80%/前端/SDK/安全扫描/集成)
- [⚪] S4 对抗演练: hluda+Stalker+MT+IDA+dump (红蓝双方)
- [🟢] admin-web 单元测试 (AI,10 spec 47 用例,08-08 vitest3 全绿)
- [🟢] backend hardening 模块单测 (AI,覆盖率 80%→98.01%,ef06b8a)
- [🟢] 依赖漏洞治理 (AI,08-08 34→3 moderate,critical/high 清零,剩 3 需 major 跳版留专项)
- [🟡] C 代码 host 端单测 (AI,已有 obfstr_poly/so_cipher,覆盖待扩)

## P2 — 中期规划

- [⚪] 反 Frida K 层: 时间侧信道 (AI)
- [⚪] 反 Frida L 层: inotify maps (AI)
- [⚪] 反 Frida M 层: 行为启发式 (AI)
- [⚪] T2 VMP 扩围: hash_calculator + sig_verify 包入 VM (AI)
- [⚪] T3 运行时集成: 检测路径切换分段存储 (AI)
- [⚪] 白盒 bitslice: 消除 cache-timing 侧信道 (AI)
- [⚪] 用户文档: 集成指南+加固手册+API 文档 (AI)
- [⚪] admin-web i18n 国际化 (AI)

## P3 — 远期

- [⚪] x86/x86_64 架构支持
- [⚪] DEX2C 核心逻辑 native 化
- [⚪] 全量 VMP + 精准 VMP (@VMPProtect 注解)
- [⚪] 托管方案 C + 定期绕过演练 (T10)
- [⚪] 白盒密钥: str_key/RC4 key 熔入查表
- [⚪] Google Play 上架合规适配

---

## 已完成归档 (本轮 2026-07-26 ~ 07-29)

<details>
<summary>点击展开 (45 commits)</summary>

- [🟢] 玄甲 X0-X9 全套代码 + 真机验证
- [🟢] 天衍 T1-T6 代码就位
- [🟢] 反 Frida 12 层纵深 A-M
- [🟢] 攻击成本提升 7 项 (Canary/Honeypot/白盒/多态/ELF 擦除/VM 自检/opcode XOR)
- [🟢] ADR 0090 accepted (律师意见书)
- [🟢] ADR 0092-0096 accepted/superseded
- [🟢] PRODUCT 文档同步
- [🟢] LOGE 脱敏 30 条
- [🟢] X6 MIUI 误报修复
- [🟢] X3 相对类名修复
- [🟢] cl ClassLoader 传递修复
- [🟢] 加固流水线: 异步+Redis+实时进度+任务列表
- [🟢] Dashboard 新用户引导重构
- [🟢] 侧边栏分组
- [🟢] ADR 0097 合规变更 (自有 APK 注入+风险自担)
- [🟢] FormData Content-Type 修复
- [🟢] Dockerfile aapt PATH + gcompat 修复
- [🟢] android-hardening-impl skill 创建
- [🟢] 交接文档 HANDOVER-PROMPT-2026-07-27.md

</details>
