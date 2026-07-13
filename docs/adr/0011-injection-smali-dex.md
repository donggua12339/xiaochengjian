# ADR 0011 · APK 注入方案:Smali + dex

- 状态:accepted
- 日期:2026-07-13
- 决策者:小城笺项目
- 层次:技术栈

## 背景

APK 注入工具需要修改成品 APK 加入"小城笺"验证逻辑。两种主流方案:Smali 修改(apktool 反编译)与 dex 字节码修改(dexlib2 直接操作)。

## 决策

### 双引擎:dex 主,Smali 备
- **默认**:dex 字节码操作(dexlib2)
- **降级**:dex 操作失败时自动降级到 Smali(apktool 反编译改 smali 再重打包)
- **用户无感**:不暴露引擎选择,工具"just work"

### 引擎分工理由
- **dex 优势**:不碰资源、更快(2-5s vs 30s-2min)、兼容加固 APK 更好
- **Smali 优势**:对极端混淆 dex 兼容性更好
- **dex 失败场景**:某些极端混淆 dex 用 dexlib2 操作失败,降级 Smali

### 注入工具语言
- **Kotlin + dexlib2**(注入工具)
- **Rust**(SDK 核心,与注入工具独立)
- 两者不共享代码,各司其职

### 注入点
- **主**:Application.onCreate(99% APK 必经)
- **备**:MainActivity.onCreate(加固 APK Application 被接管的降级方案)
- **无自定义 Application 的 APK**:注入工具自动创建自定义 Application 类,注册到 AndroidManifest

### 注入逻辑
- 在原 Application.onCreate **首行**插入 `XiaochengjianSDK.init(this)`
- 注入工具**生成独立 dex**(包含 SDK 初始化代码),通过 multidex 加载,不污染原 dex

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| Smali 主,dex 备 | apktool 生态成熟 | 慢、加固兼容差 | dex 更优 |
| dex 主,Smali 备(本方案) | 快、兼容好 | dexlib2 学习成本 | 合理 |
| 并列双引擎 | 用户可选 | 增加决策负担 | 不友好 |
| 只用 dex | 最快 | 极端场景失败 | 缺降级 |

## 影响

- 正面:覆盖最大兼容性,用户无感
- 负面:维护两套引擎代码,复杂度增加
- 风险:Smali 降级路径测试覆盖必须充分

## 关联

- 关联 ADR:0009(Kotlin + Rust)、0028(注入工具架构)、0029(加固兼容)
- 关联代码:`injector/`
