# ADR 0063 · dex 指令插入:ImmutableDexFile 重建

- 状态:**superseded by 0068**(v2 重构撤除 dex 注入)
- 日期:2026-07-14
- 层次:注入工具

> **本 ADR 已被 [ADR 0068](0068-v2-injector-architecture-sdk-integration-only.md) 取代**(2026-07-19)。
> v2 重构移除了 dex 字节码注入路径,ImmutableDexFile 重建不再需要。
> 本文档保留作为决策追溯,不再有效。

## 背景

M3.1 + 迭代1 集成了 dexlib2 2.5.2,需明确指令插入方式。

## 决策

**ImmutableDexFile 重建**

- 只重建 Application 类(其他类保持 Immutable 引用)
- 插入 invoke-static 指令后,用 ImmutableDexFile 重写 dex

## 备选方案

| 方案 | 方式 | 不选原因 |
|---|---|---|
| ImmutableDexFile(本方案) | 重建 | 合理 |
| MutableDexClassDef | 改目标类 | 2.5.2 不稳定 |
| 原始字节码 patch | 改字节 | 偏移重算噩梦 |
| smali 反编译重编译 | apktool | 慢(ADR E3 备用) |

## 影响

- 正面:dexlib2 推荐方式,稳定
- 负面:重建 Application 类代码量大
- 开发量:3 天

## 关联

- 关联 ADR:0011(dex 主 Smali 备)、M3.1(注入工具)
