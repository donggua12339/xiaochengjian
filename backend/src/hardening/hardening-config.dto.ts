/**
 * 加固配置 DTO —— 用户对玄甲 X0-X9 / 天衍 T1-T6 的复选框选择
 *
 * 合规约束(ADR 0081 + 0088):
 *  - 仅注入固定 classes-xcj.dex + 30 池随机 .so,禁止自定义 smali
 *  - Manifest 修改仅限 Application 委托 + meta-data + provider
 *  - 重签必须使用开发者自备 Keystore
 */

/** 玄甲 X0-X9 模块开关 */
export interface XuanjiaModules {
  /** X0 SO 本体加密(RC4+memfd) */
  x0_soEncrypt: boolean;
  /** X3 生命周期劫持检测 */
  x3_lifecycle: boolean;
  /** X4 反动态五层(L1-L5) + 12 层反 Frida(A-M) */
  x4_antiDynamic: boolean;
  /** X5 VPN/代理检测 */
  x5_vpnProxy: boolean;
  /** X6 双开/分身检测 */
  x6_dualApp: boolean;
  /** X7 私人端口保护 */
  x7_privatePort: boolean;
  /** X8 FART 脱壳扫描 */
  x8_fart: boolean;
  /** X9 ODEX 修补检测 */
  x9_odex: boolean;
}

/** 天衍 T1-T6 模块开关 */
export interface TianyanModules {
  /** T1 自实现 Linker(匿名映射) */
  t1_customLinker: boolean;
  /** T2 VMP 保护解密函数 */
  t2_vmp: boolean;
  /** T3 字符串分段散列 */
  t3_segment: boolean;
  /** T4 DEX 字符串加密(需 ADR 0090) */
  t4_dexStringEncrypt: boolean;
}

/** 加固强度预设 */
export type HardeningPreset = 'basic' | 'standard' | 'aggressive' | 'paranoid';

/** 加固请求配置 */
export interface HardeningConfig {
  /** 产品线:玄甲或天衍 */
  productLine: 'xuanjia' | 'tianyan';
  /** 强度预设(覆盖下方模块开关) */
  preset?: HardeningPreset;
  /** 玄甲模块开关 */
  xuanjia?: Partial<XuanjiaModules>;
  /** 天衍模块开关(仅 productLine=tianyan 时有效) */
  tianyan?: Partial<TianyanModules>;
  /** kill 策略 */
  killPolicy?: {
    strongEvidence: 'kill' | 'warn' | 'none';
    weakScoreThreshold: number;
    delayMinMs: number;
    delayMaxMs: number;
  };
}

/** APK 分析结果 */
export interface ApkAnalysisResult {
  /** 包名 */
  packageName: string;
  /** 原始 Application 类名(null = 默认 android.app.Application) */
  originalApplicationName: string | null;
  /** DEX 文件列表 */
  dexFiles: string[];
  /** 是否为 MultiDex */
  isMultidex: boolean;
  /** 支持的 ABI */
  nativeAbis: string[];
  /** 是否已加固(检测到已知加固厂商特征) */
  alreadyHardened: boolean;
  /** 已检测到的加固厂商(null = 未加固) */
  detectedHardener: string | null;
  /** minSdkVersion */
  minSdkVersion: number;
  /** targetSdkVersion */
  targetSdkVersion: number;
  /** APK 大小(bytes) */
  apkSize: number;
  /** 推荐的加固配置 */
  recommendedConfig: HardeningConfig;
  /** 不可用的加固功能及原因 */
  unavailableFeatures: Array<{ feature: string; reason: string }>;
}

/** 默认玄甲配置(standard 预设) */
export const DEFAULT_XUANJIA: XuanjiaModules = {
  x0_soEncrypt: true,
  x3_lifecycle: true,
  x4_antiDynamic: true,
  x5_vpnProxy: true,
  x6_dualApp: true,
  x7_privatePort: true,
  x8_fart: false,
  x9_odex: false,
};

/** 默认天衍配置(standard 预设) */
export const DEFAULT_TIANYAN: TianyanModules = {
  t1_customLinker: true,
  t2_vmp: true,
  t3_segment: false,
  t4_dexStringEncrypt: false,
};

/** 预设 → 模块开关映射 */
export function applyPreset(preset: HardeningPreset): {
  xuanjia: XuanjiaModules;
  tianyan: TianyanModules;
} {
  switch (preset) {
    case 'basic':
      return {
        xuanjia: {
          ...DEFAULT_XUANJIA,
          x5_vpnProxy: false,
          x6_dualApp: false,
          x7_privatePort: false,
        },
        tianyan: { ...DEFAULT_TIANYAN, t2_vmp: false },
      };
    case 'standard':
      return { xuanjia: { ...DEFAULT_XUANJIA }, tianyan: { ...DEFAULT_TIANYAN } };
    case 'aggressive':
      return {
        xuanjia: { ...DEFAULT_XUANJIA, x8_fart: true, x9_odex: true },
        tianyan: { ...DEFAULT_TIANYAN, t3_segment: true },
      };
    case 'paranoid':
      return {
        xuanjia: {
          x0_soEncrypt: true,
          x3_lifecycle: true,
          x4_antiDynamic: true,
          x5_vpnProxy: true,
          x6_dualApp: true,
          x7_privatePort: true,
          x8_fart: true,
          x9_odex: true,
        },
        tianyan: {
          t1_customLinker: true,
          t2_vmp: true,
          t3_segment: true,
          t4_dexStringEncrypt: true,
        },
      };
  }
}
