import { Injectable, ForbiddenException, Logger } from '@nestjs/common';

/**
 * 加固厂商检测器(ADR 0078 锁 A + ADR 0082-A/B 扩展)
 *
 * V1.5 支持范围:
 *  - 梆梆(ADR 0078,已实现)
 *  - 腾讯乐固(ADR 0082-B,V1.5a)
 *  - 360 加固保(ADR 0082-A,V1.5b)
 *
 * 不支持范围(明确拒绝):
 *  - 爱加密(ADR 0082-C,V2 评估)
 *  - 百度加固 / 网易易盾 / 几维 / 顶象 / 天磊 / FairGuard / Guardsquare / Appdome / Digital.ai / Promon / AppSealing
 */

export type HardenerType = 'bangcle' | 'legu' | 'qihoo360' | null;

export interface HardenerDetectResult {
  hardener: HardenerType;
  /** 检测到的特征(用于审计日志) */
  evidence?: string[];
}

/**
 * 梆梆加固特征(ADR 0078)
 */
const BANGCLE_SO_PATTERNS = [
  /^lib\/[^/]+\/libSecShell\.so$/i,
  /^lib\/[^/]+\/libDexHelper\.so$/i,
  /^lib\/[^/]+\/libNative\.so$/i,
];

const BANGCLE_APP_PREFIXES = ['com.bangcle.', 'com.secapk.'];

/**
 * 腾讯乐固特征(ADR 0082-B)
 */
const LEGU_SO_PATTERNS = [
  /^lib\/[^/]+\/libshell\.so$/i,
  /^lib\/[^/]+\/libshella\.so$/i,
];

const LEGU_APP_PREFIXES = ['com.tencent.'];

/**
 * 360 加固保特征(ADR 0082-A)
 */
const QIHOO360_SO_PATTERNS = [
  /^lib\/[^/]+\/libjiagu\.so$/i,
];

const QIHOO360_APP_PREFIXES = ['com.qihoo.util.', 'com.qihoo.'];

/**
 * 不支持的加固厂商黑名单(检测到这些特征 -> 拒绝)
 * ADR 0082 锁 A:除梆梆/腾讯乐固/360 外,其他厂商明确不支持
 */
const UNSUPPORTED_HARDENER_SO_PATTERNS = [
  // 爱加密(ADR 0082-C,V2 评估)
  /^lib\/[^/]+\/libexec\.so$/i,
  // 百度加固
  /^lib\/[^/]+\/libbaiduprotect\.so$/i,
  // 网易易盾
  /^lib\/[^/]+\/libnesec\.so$/i,
  // 几维安全
  /^lib\/[^/]+\/libkwscmm\.so$/i,
  // 通付盾
  /^lib\/[^/]+\/libmobifree\.so$/i,
  // 娜迦
  /^lib\/[^/]+\/libnagain\.so$/i,
];

export interface HardenerPattern {
  name: string;
  soPatterns: RegExp[];
  appPrefixes: string[];
}

/**
 * 已支持的加固厂商列表(按检测优先级排序)
 */
const SUPPORTED_HARDENERS: HardenerPattern[] = [
  {
    name: 'bangcle',
    soPatterns: BANGCLE_SO_PATTERNS,
    appPrefixes: BANGCLE_APP_PREFIXES,
  },
  {
    name: 'legu',
    soPatterns: LEGU_SO_PATTERNS,
    appPrefixes: LEGU_APP_PREFIXES,
  },
  {
    name: 'qihoo360',
    soPatterns: QIHOO360_SO_PATTERNS,
    appPrefixes: QIHOO360_APP_PREFIXES,
  },
];

@Injectable()
export class HardenerDetector {
  private readonly logger = new Logger(HardenerDetector.name);

  /**
   * 检测 APK 内的加固厂商
   *
   * @param apkEntries APK zip 内的文件路径列表
   * @param applicationClassName AndroidManifest 中 <application android:name> 的值(可选)
   * @returns 检测结果
   * @throws ForbiddenException 检测到不支持的加固厂商(UNSUPPORTED_HARDENER)
   */
  detect(
    apkEntries: string[],
    applicationClassName?: string,
  ): HardenerDetectResult {
    // 1. 先检测不支持的厂商(黑名单优先,拒绝)
    const unsupportedSos = apkEntries.filter((entry) =>
      UNSUPPORTED_HARDENER_SO_PATTERNS.some((pattern) => pattern.test(entry)),
    );
    if (unsupportedSos.length > 0) {
      this.logger.warn(
        `检测到不支持的加固厂商 so: ${unsupportedSos.join(', ')}`,
      );
      throw new ForbiddenException('UNSUPPORTED_HARDENER', {
        cause:
          'detected unsupported hardener (ijiami/baidu/netease/kiwi/dingxiang/mobifree/nagain). Only bangcle/legu/qihoo360 are supported (ADR 0078 + 0082-A/B)',
      });
    }

    // 2. 按优先级检测已支持的厂商
    for (const hardener of SUPPORTED_HARDENERS) {
      const evidence: string[] = [];

      // 检测 so 文件
      const matchedSos = apkEntries.filter((entry) =>
        hardener.soPatterns.some((pattern) => pattern.test(entry)),
      );
      if (matchedSos.length > 0) {
        evidence.push(`so: ${matchedSos.join(', ')}`);
      }

      // 检测 Application 类名前缀
      if (applicationClassName) {
        for (const prefix of hardener.appPrefixes) {
          if (applicationClassName.startsWith(prefix)) {
            evidence.push(`applicationClass: ${applicationClassName}`);
            break;
          }
        }
      }

      if (evidence.length > 0) {
        this.logger.log(
          `检测到 ${hardener.name} 加固: ${evidence.join('; ')}`,
        );
        return { hardener: hardener.name as HardenerType, evidence };
      }
    }

    return { hardener: null };
  }

  /**
   * 检查厂商是否已支持(供 controller 校验 ?hardener= 参数)
   */
  isSupported(hardener: string): boolean {
    return SUPPORTED_HARDENERS.some((h) => h.name === hardener);
  }
}
