import { Injectable, ForbiddenException, Logger } from '@nestjs/common';

/**
 * 加固厂商检测器(ADR 0078 锁 A:仅梆梆一家)
 *
 * 检测 APK 是否使用梆梆加固,非梆梆加固一律拒绝(返回 UNSUPPORTED_HARDENER)。
 * 360/爱加密/乐固/腾讯乐固等其他厂商明确不支持,适配器不扩展。
 */

export type HardenerType = 'bangcle' | null;

export interface HardenerDetectResult {
  hardener: HardenerType;
  /** 检测到的梆梆特征(用于审计日志) */
  evidence?: string[];
}

/**
 * 梆梆加固特征(公开,便于审计)
 *
 * 详见 ADR 0078 §4 检测规则
 */
const BANGCLE_SO_PATTERNS = [
  /^lib\/[^/]+\/libSecShell\.so$/i,
  /^lib\/[^/]+\/libDexHelper\.so$/i,
  /^lib\/[^/]+\/libNative\.so$/i,
];

const BANGCLE_APP_PREFIXES = ['com.bangcle.', 'com.secapk.'];

/**
 * 不支持的加固厂商黑名单(检测到这些特征 -> 拒绝)
 * 用户在 ADR 0078 锁 A 明确不支持
 */
const UNSUPPORTED_HARDENER_SO_PATTERNS = [
  // 360 加固
  /^lib\/[^/]+\/libjiagu\.so$/i,
  // 爱加密
  /^lib\/[^/]+\/libexec\.so$/i,
  // 腾讯乐固
  /^lib\/[^/]+\/libshell\.so$/i,
  /^lib\/[^/]+\/libshella\.so$/i,
  // 百度加固
  /^lib\/[^/]+\/libbaiduprotect\.so$/i,
];

@Injectable()
export class HardenerDetector {
  private readonly logger = new Logger(HardenerDetector.name);

  /**
   * 检测 APK 内的加固厂商
   *
   * @param apkEntries APK zip 内的文件路径列表(由调用方从 zip 提取)
   * @param applicationClassName AndroidManifest 中 <application android:name> 的值(可选)
   * @returns 检测结果
   * @throws ForbiddenException 检测到不支持的加固厂商(UNSUPPORTED_HARDENER)
   */
  detect(
    apkEntries: string[],
    applicationClassName?: string,
  ): HardenerDetectResult {
    const evidence: string[] = [];

    // 1. 检测梆梆 so 文件
    const bangcleSos = apkEntries.filter((entry) =>
      BANGCLE_SO_PATTERNS.some((pattern) => pattern.test(entry)),
    );
    if (bangcleSos.length > 0) {
      evidence.push(`so: ${bangcleSos.join(', ')}`);
    }

    // 2. 检测梆梆 Application 类名前缀
    if (applicationClassName) {
      for (const prefix of BANGCLE_APP_PREFIXES) {
        if (applicationClassName.startsWith(prefix)) {
          evidence.push(`applicationClass: ${applicationClassName}`);
          break;
        }
      }
    }

    // 3. 检测不支持的加固厂商(锁 A:拒绝)
    const unsupportedSos = apkEntries.filter((entry) =>
      UNSUPPORTED_HARDENER_SO_PATTERNS.some((pattern) => pattern.test(entry)),
    );
    if (unsupportedSos.length > 0) {
      this.logger.warn(
        `检测到不支持的加固厂商 so: ${unsupportedSos.join(', ')}`,
      );
      throw new ForbiddenException('UNSUPPORTED_HARDENER', {
        cause:
          'detected unsupported hardener (360/ijiami/legu/baidu). Only bangcle is supported (ADR 0078 锁 A)',
      });
    }

    if (evidence.length > 0) {
      this.logger.log(`检测到梆梆加固: ${evidence.join('; ')}`);
      return { hardener: 'bangcle', evidence };
    }

    return { hardener: null };
  }
}
