import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import type { ApkAnalysisResult, HardeningConfig } from './hardening-config.dto';
import { applyPreset } from './hardening-config.dto';

const execFileAsync = promisify(execFile);

/** aapt 全路径 fallback(Docker 容器内 build-tools 路径) */
const AAPT_PATHS = ['aapt', '/opt/android-sdk/build-tools/34.0.0/aapt'];

/** 进度回调 */
export type ProgressCallback = (step: string, progress: number, detail?: string) => void;

/**
 * APK 结构分析器
 *
 * 分析上传的 APK 文件,提取:
 *  - 包名、Application 类名
 *  - DEX 文件列表(MultiDex 检测)
 *  - 原生 ABI(arm64-v8a / armeabi-v7a)
 *  - 已加固检测(已知加固厂商特征)
 *  - SDK 版本
 *
 * 合规:仅做只读分析,不修改 APK 内容(ADR 0083)
 */
@Injectable()
export class ApkAnalyzerService {
  private readonly logger = new Logger(ApkAnalyzerService.name);

  /** 已知加固厂商特征(与 hardener-detector.ts 对齐) */
  private readonly HARDENER_SIGNATURES: Array<{ name: string; patterns: RegExp[] }> = [
    { name: 'bangcle', patterns: [/libsecexe\.so/i, /libbangcle\.so/i, /com\.bangcle\./i] },
    { name: 'legu', patterns: [/libshell\.so/i, /libshella\.so/i, /com\.tencent\./i] },
    { name: 'qihoo360', patterns: [/libjiagu\.so/i, /com\.qihoo\./i] },
    { name: 'ijiami', patterns: [/libexec\.so/i, /libexecmain\.so/i] },
  ];

  /**
   * 分析 APK 结构
   */
  async analyze(apkPath: string, onProgress?: ProgressCallback): Promise<ApkAnalysisResult> {
    const stat = await fs.stat(apkPath);
    if (stat.size < 1024) {
      throw new BadRequestException('APK_TOO_SMALL');
    }
    if (stat.size > 500 * 1024 * 1024) {
      throw new BadRequestException('APK_TOO_LARGE', {
        cause: 'APK size exceeds 500MB limit',
      });
    }

    // 1. 用 unzip -l 列出 APK 内容
    onProgress?.('unzip', 10, '正在解压 APK 文件列表...');
    const { stdout: zipList } = await execFileAsync('unzip', ['-l', apkPath], {
      timeout: 30_000,
      maxBuffer: 10 * 1024 * 1024,
    });

    const entries = this.parseZipEntries(zipList);
    onProgress?.('unzip', 20, `发现 ${entries.length} 个文件`);

    // 2. 提取 DEX 文件列表
    const dexFiles = entries
      .filter((e) => e.name.match(/^classes\d*\.dex$/))
      .map((e) => e.name)
      .sort((a, b) => {
        const na = a === 'classes.dex' ? 1 : parseInt(a.match(/\d+/)?.[0] ?? '0', 10);
        const nb = b === 'classes.dex' ? 1 : parseInt(b.match(/\d+/)?.[0] ?? '0', 10);
        return na - nb;
      });

    if (dexFiles.length === 0) {
      throw new BadRequestException('NO_DEX_FILES', {
        cause: 'APK contains no classes.dex',
      });
    }
    onProgress?.('dex', 30, `DEX 文件: ${dexFiles.join(', ')}`);

    // 3. 提取原生 ABI
    const nativeAbis = this.detectAbis(entries);
    onProgress?.('abi', 40, `原生架构: ${nativeAbis.join(', ') || '无'}`);

    // 4. 用 apktool 反编译获取 Manifest 信息
    onProgress?.('manifest', 50, '正在解析 AndroidManifest.xml...');
    const manifestInfo = await this.extractManifestInfo(apkPath);
    onProgress?.('manifest', 60, `包名: ${manifestInfo.packageName}`);

    // 5. 检测已加固
    const hardenerResult = this.detectHardener(entries);
    onProgress?.(
      'hardener',
      70,
      hardenerResult.name ? `检测到 ${hardenerResult.name} 加固` : '未检测到已知加固',
    );

    // 6. 提取 SDK 版本(从 aapt dump badging)
    onProgress?.('sdk', 80, '正在提取 SDK 版本...');
    const sdkInfo = await this.extractSdkInfo(apkPath);

    // 7. 构建不可用功能列表
    const unavailableFeatures = this.buildUnavailableList(
      nativeAbis,
      hardenerResult.name,
      sdkInfo.minSdk,
    );

    // 8. 推荐配置
    const recommendedConfig = this.buildRecommendedConfig(
      hardenerResult.name,
      nativeAbis,
      unavailableFeatures,
    );

    this.logger.log(
      `APK 分析完成: pkg=${manifestInfo.packageName}, ` +
        `dex=${dexFiles.length}, abi=[${nativeAbis.join(',')}], ` +
        `hardened=${hardenerResult.name ?? 'none'}`,
    );

    return {
      packageName: manifestInfo.packageName,
      originalApplicationName: manifestInfo.applicationName,
      dexFiles,
      isMultidex: dexFiles.length > 1,
      nativeAbis,
      alreadyHardened: hardenerResult.name !== null,
      detectedHardener: hardenerResult.name,
      minSdkVersion: sdkInfo.minSdk,
      targetSdkVersion: sdkInfo.targetSdk,
      apkSize: stat.size,
      recommendedConfig,
      unavailableFeatures,
    };
  }

  private parseZipEntries(output: string): Array<{ name: string; size: number }> {
    const lines = output.split('\n').slice(3, -2);
    return lines
      .map((line) => {
        const parts = line.trim().split(/\s+/);
        if (parts.length < 4) return null;
        const size = parseInt(parts[0], 10);
        const name = parts.slice(3).join(' ');
        return name ? { name, size: isNaN(size) ? 0 : size } : null;
      })
      .filter((e): e is { name: string; size: number } => e !== null);
  }

  private detectAbis(entries: Array<{ name: string }>): string[] {
    const abiSet = new Set<string>();
    for (const e of entries) {
      const m = e.name.match(/^lib\/([^/]+)\//);
      if (m) abiSet.add(m[1]);
    }
    return [...abiSet].sort();
  }

  private detectHardener(entries: Array<{ name: string }>): { name: string | null } {
    const entryNames = entries.map((e) => e.name);
    for (const sig of this.HARDENER_SIGNATURES) {
      for (const pattern of sig.patterns) {
        if (entryNames.some((n) => pattern.test(n))) {
          return { name: sig.name };
        }
      }
    }
    return { name: null };
  }

  /** 尝试多个 aapt 路径执行命令 */
  private async execAapt(args: string[]): Promise<string> {
    let lastErr: Error | null = null;
    for (const aaptPath of AAPT_PATHS) {
      try {
        const { stdout } = await execFileAsync(aaptPath, args, {
          timeout: 30_000,
          maxBuffer: 5 * 1024 * 1024,
        });
        return stdout;
      } catch (e) {
        lastErr = e as Error;
      }
    }
    throw lastErr ?? new Error('aapt not found');
  }

  private async extractManifestInfo(apkPath: string): Promise<{
    packageName: string;
    applicationName: string | null;
  }> {
    const workDir = path.join(path.dirname(apkPath), `_analyze_${Date.now()}`);
    await fs.mkdir(workDir, { recursive: true });

    try {
      // 用 aapt dump badging 获取包名(快速,不需要反编译)
      const stdout = await this.execAapt(['dump', 'badging', apkPath]);

      const pkgMatch = stdout.match(/package:\s*name='([^']+)'/);
      // 用 aapt dump xmltree 获取 Application 类名
      const xmlOut = await this.execAapt(['dump', 'xmltree', apkPath, 'AndroidManifest.xml']);

      // 找 application 标签的 name 属性
      const appNameMatch2 = xmlOut.match(
        /E:\s*application[\s\S]*?A:\s*android:name\(0x01010003\)=\(type\s*0x3\)"([^"]+)"/,
      );

      return {
        packageName: pkgMatch?.[1] ?? 'unknown',
        applicationName: appNameMatch2?.[1] ?? null,
      };
    } catch {
      // aapt 不可用时降级:用 unzip 读 manifest 二进制(无法解析,返回 unknown)
      this.logger.warn('aapt 不可用,manifest 信息降级');
      return { packageName: 'unknown', applicationName: null };
    } finally {
      await fs.rm(workDir, { recursive: true, force: true }).catch(() => {});
    }
  }

  private async extractSdkInfo(apkPath: string): Promise<{
    minSdk: number;
    targetSdk: number;
  }> {
    try {
      const stdout = await this.execAapt(['dump', 'badging', apkPath]);
      const minMatch = stdout.match(/sdkVersion:'(\d+)'/);
      const targetMatch = stdout.match(/targetSdkVersion:'(\d+)'/);
      return {
        minSdk: minMatch ? parseInt(minMatch[1], 10) : 21,
        targetSdk: targetMatch ? parseInt(targetMatch[1], 10) : 35,
      };
    } catch {
      return { minSdk: 21, targetSdk: 35 };
    }
  }

  private buildUnavailableList(
    abis: string[],
    hardener: string | null,
    minSdk: number,
  ): Array<{ feature: string; reason: string }> {
    const list: Array<{ feature: string; reason: string }> = [];

    if (hardener) {
      list.push({
        feature: 'all',
        reason: `APK 已被 ${hardener} 加固,请先去除加固再使用玄甲/天衍`,
      });
    }

    if (!abis.includes('arm64-v8a')) {
      list.push({
        feature: 'x0_soEncrypt',
        reason: 'APK 不含 arm64-v8a 架构,SO 加密仅支持 arm64',
      });
      list.push({
        feature: 't1_customLinker',
        reason: '自实现 Linker 仅支持 arm64-v8a',
      });
    }

    if (minSdk < 24) {
      list.push({
        feature: 'x4_antiDynamic',
        reason: '反动态五层需要 minSdk >= 24 (Android 7.0)',
      });
    }

    return list;
  }

  private buildRecommendedConfig(
    _hardener: string | null,
    _abis: string[],
    unavailable: Array<{ feature: string }>,
  ): HardeningConfig {
    const unavailableSet = new Set(unavailable.map((u) => u.feature));
    const { xuanjia, tianyan } = applyPreset('standard');

    // 移除不可用功能
    if (unavailableSet.has('all')) {
      // 已加固,全部禁用
      for (const key of Object.keys(xuanjia) as Array<keyof typeof xuanjia>) {
        xuanjia[key] = false;
      }
      for (const key of Object.keys(tianyan) as Array<keyof typeof tianyan>) {
        tianyan[key] = false;
      }
    } else {
      for (const key of Object.keys(xuanjia) as Array<keyof typeof xuanjia>) {
        if (unavailableSet.has(key)) xuanjia[key] = false;
      }
      for (const key of Object.keys(tianyan) as Array<keyof typeof tianyan>) {
        if (unavailableSet.has(key)) tianyan[key] = false;
      }
    }

    return {
      productLine: 'xuanjia',
      preset: 'standard',
      xuanjia,
      tianyan,
    };
  }
}
