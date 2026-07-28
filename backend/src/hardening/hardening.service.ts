import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { ApkAnalyzerService } from './apk-analyzer.service';
import { DexInjector } from '../packer/dex-injector';
import { SoInjector } from '../packer/so-injector';
import type { HardeningConfig, ApkAnalysisResult } from './hardening-config.dto';
import { applyPreset } from './hardening-config.dto';

const execFileAsync = promisify(execFile);

/** 加固任务状态 */
export interface HardeningTask {
  id: string;
  status: 'analyzing' | 'hardening' | 'signing' | 'completed' | 'failed';
  progress: number;
  message: string;
  analysis?: ApkAnalysisResult;
  outputPath?: string;
  error?: string;
}

/**
 * 加固编排服务
 *
 * 流水线: 上传 APK → 分析 → 用户选择模块 → 注入 DEX/SO/config → 修改 Manifest → 重签 → 下载
 *
 * 合规约束(ADR 0081 + 0088 + 0097):
 *  - 可注入用户自有 APK(ADR 0097 扩展,用户声明自担风险)
 *  - 注入内容: SDK DEX + 30 池随机 .so + defender-config.json
 *  - smali 修改限于 ADR 0090 授权范围(const-string 替换 + 解密调用)
 *  - Manifest 修改仅限 Application 委托 + meta-data + provider
 *  - 重签必须使用开发者自备 Keystore(锁 4)
 *  - 用户所有权声明必须为 true,否则拒绝执行(ADR 0097)
 */
@Injectable()
export class HardeningService {
  private readonly logger = new Logger(HardeningService.name);
  private readonly tasks = new Map<string, HardeningTask>();

  constructor(
    private readonly analyzer: ApkAnalyzerService,
    private readonly dexInjector: DexInjector,
    private readonly soInjector: SoInjector,
  ) {}

  /**
   * Step 1: 分析 APK
   */
  async analyze(apkPath: string): Promise<HardeningTask> {
    const taskId = crypto.randomUUID();
    const task: HardeningTask = {
      id: taskId,
      status: 'analyzing',
      progress: 0,
      message: '正在分析 APK 结构...',
    };
    this.tasks.set(taskId, task);

    try {
      task.progress = 30;
      task.message = '解析 DEX 文件...';
      const analysis = await this.analyzer.analyze(apkPath);

      task.progress = 100;
      task.status = 'completed';
      task.message = '分析完成';
      task.analysis = analysis;

      this.logger.log(`分析完成: taskId=${taskId} pkg=${analysis.packageName}`);
      return task;
    } catch (e) {
      task.status = 'failed';
      task.error = (e as Error).message;
      task.message = `分析失败: ${task.error}`;
      throw e;
    }
  }

  /**
   * Step 2: 执行加固(注入 + 修改 Manifest + 重签)
   */
  async harden(params: {
    apkPath: string;
    keystorePath: string;
    keystorePassword: string;
    keyAlias: string;
    keyPassword: string;
    config: HardeningConfig;
    analysis: ApkAnalysisResult;
  }): Promise<HardeningTask> {
    const taskId = crypto.randomUUID();
    const task: HardeningTask = {
      id: taskId,
      status: 'hardening',
      progress: 0,
      message: '准备加固环境...',
    };
    this.tasks.set(taskId, task);

    const workDir = path.join(
      path.dirname(params.apkPath),
      `_harden_${taskId}`,
    );
    await fs.mkdir(workDir, { recursive: true });

    try {
      // 复制 APK 到工作目录
      const workApk = path.join(workDir, 'work.apk');
      await fs.copyFile(params.apkPath, workApk);

      // 合并预设和手动选择
      const mergedConfig = this.mergeConfig(params.config);
      const { xuanjia, tianyan } = mergedConfig;

      // === 生成 defender-config.json ===
      task.progress = 10;
      task.message = '生成加固配置...';

      const defenderConfig = this.buildDefenderConfig(
        xuanjia,
        tianyan,
        params.config.killPolicy,
      );
      const configJson = JSON.stringify(defenderConfig, null, 2);
      const configPath = path.join(workDir, 'defender-config.json');
      await fs.writeFile(configPath, configJson, 'utf-8');

      // === 注入 defender-config.json 到 assets/ ===
      task.progress = 20;
      task.message = '注入配置文件...';
      await this.injectAsset(workApk, 'assets/defender-config.json', Buffer.from(configJson));

      // === 注入 DEX(SDK 核心逻辑) ===
      task.progress = 30;
      task.message = '注入 SDK 模块...';

      const sdkDexPath = this.findSdkDex();
      if (sdkDexPath) {
        const dexContent = await fs.readFile(sdkDexPath);
        const { dexFiles } = params.analysis;
        const maxNum = dexFiles.reduce((max, f) => {
          const m = f.match(/classes(\d*)\.dex/);
          return Math.max(max, m ? (m[1] ? parseInt(m[1], 10) : 1) : 0);
        }, 0);
        const nextDexName = `classes${maxNum + 1}.dex`;
        await this.dexInjector.injectDex(workApk, dexContent, nextDexName);
        this.logger.log(`DEX 注入完成: ${nextDexName}`);
      }

      // === 注入 native .so(如果 X0 或 X4 启用) ===
      task.progress = 50;
      task.message = '注入 native 库...';

      if (xuanjia.x0_soEncrypt || xuanjia.x4_antiDynamic) {
        const soPath = this.findSdkSo('arm64-v8a');
        if (soPath) {
          const randomSoName = this.soInjector.pickRandomSoName();
          await this.injectNativeSo(workApk, soPath, randomSoName, 'arm64-v8a');

          // 如果有 armeabi-v7a 也注入
          const soPathV7 = this.findSdkSo('armeabi-v7a');
          if (soPathV7 && params.analysis.nativeAbis.includes('armeabi-v7a')) {
            await this.injectNativeSo(workApk, soPathV7, randomSoName, 'armeabi-v7a');
          }

          // 注入 .so 名到 meta-data(DefenderInitProvider 需要)
          await this.injectMetaSoName(workApk, workDir, randomSoName, params.analysis);
        }
      }

      // === 修改 AndroidManifest ===
      task.progress = 70;
      task.message = '修改 Manifest...';

      const originalAppName = params.analysis.originalApplicationName;
      if (originalAppName || xuanjia.x4_antiDynamic) {
        await this.patchManifestForHardening(
          workApk,
          workDir,
          originalAppName,
          params.analysis.packageName,
        );
      }

      // === 重签 ===
      task.progress = 85;
      task.status = 'signing';
      task.message = '重签名...';

      // 先移除旧签名
      await this.stripSignature(workApk);

      // 用 apksigner 重签
      await this.resignApk(
        workApk,
        params.keystorePath,
        params.keystorePassword,
        params.keyAlias,
        params.keyPassword,
      );

      // === 完成 ===
      task.progress = 100;
      task.status = 'completed';
      task.message = '加固完成';
      task.outputPath = workApk;

      this.logger.log(
        `加固完成: taskId=${taskId} pkg=${params.analysis.packageName} ` +
        `modules=[X0=${xuanjia.x0_soEncrypt},X4=${xuanjia.x4_antiDynamic},` +
        `X5=${xuanjia.x5_vpnProxy},X6=${xuanjia.x6_dualApp}]`,
      );

      return task;
    } catch (e) {
      task.status = 'failed';
      task.error = (e as Error).message;
      task.message = `加固失败: ${task.error}`;
      this.logger.error(`加固失败: taskId=${taskId}`, (e as Error).stack);
      throw e;
    }
  }

  /** 查询任务状态 */
  getTask(taskId: string): HardeningTask | undefined {
    return this.tasks.get(taskId);
  }

  // ========== 内部方法 ==========

  private mergeConfig(config: HardeningConfig) {
    const preset = config.preset ?? 'standard';
    const presetModules = applyPreset(preset);

    return {
      xuanjia: { ...presetModules.xuanjia, ...(config.xuanjia ?? {}) },
      tianyan: { ...presetModules.tianyan, ...(config.tianyan ?? {}) },
    };
  }

  private buildDefenderConfig(
    xuanjia: Record<string, boolean>,
    tianyan: Record<string, boolean>,
    killPolicy?: HardeningConfig['killPolicy'],
  ): Record<string, unknown> {
    const kp = killPolicy ?? {
      strongEvidence: 'kill',
      weakScoreThreshold: 70,
      delayMinMs: 0,
      delayMaxMs: 1000,
    };

    return {
      version: 2,
      signatureVerify: { enabled: true, onViolation: kp.strongEvidence },
      integrityCheck: { enabled: xuanjia.x0_soEncrypt, onViolation: kp.strongEvidence },
      antiDebug: { enabled: xuanjia.x4_antiDynamic, onViolation: kp.strongEvidence },
      antiFrida: { enabled: xuanjia.x4_antiDynamic, onViolation: kp.strongEvidence },
      antiDump: { enabled: xuanjia.x4_antiDynamic, onViolation: kp.strongEvidence },
      rootDetect: { enabled: xuanjia.x4_antiDynamic, onViolation: 'warn' },
      xposedDetect: { enabled: xuanjia.x4_antiDynamic, onViolation: kp.strongEvidence, killThreshold: 70 },
      emulatorDetect: { enabled: xuanjia.x6_dualApp, onViolation: 'warn' },
      vpnDetect: { enabled: xuanjia.x5_vpnProxy, onViolation: 'warn' },
      dualAppDetect: { enabled: xuanjia.x6_dualApp, onViolation: 'warn' },
      fartDetect: { enabled: xuanjia.x8_fart, onViolation: kp.strongEvidence },
      odexDetect: { enabled: xuanjia.x9_odex, onViolation: kp.strongEvidence },
      lifecycleGuard: { enabled: xuanjia.x3_lifecycle, onViolation: kp.strongEvidence },
      secureScreen: { enabled: false, excludeActivities: [] },
      customLinker: { enabled: tianyan.t1_customLinker },
      vmpProtect: { enabled: tianyan.t2_vmp },
      segmentStrings: { enabled: tianyan.t3_segment },
      onViolationKill: {
        delayMinMs: kp.delayMinMs,
        delayMaxMs: kp.delayMaxMs,
        method: 'sigabrt',
        showToast: true,
        toastMessage: '检测到安全风险',
      },
      report: { enabled: false, throttleMs: 300000 },
      integrityCrcTable: [],
      integrityFileList: [],
    };
  }

  private findSdkDex(): string | null {
    // SDK DEX 预编译产物路径(由 CI 构建生成)
    const candidates = [
      path.resolve(process.cwd(), 'sdk-artifacts', 'classes-xcj.dex'),
      path.resolve(process.cwd(), '..', 'sdk-android', 'defender-sdk', 'build', 'intermediates', 'aar_main_jar', 'release', 'classes.jar'),
    ];
    for (const p of candidates) {
      try {
        // sync check via statSync
        const { statSync } = require('fs');
        statSync(p);
        return p;
      } catch {
        // not found
      }
    }
    this.logger.warn('SDK DEX 未找到,跳过 DEX 注入');
    return null;
  }

  private findSdkSo(abi: string): string | null {
    const candidates = [
      path.resolve(process.cwd(), 'sdk-artifacts', 'lib', abi, 'libxcj_defender.so'),
      path.resolve(process.cwd(), '..', 'sdk-android', 'defender-sdk', 'build', 'intermediates', 'stripped_native_libs', 'release', 'stripReleaseDebugSymbols', 'out', 'lib', abi, 'libxcj_defender.so'),
    ];
    for (const p of candidates) {
      try {
        const { statSync } = require('fs');
        statSync(p);
        return p;
      } catch {
        // not found
      }
    }
    this.logger.warn(`SDK .so 未找到(${abi}),跳过 SO 注入`);
    return null;
  }

  private async injectAsset(
    apkPath: string,
    assetPath: string,
    content: Buffer,
  ): Promise<void> {
    // 写临时文件,用 zip 命令注入
    const tmpFile = path.join(path.dirname(apkPath), path.basename(assetPath));
    await fs.writeFile(tmpFile, content);
    try {
      await execFileAsync('zip', ['-j0', apkPath, tmpFile], { timeout: 30_000 });
    } catch (e) {
      throw new BadRequestException('ASSET_INJECT_FAILED', {
        cause: `Failed to inject asset: ${(e as Error).message}`,
      });
    } finally {
      await fs.unlink(tmpFile).catch(() => {});
    }
  }

  private async injectNativeSo(
    apkPath: string,
    soPath: string,
    randomName: string,
    abi: string,
  ): Promise<void> {
    const tmpDir = path.join(path.dirname(apkPath), `_so_${abi}`);
    await fs.mkdir(tmpDir, { recursive: true });
    const tmpSo = path.join(tmpDir, randomName);
    await fs.copyFile(soPath, tmpSo);
    try {
      // 注入到 lib/<abi>/ 目录(保持目录结构)
      const libDir = path.join(tmpDir, 'lib', abi);
      await fs.mkdir(libDir, { recursive: true });
      await fs.copyFile(soPath, path.join(libDir, randomName));
      await execFileAsync('zip', ['-0', apkPath, `lib/${abi}/${randomName}`], {
        timeout: 30_000,
        cwd: tmpDir,
      });
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
    }
  }

  private async injectMetaSoName(
    apkPath: string,
    workDir: string,
    randomSoName: string,
    _analysis: ApkAnalysisResult,
  ): Promise<void> {
    // 通过 apktool 修改 Manifest 添加 meta-data
    const decodedDir = path.join(workDir, 'decoded_meta');
    try {
      await execFileAsync('apktool', ['d', '-f', '-o', decodedDir, apkPath], {
        timeout: 120_000,
        maxBuffer: 10 * 1024 * 1024,
      });

      const manifestPath = path.join(decodedDir, 'AndroidManifest.xml');
      let manifest = await fs.readFile(manifestPath, 'utf-8');

      // 在 <application> 标签内插入 meta-data
      const metaTag = `<meta-data android:name="xcj.defender.lib" android:value="${randomSoName}" />`;
      if (!manifest.includes('xcj.defender.lib')) {
        manifest = manifest.replace(
          /(<application[^>]*>)/,
          `$1\n        ${metaTag}`,
        );
        await fs.writeFile(manifestPath, manifest, 'utf-8');
      }

      // 重新打包
      await execFileAsync('apktool', ['b', '-o', apkPath, decodedDir], {
        timeout: 120_000,
        maxBuffer: 10 * 1024 * 1024,
      });
    } catch (e) {
      this.logger.warn(`Manifest meta-data 注入失败(降级): ${(e as Error).message}`);
    } finally {
      await fs.rm(decodedDir, { recursive: true, force: true }).catch(() => {});
    }
  }

  private async patchManifestForHardening(
    apkPath: string,
    workDir: string,
    _originalAppName: string | null,
    packageName: string,
  ): Promise<void> {
    const decodedDir = path.join(workDir, 'decoded_manifest');
    try {
      await execFileAsync('apktool', ['d', '-f', '-o', decodedDir, apkPath], {
        timeout: 120_000,
        maxBuffer: 10 * 1024 * 1024,
      });

      const manifestPath = path.join(decodedDir, 'AndroidManifest.xml');
      let manifest = await fs.readFile(manifestPath, 'utf-8');

      const insertItems: string[] = [];

      // 添加 INTERNET 权限(如果不存在)
      if (!manifest.includes('android.permission.INTERNET')) {
        insertItems.push('<uses-permission android:name="android.permission.INTERNET" />');
      }

      // 添加 DefenderInitProvider(如果 X4 启用)
      if (!manifest.includes('DefenderInitProvider')) {
        insertItems.push(
          `<provider android:name="com.xcj.defender.DefenderInitProvider" ` +
          `android:authorities="${packageName}.xcj.defender.init" ` +
          `android:exported="false" android:initOrder="100" />`,
        );
      }

      if (insertItems.length > 0) {
        // 插入到 <manifest> 标签后
        const permissionStr = insertItems.filter((i) => i.includes('uses-permission')).join('\n    ');
        const providerStr = insertItems.filter((i) => i.includes('provider')).join('\n        ');

        if (permissionStr) {
          manifest = manifest.replace(
            /(<manifest[^>]*>)/,
            `$1\n    ${permissionStr}`,
          );
        }
        if (providerStr) {
          manifest = manifest.replace(
            /(<application[^>]*>)/,
            `$1\n        ${providerStr}`,
          );
        }

        await fs.writeFile(manifestPath, manifest, 'utf-8');
      }

      await execFileAsync('apktool', ['b', '-o', apkPath, decodedDir], {
        timeout: 120_000,
        maxBuffer: 10 * 1024 * 1024,
      });
    } catch (e) {
      this.logger.warn(`Manifest 修改失败(降级): ${(e as Error).message}`);
    } finally {
      await fs.rm(decodedDir, { recursive: true, force: true }).catch(() => {});
    }
  }

  private async stripSignature(apkPath: string): Promise<void> {
    try {
      await execFileAsync('zip', ['-d', apkPath, 'META-INF/*'], {
        timeout: 10_000,
      });
    } catch {
      // META-INF 可能不存在,忽略
    }
  }

  private async resignApk(
    apkPath: string,
    keystorePath: string,
    keystorePassword: string,
    keyAlias: string,
    keyPassword: string,
  ): Promise<void> {
    const apksigner = this.findApksigner();
    if (!apksigner) {
      throw new BadRequestException('APKSIGNER_NOT_FOUND', {
        cause: 'apksigner not found in PATH or ANDROID_HOME',
      });
    }

    const unsigned = apkPath + '-unsigned';
    await fs.rename(apkPath, unsigned);

    try {
      await execFileAsync(apksigner, [
        'sign',
        '--ks', keystorePath,
        '--ks-pass', `pass:${keystorePassword}`,
        '--ks-key-alias', keyAlias,
        '--key-pass', `pass:${keyPassword}`,
        '--v1-signing-enabled', 'true',
        '--v2-signing-enabled', 'true',
        '--v3-signing-enabled', 'true',
        '--in', unsigned,
        '--out', apkPath,
      ], { timeout: 60_000 });
    } catch (e) {
      throw new BadRequestException('RESIGN_FAILED', {
        cause: `apksigner failed: ${(e as Error).message}`,
      });
    } finally {
      await fs.unlink(unsigned).catch(() => {});
    }
  }

  private findApksigner(): string | null {
    const candidates = [
      'apksigner',
      path.join(
        process.env.ANDROID_HOME ?? '',
        'build-tools',
        '35.0.0',
        'apksigner',
      ),
      path.join(
        process.env.ANDROID_HOME ?? '',
        'build-tools',
        '34.0.0',
        'apksigner',
      ),
    ];
    for (const c of candidates) {
      try {
        const { existsSync } = require('fs');
        if (existsSync(c)) return c;
      } catch {
        // ignore
      }
    }
    // 尝试 PATH 中的 apksigner
    return 'apksigner';
  }
}
