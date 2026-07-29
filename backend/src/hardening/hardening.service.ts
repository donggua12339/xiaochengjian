import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import * as fs from 'fs/promises';
import { existsSync, statSync } from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { ApkAnalyzerService } from './apk-analyzer.service';
import { DexInjector } from '../packer/dex-injector';
import { SoInjector } from '../packer/so-injector';
import { RedisService } from '../redis/redis.service';
import type { HardeningConfig, ApkAnalysisResult } from './hardening-config.dto';
import { applyPreset } from './hardening-config.dto';

const execFileAsync = promisify(execFile);

/** Redis key 前缀 */
const TASK_KEY = 'hardening:task:';
const USER_TASKS_KEY = 'hardening:user_tasks:';
const TASK_TTL = 86400; // 24 小时

/** 加固任务状态(Redis 持久化) */
export interface HardeningTask {
  id: string;
  developerId: string;
  status: 'queued' | 'analyzing' | 'hardening' | 'signing' | 'completed' | 'failed';
  progress: number;
  message: string;
  step: string;
  detail: string;
  analysis?: ApkAnalysisResult;
  outputPath?: string;
  apkFileName?: string;
  error?: string;
  createdAt: string;
  updatedAt: string;
}

/**
 * 加固编排服务
 *
 * 流水线: 上传 APK → 异步分析 → 用户选择模块 → 注入 DEX/SO/config → 修改 Manifest → 重签 → 下载
 *
 * 任务状态持久化到 Redis(TTL 24h),刷新页面不丢失。
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

  constructor(
    private readonly analyzer: ApkAnalyzerService,
    private readonly dexInjector: DexInjector,
    private readonly soInjector: SoInjector,
    private readonly redis: RedisService,
  ) {}

  // ========== Redis 任务管理 ==========

  private taskKey(taskId: string): string {
    return `${TASK_KEY}${taskId}`;
  }

  private userTasksKey(developerId: string): string {
    return `${USER_TASKS_KEY}${developerId}`;
  }

  private async saveTask(task: HardeningTask): Promise<void> {
    task.updatedAt = new Date().toISOString();
    await this.redis.set(this.taskKey(task.id), JSON.stringify(task), TASK_TTL);
  }

  async getTask(taskId: string): Promise<HardeningTask | null> {
    const raw = await this.redis.get(this.taskKey(taskId));
    return raw ? JSON.parse(raw) : null;
  }

  async getUserTasks(developerId: string): Promise<HardeningTask[]> {
    const raw = await this.redis.get(this.userTasksKey(developerId));
    if (!raw) return [];
    const taskIds: string[] = JSON.parse(raw);
    const tasks: HardeningTask[] = [];
    for (const id of taskIds) {
      const t = await this.getTask(id);
      if (t) tasks.push(t);
    }
    return tasks.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  private async addUserTask(developerId: string, taskId: string): Promise<void> {
    const raw = await this.redis.get(this.userTasksKey(developerId));
    const taskIds: string[] = raw ? JSON.parse(raw) : [];
    taskIds.unshift(taskId);
    // 最多保留 50 条
    if (taskIds.length > 50) taskIds.length = 50;
    await this.redis.set(this.userTasksKey(developerId), JSON.stringify(taskIds), TASK_TTL);
  }

  private async updateProgress(
    task: HardeningTask,
    step: string,
    progress: number,
    message: string,
    detail?: string,
  ): Promise<void> {
    task.step = step;
    task.progress = progress;
    task.message = message;
    if (detail) task.detail = detail;
    await this.saveTask(task);
  }

  // ========== 异步分析 ==========

  /**
   * 创建分析任务(立即返回 taskId,后台异步执行)
   */
  async startAnalysis(
    apkPath: string,
    developerId: string,
    apkFileName: string,
  ): Promise<HardeningTask> {
    const taskId = crypto.randomUUID();
    const now = new Date().toISOString();
    const task: HardeningTask = {
      id: taskId,
      developerId,
      status: 'analyzing',
      progress: 0,
      message: '排队中...',
      step: 'queued',
      detail: '',
      apkFileName,
      createdAt: now,
      updatedAt: now,
    };

    await this.saveTask(task);
    await this.addUserTask(developerId, taskId);

    // 后台异步执行分析(不 await)
    this.runAnalysis(task, apkPath).catch(async (e) => {
      this.logger.error(`分析任务 ${taskId} 异常: ${(e as Error).message}`);
      // 兜底: 如果 runAnalysis 内部 catch 的 saveTask 也失败,此处再试一次
      try {
        task.status = 'failed';
        task.error = (e as Error).message;
        task.message = `分析异常: ${task.error}`;
        task.step = 'error';
        await this.saveTask(task);
      } catch {
        this.logger.error(`分析任务 ${taskId} 状态更新也失败(Redis 不可用?)`);
      }
    });

    return task;
  }

  private async runAnalysis(task: HardeningTask, apkPath: string): Promise<void> {
    try {
      await this.updateProgress(task, 'unzip', 5, '开始分析 APK...');

      const analysis = await this.analyzer.analyze(apkPath, async (step, progress, detail) => {
        task.status = 'analyzing';
        await this.updateProgress(task, step, progress, this.stepLabel(step), detail);
      });

      task.status = 'completed';
      task.progress = 100;
      task.message = '分析完成';
      task.step = 'done';
      task.detail = `包名: ${analysis.packageName}, DEX: ${analysis.dexFiles.length} 个, ABI: ${analysis.nativeAbis.join(',')}`;
      task.analysis = analysis;
      await this.saveTask(task);

      this.logger.log(`分析完成: taskId=${task.id} pkg=${analysis.packageName}`);
    } catch (e) {
      task.status = 'failed';
      task.error = (e as Error).message;
      task.message = `分析失败: ${task.error}`;
      task.step = 'error';
      await this.saveTask(task);
      this.logger.error(`分析失败: taskId=${task.id}`, (e as Error).stack);
    }
  }

  private stepLabel(step: string): string {
    const labels: Record<string, string> = {
      queued: '排队中...',
      unzip: '解压 APK 文件列表',
      dex: '解析 DEX 文件',
      abi: '检测原生架构',
      manifest: '解析 AndroidManifest.xml',
      hardener: '检测已有加固',
      sdk: '提取 SDK 版本信息',
      done: '分析完成',
      error: '分析失败',
    };
    return labels[step] ?? step;
  }

  // ========== 加固执行 ==========

  async harden(params: {
    apkPath: string;
    keystorePath: string;
    keystorePassword: string;
    keyAlias: string;
    keyPassword: string;
    config: HardeningConfig;
    analysis: ApkAnalysisResult;
    developerId: string;
  }): Promise<HardeningTask> {
    const taskId = crypto.randomUUID();
    const now = new Date().toISOString();
    const task: HardeningTask = {
      id: taskId,
      developerId: params.developerId,
      status: 'hardening',
      progress: 0,
      message: '准备加固环境...',
      step: 'init',
      detail: '',
      createdAt: now,
      updatedAt: now,
    };
    await this.saveTask(task);
    await this.addUserTask(params.developerId, taskId);

    // 后台异步执行加固
    this.runHarden(task, params).catch(async (e) => {
      this.logger.error(`加固任务 ${taskId} 异常: ${(e as Error).message}`);
      try {
        task.status = 'failed';
        task.error = (e as Error).message;
        task.message = `加固异常: ${task.error}`;
        task.step = 'error';
        await this.saveTask(task);
      } catch {
        this.logger.error(`加固任务 ${taskId} 状态更新也失败(Redis 不可用?)`);
      }
    });

    return task;
  }

  private async runHarden(
    task: HardeningTask,
    params: {
      apkPath: string;
      keystorePath: string;
      keystorePassword: string;
      keyAlias: string;
      keyPassword: string;
      config: HardeningConfig;
      analysis: ApkAnalysisResult;
    },
  ): Promise<void> {
    const workDir = path.join(path.dirname(params.apkPath), `_harden_${task.id}`);
    await fs.mkdir(workDir, { recursive: true });

    try {
      const workApk = path.join(workDir, 'work.apk');
      await fs.copyFile(params.apkPath, workApk);

      const mergedConfig = this.mergeConfig(params.config);
      const { xuanjia, tianyan } = mergedConfig;

      await this.updateProgress(task, 'config', 10, '生成加固配置...');

      const defenderConfig = this.buildDefenderConfig(xuanjia, tianyan, params.config.killPolicy);
      const configJson = JSON.stringify(defenderConfig, null, 2);
      const configPath = path.join(workDir, 'defender-config.json');
      await fs.writeFile(configPath, configJson, 'utf-8');

      await this.updateProgress(task, 'asset', 20, '注入配置文件到 assets/...');
      await this.injectAsset(workApk, 'assets/defender-config.json', Buffer.from(configJson));

      await this.updateProgress(task, 'dex', 30, '注入 SDK DEX 模块...');
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
      }

      await this.updateProgress(task, 'so', 50, '注入 native 库(30 池随机名)...');
      if (xuanjia.x0_soEncrypt || xuanjia.x4_antiDynamic) {
        const soPath = this.findSdkSo('arm64-v8a');
        if (soPath) {
          const randomSoName = this.soInjector.pickRandomSoName();
          await this.injectNativeSo(workApk, soPath, randomSoName, 'arm64-v8a');
          const soPathV7 = this.findSdkSo('armeabi-v7a');
          if (soPathV7 && params.analysis.nativeAbis.includes('armeabi-v7a')) {
            await this.injectNativeSo(workApk, soPathV7, randomSoName, 'armeabi-v7a');
          }
          await this.injectMetaSoName(workApk, workDir, randomSoName);
        }
      }

      await this.updateProgress(task, 'manifest', 70, '修改 AndroidManifest.xml...');
      await this.patchManifestForHardening(workApk, workDir, params.analysis.packageName);

      await this.updateProgress(task, 'sign', 85, '重签名(V1+V2+V3)...');
      task.status = 'signing';
      await this.saveTask(task);
      await this.stripSignature(workApk);
      await this.resignApk(
        workApk,
        params.keystorePath,
        params.keystorePassword,
        params.keyAlias,
        params.keyPassword,
      );

      task.status = 'completed';
      task.progress = 100;
      task.message = '加固完成';
      task.step = 'done';
      task.detail = `已启用 ${Object.values(xuanjia).filter(Boolean).length} 个模块`;
      task.outputPath = workApk;
      await this.saveTask(task);

      this.logger.log(`加固完成: taskId=${task.id}`);
    } catch (e) {
      task.status = 'failed';
      task.error = (e as Error).message;
      task.message = `加固失败: ${task.error}`;
      task.step = 'error';
      await this.saveTask(task);
      this.logger.error(`加固失败: taskId=${task.id}`, (e as Error).stack);
    }
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
      xposedDetect: {
        enabled: xuanjia.x4_antiDynamic,
        onViolation: kp.strongEvidence,
        killThreshold: 70,
      },
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
    const candidates = [
      path.resolve(process.cwd(), 'sdk-artifacts', 'classes-xcj.dex'),
      path.resolve(
        process.cwd(),
        '..',
        'sdk-android',
        'defender-sdk',
        'build',
        'intermediates',
        'aar_main_jar',
        'release',
        'classes.jar',
      ),
    ];
    for (const p of candidates) {
      try {
        statSync(p);
        return p;
      } catch {
        /* not found */
      }
    }
    this.logger.warn('SDK DEX 未找到,跳过 DEX 注入');
    return null;
  }

  private findSdkSo(abi: string): string | null {
    const candidates = [
      path.resolve(process.cwd(), 'sdk-artifacts', 'lib', abi, 'libxcj_defender.so'),
      path.resolve(
        process.cwd(),
        '..',
        'sdk-android',
        'defender-sdk',
        'build',
        'intermediates',
        'stripped_native_libs',
        'release',
        'stripReleaseDebugSymbols',
        'out',
        'lib',
        abi,
        'libxcj_defender.so',
      ),
    ];
    for (const p of candidates) {
      try {
        statSync(p);
        return p;
      } catch {
        /* not found */
      }
    }
    this.logger.warn(`SDK .so 未找到(${abi}),跳过 SO 注入`);
    return null;
  }

  private async injectAsset(apkPath: string, assetPath: string, content: Buffer): Promise<void> {
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
    const libDir = path.join(tmpDir, 'lib', abi);
    await fs.mkdir(libDir, { recursive: true });
    await fs.copyFile(soPath, path.join(libDir, randomName));
    try {
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
  ): Promise<void> {
    const decodedDir = path.join(workDir, 'decoded_meta');
    try {
      await execFileAsync('apktool', ['d', '-f', '-o', decodedDir, apkPath], {
        timeout: 120_000,
        maxBuffer: 10 * 1024 * 1024,
      });
      const manifestPath = path.join(decodedDir, 'AndroidManifest.xml');
      let manifest = await fs.readFile(manifestPath, 'utf-8');
      const metaTag = `<meta-data android:name="xcj.defender.lib" android:value="${randomSoName}" />`;
      if (!manifest.includes('xcj.defender.lib')) {
        manifest = manifest.replace(/(<application[^>]*>)/, `$1\n        ${metaTag}`);
        await fs.writeFile(manifestPath, manifest, 'utf-8');
      }
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
      if (!manifest.includes('android.permission.INTERNET')) {
        insertItems.push('<uses-permission android:name="android.permission.INTERNET" />');
      }
      if (!manifest.includes('DefenderInitProvider')) {
        insertItems.push(
          `<provider android:name="com.xcj.defender.DefenderInitProvider" android:authorities="${packageName}.xcj.defender.init" android:exported="false" android:initOrder="100" />`,
        );
      }
      if (insertItems.length > 0) {
        const permissionStr = insertItems
          .filter((i) => i.includes('uses-permission'))
          .join('\n    ');
        const providerStr = insertItems.filter((i) => i.includes('provider')).join('\n        ');
        if (permissionStr)
          manifest = manifest.replace(/(<manifest[^>]*>)/, `$1\n    ${permissionStr}`);
        if (providerStr)
          manifest = manifest.replace(/(<application[^>]*>)/, `$1\n        ${providerStr}`);
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
      await execFileAsync('zip', ['-d', apkPath, 'META-INF/*'], { timeout: 10_000 });
    } catch {
      /* ignore */
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
    if (!apksigner) throw new BadRequestException('APKSIGNER_NOT_FOUND');
    const unsigned = apkPath + '-unsigned';
    await fs.rename(apkPath, unsigned);
    try {
      await execFileAsync(
        apksigner,
        [
          'sign',
          '--ks',
          keystorePath,
          '--ks-pass',
          `pass:${keystorePassword}`,
          '--ks-key-alias',
          keyAlias,
          '--key-pass',
          `pass:${keyPassword}`,
          '--v1-signing-enabled',
          'true',
          '--v2-signing-enabled',
          'true',
          '--v3-signing-enabled',
          'true',
          '--in',
          unsigned,
          '--out',
          apkPath,
        ],
        { timeout: 60_000 },
      );
    } catch (e) {
      throw new BadRequestException('RESIGN_FAILED', {
        cause: `apksigner failed: ${(e as Error).message}`,
      });
    } finally {
      await fs.unlink(unsigned).catch(() => {});
    }
  }

  private findApksigner(): string | null {
    const candidates = ['apksigner', '/opt/android-sdk/build-tools/34.0.0/apksigner'];
    for (const c of candidates) {
      try {
        if (existsSync(c)) return c;
      } catch {
        /* ignore */
      }
    }
    return 'apksigner';
  }
}
