import { Injectable, Logger, BadRequestException, NotFoundException } from '@nestjs/common';
import * as fs from 'fs/promises';
import { existsSync, statSync } from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { execFile } from 'child_process';
import { promisify } from 'util';
// adm-zip 仅在 preflight 只读检查中使用,此处不再引入
import { ApkAnalyzerService } from './apk-analyzer.service';
import { SoInjector } from '../packer/so-injector';
import { PreflightService } from './preflight.service';
import { RedisService } from '../redis/redis.service';
import type { HardeningConfig, ApkAnalysisResult } from './hardening-config.dto';
import { applyPreset } from './hardening-config.dto';

const execFileAsync = promisify(execFile);

/** 执行命令并捕获 stderr */
async function execWithStderr(
  cmd: string,
  args: string[],
  opts: { timeout?: number; cwd?: string; maxBuffer?: number } = {},
): Promise<{ stdout: string; stderr: string }> {
  try {
    const result = await execFileAsync(cmd, args, {
      timeout: opts.timeout ?? 120_000,
      cwd: opts.cwd,
      maxBuffer: opts.maxBuffer ?? 10 * 1024 * 1024,
    });
    return { stdout: result.stdout, stderr: result.stderr ?? '' };
  } catch (e) {
    const err = e as Error & { stderr?: string; stdout?: string };
    throw new BadRequestException(`${cmd} failed: ${err.message}`, {
      cause: err.stderr || err.stdout || err.message,
    });
  }
}

/** 动态超时: 120s + fileSize_MB × 3s, cap 600s */
function computeTimeout(fileSizeBytes: number): number {
  const mb = fileSizeBytes / (1024 * 1024);
  return Math.min(600_000, 120_000 + Math.ceil(mb) * 3_000);
}

/** Redis key 前缀 */
const TASK_KEY = 'hardening:task:';
const USER_TASKS_KEY = 'hardening:user_tasks:';
const TASK_TTL = 86400; // 24 小时

/** 加固任务状态(Redis 持久化) */
export interface HardeningTask {
  id: string;
  developerId: string;
  status: 'queued' | 'analyzing' | 'hardening' | 'signing' | 'completed' | 'failed' | 'cancelled';
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
    private readonly soInjector: SoInjector,
    private readonly preflight: PreflightService,
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

  /** 取消任务(Bug E) */
  async cancelTask(taskId: string): Promise<void> {
    const task = await this.getTask(taskId);
    if (!task) throw new NotFoundException('任务不存在');
    task.status = 'cancelled' as HardeningTask['status'];
    task.message = '已取消';
    task.step = 'cancelled';
    await this.saveTask(task);
    this.logger.log(`任务已取消: taskId=${taskId}`);
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

    // 动态超时
    const totalTimeout = computeTimeout(params.analysis.apkSize);
    const controller = new AbortController();
    const timeoutHandle = setTimeout(() => controller.abort(), totalTimeout);

    try {
      const workApk = path.join(workDir, 'work.apk');
      await fs.copyFile(params.apkPath, workApk);
      const mergedConfig = this.mergeConfig(params.config);
      const { xuanjia, tianyan } = mergedConfig;

      // Step 0: 预检 (5%)
      await this.updateProgress(task, 'preflight', 5, '正在验证 Keystore 和 APK...');
      await this.preflight.runAll(
        params.apkPath, params.keystorePath, params.keystorePassword, params.keyAlias,
      );
      if (controller.signal.aborted) throw new Error('加固超时');

      // Step 1: strip 签名 (10%) — 用 zip -d 删 META-INF
      await this.updateProgress(task, 'strip', 10, '删除旧签名...');
      await this.stripSignature(workApk);

      // Step 2: 注入 config (15%)
      await this.updateProgress(task, 'config', 15, '注入 defender-config.json...');
      const defenderConfig = this.buildDefenderConfig(xuanjia, tianyan, params.config.killPolicy);
      const configJson = JSON.stringify(defenderConfig, null, 2);
      await this.injectToZip(workApk, 'assets/defender-config.json', Buffer.from(configJson));

      // Step 3: 注入 DEX (25%)
      await this.updateProgress(task, 'dex', 25, '注入 SDK DEX 模块...');
      const sdkDexPath = this.findSdkDex();
      if (sdkDexPath) {
        const dexContent = await fs.readFile(sdkDexPath);
        const { dexFiles } = params.analysis;
        const maxNum = dexFiles.reduce((max, f) => {
          const m = f.match(/classes(\d*)\.dex/);
          return Math.max(max, m ? (m[1] ? parseInt(m[1], 10) : 1) : 0);
        }, 0);
        await this.injectToZip(workApk, `classes${maxNum + 1}.dex`, dexContent);
      }

      // Step 4: 注入 SO arm64 (35%)
      let randomSoName = '';
      if (xuanjia.x0_soEncrypt || xuanjia.x4_antiDynamic) {
        const soPath = this.findSdkSo('arm64-v8a');
        if (soPath) {
          randomSoName = this.soInjector.pickRandomSoName();
          await this.updateProgress(task, 'so_arm64', 35, `注入 lib/arm64-v8a/${randomSoName}...`);
          const soData = await fs.readFile(soPath);
          await this.injectToZip(workApk, `lib/arm64-v8a/${randomSoName}`, soData);

          // Step 5: 注入 SO armv7 (40%)
          const soPathV7 = this.findSdkSo('armeabi-v7a');
          if (soPathV7 && params.analysis.nativeAbis.includes('armeabi-v7a')) {
            await this.updateProgress(task, 'so_armv7', 40, `注入 lib/armeabi-v7a/${randomSoName}...`);
            const soDataV7 = await fs.readFile(soPathV7);
            await this.injectToZip(workApk, `lib/armeabi-v7a/${randomSoName}`, soDataV7);
          }
        }
      }

      // Step 6: apktool 解包 (50%) — --no-src 跳过 DEX 反编译(省内存+省时间)
      await this.updateProgress(task, 'apktool_d', 50, '解包 APK(修改 Manifest,跳过 DEX 反编译)...');
      const decodedDir = path.join(workDir, 'decoded');
      await execWithStderr('apktool', ['d', '-f', '--no-src', '-o', decodedDir, workApk], { timeout: 180_000, maxBuffer: 20 * 1024 * 1024 });

      // Step 7: 修改 Manifest (60%) — 合并所有修改为一次
      await this.updateProgress(task, 'manifest', 60, '注入 meta-data + provider + permission...');
      const manifestPath = path.join(decodedDir, 'AndroidManifest.xml');
      let manifest = await fs.readFile(manifestPath, 'utf-8');

      // meta-data: so 随机名
      if (randomSoName && !manifest.includes('xcj.defender.lib')) {
        const metaTag = `<meta-data android:name="xcj.defender.lib" android:value="${randomSoName}" />`;
        manifest = manifest.replace(/(<application[^>]*>)/, `$1\n        ${metaTag}`);
      }
      // provider
      if (!manifest.includes('DefenderInitProvider')) {
        const providerTag = `<provider android:name="com.xcj.defender.DefenderInitProvider" android:authorities="${params.analysis.packageName}.xcj.defender.init" android:exported="false" android:initOrder="100" />`;
        manifest = manifest.replace(/(<application[^>]*>)/, `$1\n        ${providerTag}`);
      }
      // permission
      if (!manifest.includes('android.permission.INTERNET')) {
        manifest = manifest.replace(
          /(<manifest[^>]*>)/,
          `$1\n    <uses-permission android:name="android.permission.INTERNET" />`,
        );
      }
      await fs.writeFile(manifestPath, manifest, 'utf-8');

      // Step 8: apktool 重建 (70%)
      await this.updateProgress(task, 'apktool_b', 70, '重建 APK...');
      await execWithStderr('apktool', ['b', '-o', workApk, decodedDir], { timeout: 180_000, maxBuffer: 20 * 1024 * 1024 });
      // 清理 decoded 目录
      await fs.rm(decodedDir, { recursive: true, force: true }).catch(() => {});

      // Step 9: zipalign (80%)
      await this.updateProgress(task, 'zipalign', 80, '对齐 APK(-p 4)...');
      const alignedApk = workApk + '-aligned';
      await execWithStderr('zipalign', ['-p', '-f', '4', workApk, alignedApk], { timeout: 60_000 });
      await fs.rename(alignedApk, workApk);

      // Step 10: apksigner (90%)
      await this.updateProgress(task, 'sign', 90, '签名(V1+V2+V3)...');
      task.status = 'signing';
      await this.saveTask(task);
      await this.resignApk(workApk, params.keystorePath, params.keystorePassword, params.keyAlias, params.keyPassword);

      // Step 11: 完成 (100%)
      const enabledCount = Object.values(xuanjia).filter(Boolean).length +
        Object.values(tianyan).filter(Boolean).length;
      task.status = 'completed';
      task.progress = 100;
      task.message = '加固完成';
      task.step = 'done';
      task.detail = `已启用 ${enabledCount} 个模块`;
      task.outputPath = workApk;
      await this.saveTask(task);
      this.logger.log(`加固完成: taskId=${task.id}`);
    } catch (e) {
      task.status = 'failed';
      const err = e as Error & { cause?: string };
      task.error = err.cause ? `${err.message} | ${err.cause}` : err.message;
      task.message = `加固失败: ${task.error}`;
      task.step = 'error';
      await this.saveTask(task);
      this.logger.error(`加固失败: taskId=${task.id}`, err.stack);
    } finally {
      clearTimeout(timeoutHandle);
      // 清理 workDir(成功时保留 workApk 供下载)
      if (task.status !== 'completed') {
        await fs.rm(workDir, { recursive: true, force: true }).catch(() => {});
      }
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
    const kp = killPolicy ?? { strongEvidence: 'kill', weakScoreThreshold: 70, delayMinMs: 0, delayMaxMs: 1000 };
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
      onViolationKill: { delayMinMs: kp.delayMinMs, delayMaxMs: kp.delayMaxMs, method: 'sigabrt', showToast: true, toastMessage: '检测到安全风险' },
      report: { enabled: false, throttleMs: 300000 },
      integrityCrcTable: [],
      integrityFileList: [],
    };
  }

  private findSdkDex(): string | null {
    const candidates = [
      path.resolve(process.cwd(), 'sdk-artifacts', 'classes-xcj.dex'),
      path.resolve(process.cwd(), 'sdk-artifacts', 'classes.dex'),
      path.resolve(process.cwd(), '..', 'sdk-android', 'defender-sdk', 'build', 'intermediates', 'aar_main_jar', 'release', 'classes.jar'),
    ];
    for (const p of candidates) { try { statSync(p); return p; } catch { /* not found */ } }
    this.logger.warn('SDK DEX 未找到,跳过 DEX 注入');
    return null;
  }

  private findSdkSo(abi: string): string | null {
    const candidates = [
      path.resolve(process.cwd(), 'sdk-artifacts', 'lib', abi, 'libxcj_defender.so'),
      path.resolve(process.cwd(), '..', 'sdk-android', 'defender-sdk', 'build', 'intermediates', 'stripped_native_libs', 'release', 'stripReleaseDebugSymbols', 'out', 'lib', abi, 'libxcj_defender.so'),
    ];
    for (const p of candidates) { try { statSync(p); return p; } catch { /* not found */ } }
    this.logger.warn(`SDK .so 未找到(${abi}),跳过 SO 注入`);
    return null;
  }

  /** 用 zip 命令行注入文件到 APK(保留原有条目对齐,不重写整个 zip) */
  private async injectToZip(apkPath: string, entryName: string, data: Buffer): Promise<void> {
    const tmpDir = path.join(path.dirname(apkPath), `_inject_${Date.now()}`);
    const targetPath = path.join(tmpDir, entryName);
    await fs.mkdir(path.dirname(targetPath), { recursive: true });
    await fs.writeFile(targetPath, data);
    try {
      // .so 文件用 -0 (store 不压缩,保持页面对齐)
      const isNative = entryName.endsWith('.so');
      const flags = isNative ? ['-0', '-r'] : ['-r'];
      await execWithStderr('zip', [...flags, apkPath, entryName], {
        timeout: 30_000,
        cwd: tmpDir,
      });
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
    }
  }

  /** 用 zip -d 删除 META-INF 签名(不重写整个 zip) */
  private async stripSignature(apkPath: string): Promise<void> {
    try {
      await execWithStderr('zip', ['-d', apkPath, 'META-INF/*'], { timeout: 10_000 });
    } catch {
      // META-INF 不存在时 zip -d 会返回非零,忽略
    }
  }

  private async resignApk(
    apkPath: string, keystorePath: string, keystorePassword: string,
    keyAlias: string, keyPassword: string,
  ): Promise<void> {
    const apksigner = this.findApksigner();
    if (!apksigner) throw new BadRequestException('APKSIGNER_NOT_FOUND');
    const unsigned = apkPath + '-unsigned';
    await fs.rename(apkPath, unsigned);
    try {
      await execWithStderr(apksigner, [
        'sign', '--ks', keystorePath, '--ks-pass', `pass:${keystorePassword}`,
        '--ks-key-alias', keyAlias, '--key-pass', `pass:${keyPassword}`,
        '--v1-signing-enabled', 'true', '--v2-signing-enabled', 'true', '--v3-signing-enabled', 'true',
        '--in', unsigned, '--out', apkPath,
      ], { timeout: 60_000 });
    } catch (e) {
      throw new BadRequestException('RESIGN_FAILED', { cause: (e as Error).message });
    } finally {
      await fs.unlink(unsigned).catch(() => {});
    }
  }

  private findApksigner(): string | null {
    const candidates = ['apksigner', '/opt/android-sdk/build-tools/34.0.0/apksigner'];
    for (const c of candidates) { try { if (existsSync(c)) return c; } catch { /* ignore */ } }
    return 'apksigner';
  }
}
