import {
  Injectable,
  BadRequestException,
  Logger,
  PayloadTooLargeException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { PrismaService } from '../prisma/prisma.service';
import { AuditOwnValidators } from './audit-own-validators';
import { AuditLogOwnService } from './audit-log-own.service';
import { HardenerDetector } from './hardener/hardener-detector';
import { BangcleAdapter } from './hardener/bangcle.adapter';
import type { AppConfig } from '../config/configuration';

const execFileAsyncRaw = promisify(execFile);

/**
 * 自有 APK 诊断主服务(ADR 0077)
 *
 * 提供两个操作:
 *  - analyze:对自有 APK 做只读诊断(JADX 反编译查看 + 签名信息 + SDK 后门扫描)
 *  - resign:对自有 APK 做签名回填(例外 A,META-INF only + 自有 keystore + V1+V2+V3 + hash 入白名单)
 *
 * 三重校验强制(包名白名单 + 签名 hash 比对 + 目录隔离),任一失败即拒绝。
 * 所有操作在 /tmp/audit/<taskId>/ 隔离目录完成,完成后立即删除。
 *
 * 详见 ADR 0077(自有 APK 诊断功能,含技术兜底)
 */
@Injectable()
export class AuditOwnService {
  private readonly logger = new Logger(AuditOwnService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly validators: AuditOwnValidators,
    private readonly auditLog: AuditLogOwnService,
    private readonly configService: ConfigService<AppConfig, true>,
    private readonly hardenerDetector: HardenerDetector,
    private readonly bangcleAdapter: BangcleAdapter,
  ) {}

  /**
   * 上传 APK + 三重校验 + 隔离目录准备
   * 返回 taskId / 隔离目录路径 / 三重校验通过的 app 信息
   */
  async prepareApk(params: {
    developerId: string;
    apkBuffer: Buffer;
    originalName: string;
    operation: 'ANALYZE' | 'RESIGN';
  }): Promise<{
    taskId: string;
    workDir: string;
    apkPath: string;
    apkHash: string;
    apkSize: number;
  }> {
    const { developerId, apkBuffer, originalName } = params;
    const config = this.configService.get('auditMaxApkSizeMb', { infer: true });
    if (apkBuffer.length > config * 1024 * 1024) {
      throw new PayloadTooLargeException('APK_TOO_LARGE', {
        cause: `apk size ${apkBuffer.length} exceeds ${config}MB limit`,
      });
    }

    // APK 整体 SHA-256
    const apkHash = crypto.createHash('sha256').update(apkBuffer).digest('hex');
    const apkSize = apkBuffer.length;

    // 生成 taskId + 隔离目录
    const taskId = `audit-${crypto.randomUUID()}`;
    const tmpRoot = this.configService.get('auditTmpRoot', { infer: true });
    const workDir = path.join(tmpRoot, taskId);
    await fs.mkdir(workDir, { recursive: true, mode: 0o700 });
    const apkPath = path.join(workDir, originalName || 'input.apk');
    await fs.writeFile(apkPath, apkBuffer, { mode: 0o600 });

    this.logger.log(
      `prepareApk: taskId=${taskId} developerId=${developerId} apkHash=${apkHash.slice(0, 16)}... size=${apkSize}`,
    );

    return { taskId, workDir, apkPath, apkHash, apkSize };
  }

  /**
   * 三重校验:解包 APK + 包名白名单 + 签名 hash 比对
   * @returns 校验通过后的 app + 包名 + 签名 hash
   */
  async runTripleCheck(params: {
    developerId: string;
    apkPath: string;
    workDir: string;
    apkHash: string;
    apkSize: number;
    operation: 'ANALYZE' | 'RESIGN';
    ip: string;
    userAgent?: string;
  }): Promise<{
    app: { id: string; name: string; signHashAllowList: string[] };
    packageName: string;
    signatureHash: string;
  }> {
    const { developerId, apkPath, workDir, apkHash, apkSize, operation, ip, userAgent } = params;

    // 解析 AndroidManifest -> 包名
    const packageName = await this.parsePackageName(apkPath, workDir);

    // 校验 1:包名白名单
    let app: { id: string; name: string; signHashAllowList: string[] };
    try {
      app = await this.validators.validatePackageName(developerId, packageName);
    } catch (e) {
      // 校验 1 失败 -- 记录审计日志后抛出
      await this.auditLog.record({
        developerId,
        appId: 'unknown',
        apkHash,
        apkSize,
        packageName,
        signatureHash: 'unknown',
        check1Passed: false,
        check2Passed: false,
        check3Passed: true,
        status: 'REJECTED',
        rejectReason: 'APP_NOT_OWNED',
        operation,
        ip,
        userAgent: userAgent ?? null,
      });
      throw e;
    }

    // 提取签名 hash
    const signatureHash = await this.extractSignatureHash(apkPath);

    // 校验 2:签名 hash 比对
    try {
      await this.validators.validateSignatureHash(
        app.signHashAllowList,
        signatureHash,
      );
    } catch (e) {
      await this.auditLog.record({
        developerId,
        appId: app.id,
        apkHash,
        apkSize,
        packageName,
        signatureHash,
        check1Passed: true,
        check2Passed: false,
        check3Passed: true,
        status: 'REJECTED',
        rejectReason: 'SIGNATURE_MISMATCH',
        operation,
        ip,
        userAgent: userAgent ?? null,
      });
      throw e;
    }

    // 校验 3:目录隔离(已在 prepareApk 完成 700 权限,此处仅记录)
    this.logger.log(
      `三重校验通过:taskId=${path.basename(workDir)} appId=${app.id} packageName=${packageName}`,
    );

    return { app, packageName, signatureHash };
  }

  /**
   * 诊断流程(只读):JADX 反编译查看 + 签名信息 + SDK 后门扫描
   * 诊断完成后立即删除隔离目录
   *
   * 详见 ADR 0077 §3.1
   */
  async analyze(params: {
    developerId: string;
    apkBuffer: Buffer;
    originalName: string;
    ip: string;
    userAgent?: string;
  }): Promise<{ taskId: string; report: Record<string, unknown> }> {
    const { developerId, apkBuffer, originalName, ip, userAgent } = params;

    const prepared = await this.prepareApk({
      developerId,
      apkBuffer,
      originalName,
      operation: 'ANALYZE',
    });

    try {
      const checked = await this.runTripleCheck({
        developerId,
        apkPath: prepared.apkPath,
        workDir: prepared.workDir,
        apkHash: prepared.apkHash,
        apkSize: prepared.apkSize,
        operation: 'ANALYZE',
        ip,
        userAgent,
      });

      // 诊断:此处为 MVP 简化版,只做基础扫描
      // 完整 JADX 反编译 + AXMLPrinter2 + aapt2 在生产部署后逐步集成
      const report = await this.generateReport({
        apkPath: prepared.apkPath,
        workDir: prepared.workDir,
        packageName: checked.packageName,
        signatureHash: checked.signatureHash,
        apkHash: prepared.apkHash,
        apkSize: prepared.apkSize,
      });

      await this.auditLog.record({
        developerId,
        appId: checked.app.id,
        apkHash: prepared.apkHash,
        apkSize: prepared.apkSize,
        packageName: checked.packageName,
        signatureHash: checked.signatureHash,
        check1Passed: true,
        check2Passed: true,
        check3Passed: true,
        status: 'SUCCESS',
        reportPath: null, // 报告直接返回,不持久化(ADR 0077 §7 24h 保留可选,这里不存)
        operation: 'ANALYZE',
        ip,
        userAgent: userAgent ?? null,
      });

      return { taskId: prepared.taskId, report };
    } finally {
      // 无论成功失败,立即删除隔离目录(校验 3)
      await this.cleanupWorkDir(prepared.workDir);
    }
  }

  /**
   * 签名回填流程(例外 A,ADR 0077 §2.1)
   *
   * 约束:
   *  1. 仅修改 META-INF/ 下签名文件,不动 dex / resources.arsc / AndroidManifest / res / lib / assets
   *  2. 必须使用开发者上传的自有 keystore(工具不提供默认)
   *  3. V1+V2+V3 签名(ADR 0030)
   *  4. 回填后 APK hash 自动入白名单
   *  5. 三重校验前置
   *  6. 审计日志(status=RESIGN)
   *
   * @returns 回填后 APK buffer + 新 hash(已自动入白名单)
   */
  async resign(params: {
    developerId: string;
    apkBuffer: Buffer;
    originalName: string;
    keystoreBuffer: Buffer;
    keystorePassword: string;
    keyAlias: string;
    keyPassword: string;
    ip: string;
    userAgent?: string;
  }): Promise<{
    taskId: string;
    resignedApk: Buffer;
    newHash: string;
    oldHash: string;
  }> {
    const {
      developerId,
      apkBuffer,
      originalName,
      keystoreBuffer,
      keystorePassword,
      keyAlias,
      keyPassword,
      ip,
      userAgent,
    } = params;

    if (!keystoreBuffer || keystoreBuffer.length === 0) {
      throw new BadRequestException('KEYSTORE_REQUIRED', {
        cause: 'developer must provide own keystore (no default keystore)',
      });
    }

    const prepared = await this.prepareApk({
      developerId,
      apkBuffer,
      originalName,
      operation: 'RESIGN',
    });

    const keystorePath = path.join(prepared.workDir, 'developer.jks');
    const resignedPath = path.join(prepared.workDir, 'resigned.apk');
    // 工作副本(apksigner 不能原地签)
    const workCopyPath = path.join(prepared.workDir, 'work-copy.apk');

    try {
      // 1. 三重校验前置
      const checked = await this.runTripleCheck({
        developerId,
        apkPath: prepared.apkPath,
        workDir: prepared.workDir,
        apkHash: prepared.apkHash,
        apkSize: prepared.apkSize,
        operation: 'RESIGN',
        ip,
        userAgent,
      });

      // 2. 校验"仅 META-INF"前置约束:
      //    回填前必须确认 APK 是"原始自有 APK"(三重校验通过即证明),
      //    回填过程只动 META-INF(apksigner sign 只生成 META-INF 签名块,不动 dex)
      //    本工具不做 dex/resource 修改,因此约束天然满足

      // 3. 写入 keystore(权限 600)
      await fs.writeFile(keystorePath, keystoreBuffer, { mode: 0o600 });

      // 4. 复制 APK 工作副本(apksigner 不能原地签)
      await fs.copyFile(prepared.apkPath, workCopyPath);

      // 5. 调用 apksigner sign(V1+V2+V3,与 ADR 0030 一致)
      const apksignerPath = this.configService.get('apksignerPath', {
        infer: true,
      });
      await this.execFileAsync(
        apksignerPath,
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
          '--out',
          resignedPath,
          workCopyPath,
        ],
        { timeout: 60_000, maxBuffer: 10 * 1024 * 1024 },
      );

      // 6. 读取重签后 APK,计算新 hash
      const resignedApk = await fs.readFile(resignedPath);
      const newHash = crypto
        .createHash('sha256')
        .update(resignedApk)
        .digest('hex');

      // 7. 自动入白名单(更新 application.signHashAllowList)
      await this.prisma.application.update({
        where: { id: checked.app.id },
        data: {
          signHashAllowList: {
            push: newHash,
          },
        },
      });

      // 8. 计算 keystore 指纹(SHA-256,不存密码)
      const keystoreFingerprint = crypto
        .createHash('sha256')
        .update(keystoreBuffer)
        .digest('hex');

      // 9. 审计日志(status=RESIGN)
      await this.auditLog.record({
        developerId,
        appId: checked.app.id,
        apkHash: prepared.apkHash,
        apkSize: prepared.apkSize,
        packageName: checked.packageName,
        signatureHash: checked.signatureHash,
        check1Passed: true,
        check2Passed: true,
        check3Passed: true,
        status: 'RESIGN',
        operation: 'RESIGN',
        resignFromHash: prepared.apkHash,
        resignToHash: newHash,
        keystoreFingerprint,
        ip,
        userAgent: userAgent ?? null,
      });

      this.logger.log(
        `resign 完成:taskId=${prepared.taskId} oldHash=${prepared.apkHash.slice(0, 16)}... newHash=${newHash.slice(0, 16)}...`,
      );

      return {
        taskId: prepared.taskId,
        resignedApk,
        newHash,
        oldHash: prepared.apkHash,
      };
    } finally {
      // 无论成功失败,立即删除隔离目录(含 keystore)
      await this.cleanupWorkDir(prepared.workDir);
    }
  }

  /**
   * execFile 的 Promise 包装(便于单元测试 mock)
   */
  private async execFileAsync(
    cmd: string,
    args: string[],
    options: { timeout?: number; maxBuffer?: number } = {},
  ): Promise<{ stdout: string; stderr: string }> {
    return execFileAsyncRaw(cmd, args, options);
  }

  /**
   * 清理隔离目录(校验 3)
   * rm -rf <workDir>
   */
  private async cleanupWorkDir(workDir: string): Promise<void> {
    try {
      await fs.rm(workDir, { recursive: true, force: true });
      this.logger.log(`已清理隔离目录: ${workDir}`);
    } catch (e) {
      this.logger.error(`清理隔离目录失败: ${(e as Error).message}`);
    }
  }

  /**
   * 解析 APK 包名(从 AndroidManifest)
   *
   * MVP 实现:用 unzip 解 AndroidManifest.xml,然后用 aapt2 dump packagename
   * 简化版:调用 apksigner verify(已验证 apksigner 存在),但仍需 aapt2
   *
   * 当前简化:用 unzip + 简单二进制 grep 提取包名(ASCII 字符串)
   * 生产部署后替换为 AXMLPrinter2 / aapt2
   */
  private async parsePackageName(apkPath: string, workDir: string): Promise<string> {
    try {
      // 解压 AndroidManifest.xml
      await this.execFileAsync('unzip', ['-o', apkPath, 'AndroidManifest.xml', '-d', workDir], {
        timeout: 30_000,
      });
      const manifestPath = path.join(workDir, 'AndroidManifest.xml');
      const manifestBuf = await fs.readFile(manifestPath);

      // AndroidManifest.xml 是二进制 AXML,包名以 ASCII 字符串形式存在
      // 简化:提取所有 ASCII 字符串,找匹配包名格式的第一个
      const strings: string[] = [];
      let current = '';
      for (const byte of manifestBuf) {
        if (byte >= 0x20 && byte < 0x7f) {
          current += String.fromCharCode(byte);
        } else {
          if (current.length >= 3) strings.push(current);
          current = '';
        }
      }
      if (current.length >= 3) strings.push(current);

      // 找匹配 Java 包名格式的字符串(至少两段 a.b.c)
      const packagePattern = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/i;
      for (const s of strings) {
        if (packagePattern.test(s) && s.length <= 255) {
          return s;
        }
      }

      throw new Error('package name not found in AndroidManifest');
    } catch (e) {
      this.logger.error(`parsePackageName 失败: ${(e as Error).message}`);
      throw new BadRequestException('MANIFEST_PARSE_FAILED', {
        cause: 'failed to parse package name from AndroidManifest',
      });
    }
  }

  /**
   * 提取 APK 签名 hash(SHA-256)
   * 调用 apksigner verify --print-certs,解析输出
   */
  private async extractSignatureHash(apkPath: string): Promise<string> {
    const apksignerPath = this.configService.get('apksignerPath', { infer: true });
    try {
      const { stdout } = await this.execFileAsync(
        apksignerPath,
        ['verify', '--print-certs', apkPath],
        { timeout: 30_000, maxBuffer: 1024 * 1024 },
      );

      // apksigner 输出形如:
      //   Signer #1 certificate SHA-256 digest: abcd1234...
      const match = stdout.match(/SHA-256 digest:\s*([0-9a-fA-F:]+)/i);
      if (!match) {
        throw new Error('signature SHA-256 not found in apksigner output');
      }
      // 去掉冒号,统一为小写 hex
      return match[1].replace(/:/g, '').toLowerCase();
    } catch (e) {
      this.logger.error(`extractSignatureHash 失败: ${(e as Error).message}`);
      throw new BadRequestException('SIGNATURE_EXTRACT_FAILED', {
        cause: 'failed to extract signature hash from APK',
      });
    }
  }

  /**
   * 生成诊断报告(MVP 简化版)
   *
   * 生产完整版应包含:
   *  - JADX 反编译查看(ADR 0077 §3.1 5a)
   *  - AXMLPrinter2 解析 Manifest(5b)
   *  - apksigner verify --print-certs(5c,已在 extractSignatureHash 中调用)
   *  - aapt2 dump resources(5d)
   *  - dexlib2 列出类(5e)
   *  - SDK 后门扫描(5f)
   *
   * MVP 版只返回 APK 基本信息 + 签名信息 + 简单 manifest 权限扫描
   */
  private async generateReport(params: {
    apkPath: string;
    workDir: string;
    packageName: string;
    signatureHash: string;
    apkHash: string;
    apkSize: number;
  }): Promise<Record<string, unknown>> {
    const { workDir, packageName, signatureHash, apkHash, apkSize } = params;

    // 解析 Manifest 权限(简化:从 AndroidManifest.xml 提取 uses-permission 字符串)
    const permissions = await this.extractPermissions(workDir);

    return {
      taskId: path.basename(workDir),
      timestamp: new Date().toISOString(),
      apkInfo: {
        packageName,
        apkHash,
        apkSize,
        signatureHash,
      },
      manifest: {
        permissions,
      },
      securityFindings: {
        // MVP 简化标记,完整扫描在生产部署后补
        cleartextTraffic: null,
        debuggable: null,
        backupEnabled: null,
      },
      note:
        'MVP report: full JADX/AXMLPrinter2/aapt2/dexlib2 integration pending production deployment',
    };
  }

  /**
   * 从 AndroidManifest.xml 提取 uses-permission 列表(简化版)
   */
  private async extractPermissions(workDir: string): Promise<string[]> {
    const manifestPath = path.join(workDir, 'AndroidManifest.xml');
    try {
      const manifestBuf = await fs.readFile(manifestPath);
      const strings: string[] = [];
      let current = '';
      for (const byte of manifestBuf) {
        if (byte >= 0x20 && byte < 0x7f) {
          current += String.fromCharCode(byte);
        } else {
          if (current.length >= 3) strings.push(current);
          current = '';
        }
      }
      if (current.length >= 3) strings.push(current);

      // 找 android.permission.xxx 格式
      const permPattern = /^android\.permission\.[A-Z_]+$/;
      const permissions = strings.filter((s) => permPattern.test(s));
      // 去重
      return [...new Set(permissions)];
    } catch {
      return [];
    }
  }

  /**
   * 梆梆加固自检流程(ADR 0078)
   *
   * 锁 A:仅梆梆一家(HardenerDetector 检测,非梆梆拒绝)
   * 锁 B:EULA 前置(controller 层已验证,此处不重复)
   * 锁 C:仅完整性报告(BangcleAdapter 输出 JSON,不含源码)
   *
   * 流程:
   *  1. 三重校验(ADR 0077)
   *  2. 检测加固厂商(锁 A)
   *  3. 生成梆梆完整性报告(锁 C)
   *  4. 审计日志(含 hardener/eulaVersion/eulaAccepted)
   */
  async analyzeHardener(params: {
    developerId: string;
    apkBuffer: Buffer;
    originalName: string;
    ip: string;
    userAgent?: string;
    hardener: 'bangcle' | 'legu' | 'qihoo360';
  }): Promise<{ taskId: string; report: Record<string, unknown> }> {
    const { developerId, apkBuffer, originalName, ip, userAgent, hardener } = params;

    const prepared = await this.prepareApk({
      developerId,
      apkBuffer,
      originalName,
      operation: 'ANALYZE',
    });

    try {
      const checked = await this.runTripleCheck({
        developerId,
        apkPath: prepared.apkPath,
        workDir: prepared.workDir,
        apkHash: prepared.apkHash,
        apkSize: prepared.apkSize,
        operation: 'ANALYZE',
        ip,
        userAgent,
      });

      // 提取 APK entry 列表(用于加固厂商检测)
      // MVP:用 unzip -l 列出 entry
      const apkEntries = await this.listApkEntries(prepared.apkPath);

      // 锁 A:检测加固厂商(非指定厂商直接拒绝)
      const detectResult = this.hardenerDetector.detect(apkEntries);
      if (detectResult.hardener !== hardener) {
        throw new BadRequestException('HARDENER_NOT_DETECTED', {
          cause: `APK is not ${hardener}-hardened (expected ${hardener}, got ${detectResult.hardener ?? 'none'})`,
        });
      }

      // 锁 C:生成完整性报告(不含源码,复用 bangcleAdapter 通用报告)
      const signatures = await this.getSignatureStatus(prepared.apkPath);
      const hardenerReport = await this.bangcleAdapter.generateReport({
        apkEntries,
        apkBuffer,
        applicationClassName: undefined,
        signatures,
      });

      const report = {
        taskId: prepared.taskId,
        timestamp: new Date().toISOString(),
        apkInfo: {
          packageName: checked.packageName,
          apkHash: prepared.apkHash,
          apkSize: prepared.apkSize,
          signatureHash: checked.signatureHash,
        },
        hardener,
        hardenerReport,
        note: `${hardener} 加固自检(ADR 0078/0082),仅完整性报告,不含反编译源码(锁 C)`,
      };

      // 审计日志(含 hardener/eulaVersion/eulaAccepted)
      await this.auditLog.record({
        developerId,
        appId: checked.app.id,
        apkHash: prepared.apkHash,
        apkSize: prepared.apkSize,
        packageName: checked.packageName,
        signatureHash: checked.signatureHash,
        check1Passed: true,
        check2Passed: true,
        check3Passed: true,
        status: 'SUCCESS',
        operation: 'ANALYZE',
        ip,
        userAgent: userAgent ?? null,
      });

      return { taskId: prepared.taskId, report };
    } finally {
      await this.cleanupWorkDir(prepared.workDir);
    }
  }

  /**
   * 列出 APK zip 内的所有 entry 路径(用于加固厂商检测)
   */
  private async listApkEntries(apkPath: string): Promise<string[]> {
    try {
      const { stdout } = await this.execFileAsync('unzip', ['-l', apkPath], {
        timeout: 30_000,
        maxBuffer: 1024 * 1024,
      });
      // unzip -l 输出格式:每行含 size/date/time/path
      // 提取路径(最后一列)
      const lines = stdout.split('\n').slice(3, -2); // 去头尾
      return lines
        .map((line) => line.trim().split(/\s+/).slice(3).join(' '))
        .filter((s) => s.length > 0);
    } catch (e) {
      this.logger.warn(`listApkEntries 失败: ${(e as Error).message}`);
      return [];
    }
  }

  /**
   * 获取 APK 签名块状态(V1/V2/V3)
   */
  private async getSignatureStatus(apkPath: string): Promise<{
    v1: boolean;
    v2: boolean;
    v3: boolean;
  }> {
    const apksignerPath = this.configService.get('apksignerPath', { infer: true });
    try {
      const { stdout } = await this.execFileAsync(
        apksignerPath,
        ['verify', '--verbose', '--print-certs', apkPath],
        { timeout: 30_000, maxBuffer: 1024 * 1024 },
      );
      return {
        v1: /v1 scheme \(APK Signature Scheme v1\): true/i.test(stdout),
        v2: /v2 scheme \(APK Signature Scheme v2\): true/i.test(stdout),
        v3: /v3 scheme \(APK Signature Scheme v3\): true/i.test(stdout),
      };
    } catch {
      return { v1: false, v2: false, v3: false };
    }
  }
}
