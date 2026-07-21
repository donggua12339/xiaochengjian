import { Injectable, Logger, PayloadTooLargeException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';
import { PrismaService } from '../prisma/prisma.service';
import { PackerValidators } from './packer-validators';
import { DexInjector } from './dex-injector';
import { PackerLogService } from './packer-log.service';
import type { AppConfig } from '../config/configuration';

/**
 * Packer 主服务(ADR 0081)
 *
 * 封装流程(七锁校验):
 *  1. 上传 APK + Keystore + 凭证
 *  2. 锁 1:对象锁定(三重校验)
 *  3. 锁 2:内容锁定(注入内容为固定 classes-xcj.dex)
 *  4. 锁 3:入口锁定(Manifest 修改范围)
 *  5. dex 注入 + Manifest 修改
 *  6. 锁 4:签名锁定(自备 Keystore V1+V2+V3 重签)
 *  7. 锁 5:权限锁定(JWT 开发者自身)
 *  8. 锁 6:数据锁定(SDK 配置仅 OAID + 包信息)
 *  9. 锁 7:客户端签名自检(配置预期 hash)
 *  10. 返回封装后 APK + 审计日志
 *
 * 所有操作在 /tmp/packer/<taskId>/ 隔离目录完成,完成后立即删除。
 */
@Injectable()
export class PackerService {
  private readonly logger = new Logger(PackerService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly validators: PackerValidators,
    private readonly dexInjector: DexInjector,
    private readonly packerLog: PackerLogService,
    private readonly configService: ConfigService<AppConfig, true>,
  ) {}

  /**
   * 封装流程
   */
  async pack(params: {
    developerId: string;
    apkBuffer: Buffer;
    originalName: string;
    keystoreBuffer: Buffer;
    keystorePassword: string;
    keyAlias: string;
    keyPassword: string;
    sdkConfig: Record<string, unknown>;
    xcjAuthSdkDex: Buffer; // xcj-auth-sdk 编译产物(classes-xcj.dex)
    ip: string;
    userAgent?: string;
  }): Promise<{
    taskId: string;
    packedApk: Buffer;
    packedApkHash: string;
    injectedDexHash: string;
    keystoreFingerprint: string;
  }> {
    const {
      developerId,
      apkBuffer,
      originalName,
      keystoreBuffer,
      keystorePassword,
      keyAlias,
      keyPassword,
      sdkConfig,
      xcjAuthSdkDex,
      ip,
      userAgent,
    } = params;

    // APK 大小限制
    const maxSize = this.configService.get('auditMaxApkSizeMb', { infer: true });
    if (apkBuffer.length > maxSize * 1024 * 1024) {
      throw new PayloadTooLargeException('APK_TOO_LARGE', {
        cause: `apk size ${apkBuffer.length} exceeds ${maxSize}MB`,
      });
    }

    // 锁 4:签名锁定(keystore 必须自备)
    this.validators.validateSignLock(keystoreBuffer);

    // 锁 6:数据锁定(SDK 配置仅 OAID + 包信息)
    this.validators.validateDataLock(sdkConfig);

    // 准备隔离目录
    const taskId = `packer-${crypto.randomUUID()}`;
    const tmpRoot = this.configService.get('auditTmpRoot', { infer: true });
    const workDir = path.join(tmpRoot.replace('/audit', '/packer'), taskId);
    await fs.mkdir(workDir, { recursive: true, mode: 0o700 });

    const apkPath = path.join(workDir, originalName || 'input.apk');
    const keystorePath = path.join(workDir, 'developer.jks');
    const packedPath = path.join(workDir, 'packed.apk');

    try {
      await fs.writeFile(apkPath, apkBuffer, { mode: 0o600 });
      await fs.writeFile(keystorePath, keystoreBuffer, { mode: 0o600 });

      // 计算 APK hash + 提取签名 hash + 解析包名
      const apkHash = crypto.createHash('sha256').update(apkBuffer).digest('hex');
      const signatureHash = await this.extractSignatureHash(apkPath);
      const packageName = await this.parsePackageName(apkPath, workDir);

      // 锁 1:对象锁定(三重校验)
      const app = await this.validators.validateObjectLock(
        developerId,
        packageName,
        signatureHash,
      );

      // 锁 5:权限锁定(JWT 开发者 = 应用所有者)
      this.validators.validatePermissionLock(developerId, app.id);

      // 锁 2:内容锁定(注入 dex hash 白名单)
      const injectedDexHash = crypto
        .createHash('sha256')
        .update(xcjAuthSdkDex)
        .digest('hex');
      this.validators.validateContentLock(injectedDexHash);

      // 锁 7:客户端签名自检(配置预期 hash)
      const clientCheckConfig = this.validators.configureClientSignatureCheck(
        signatureHash,
      );

      // 复制工作副本
      await fs.copyFile(apkPath, packedPath);

      // dex 注入(锁 2 + 锁 3)
      const multidexInfo = await this.dexInjector.detectMultidex(packedPath);
      await this.dexInjector.injectDex(
        packedPath,
        xcjAuthSdkDex,
        multidexInfo.nextDexName,
      );

      // Manifest 修改(锁 3)
      const manifestChanges = await this.dexInjector.patchManifest({
        apkPath: packedPath,
        workDir,
        originalApplicationName: null, // MVP:假设无自定义 Application
        xcjConfig: {
          appId: app.id,
          serverUrl: String(sdkConfig.serverUrl ?? ''),
          expectedSignatureHash: clientCheckConfig.expectedSignatureHash,
        },
      });

      // 锁 3:入口锁定校验
      this.validators.validateEntryLock(manifestChanges);

      // 重打包
      await this.dexInjector.repackApk(packedPath);

      // 锁 4:签名锁定(V1+V2+V3 重签)
      await this.resignApk({
        apkPath: packedPath,
        keystorePath,
        keystorePassword,
        keyAlias,
        keyPassword,
      });

      // 读取封装后 APK + 计算 hash
      const packedApk = await fs.readFile(packedPath);
      const packedApkHash = crypto
        .createHash('sha256')
        .update(packedApk)
        .digest('hex');

      // 自动入白名单(封装后 APK hash)
      await this.prisma.application.update({
        where: { id: app.id },
        data: {
          signHashAllowList: { push: packedApkHash },
        },
      });

      // keystore 指纹(不存密码)
      const keystoreFingerprint = crypto
        .createHash('sha256')
        .update(keystoreBuffer)
        .digest('hex');

      // 审计日志(七锁全过)
      await this.packerLog.record({
        developerId,
        appId: app.id,
        apkHash,
        apkSize: apkBuffer.length,
        packageName,
        signatureHash,
        check1Passed: true,
        check2Passed: true,
        check3Passed: true,
        check4Passed: true,
        check5Passed: true,
        check6Passed: true,
        check7Passed: true,
        status: 'SUCCESS',
        dexInjected: true,
        multidexHandled: multidexInfo.isMultidex,
        injectedDexHash,
        resignedApkHash: packedApkHash,
        keystoreFingerprint,
        ip,
        userAgent: userAgent ?? null,
      });

      this.logger.log(
        `pack 完成:taskId=${taskId} oldHash=${apkHash.slice(0, 16)}... newHash=${packedApkHash.slice(0, 16)}...`,
      );

      return {
        taskId,
        packedApk,
        packedApkHash,
        injectedDexHash,
        keystoreFingerprint,
      };
    } finally {
      // 清理隔离目录
      await this.cleanupWorkDir(workDir);
    }
  }

  /**
   * 提取 APK 签名 hash
   */
  private async extractSignatureHash(apkPath: string): Promise<string> {
    const apksignerPath = this.configService.get('apksignerPath', { infer: true });
    try {
      const { execFile } = await import('child_process');
      const { promisify } = await import('util');
      const execFileAsync = promisify(execFile);
      const { stdout } = await execFileAsync(
        apksignerPath,
        ['verify', '--print-certs', apkPath],
        { timeout: 30_000, maxBuffer: 1024 * 1024 },
      );
      const match = stdout.match(/SHA-256 digest:\s*([0-9a-fA-F:]+)/i);
      if (!match) {
        throw new Error('signature SHA-256 not found');
      }
      return match[1].replace(/:/g, '').toLowerCase();
    } catch (e) {
      throw new Error(`extractSignatureHash failed: ${(e as Error).message}`);
    }
  }

  /**
   * 解析 APK 包名(从 AndroidManifest)
   */
  private async parsePackageName(apkPath: string, workDir: string): Promise<string> {
    try {
      const { execFile } = await import('child_process');
      const { promisify } = await import('util');
      const execFileAsync = promisify(execFile);
      await execFileAsync('unzip', ['-o', apkPath, 'AndroidManifest.xml', '-d', workDir], {
        timeout: 30_000,
      });
      const manifestPath = path.join(workDir, 'AndroidManifest.xml');
      const manifestBuf = await fs.readFile(manifestPath);

      // 从二进制 AXML 提取 ASCII 字符串,找包名格式
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

      const packagePattern = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/i;
      for (const s of strings) {
        if (packagePattern.test(s) && s.length <= 255) {
          return s;
        }
      }
      throw new Error('package name not found');
    } catch (e) {
      throw new Error(`parsePackageName failed: ${(e as Error).message}`);
    }
  }

  /**
   * V1+V2+V3 重签(锁 4)
   */
  private async resignApk(params: {
    apkPath: string;
    keystorePath: string;
    keystorePassword: string;
    keyAlias: string;
    keyPassword: string;
  }): Promise<void> {
    const { apkPath, keystorePath, keystorePassword, keyAlias, keyPassword } = params;
    const apksignerPath = this.configService.get('apksignerPath', { infer: true });
    const { execFile } = await import('child_process');
    const { promisify } = await import('util');
    const execFileAsync = promisify(execFile);

    try {
      await execFileAsync(
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
          apkPath,
        ],
        { timeout: 60_000, maxBuffer: 10 * 1024 * 1024 },
      );
      this.logger.log('V1+V2+V3 重签完成(锁 4)');
    } catch (e) {
      throw new Error(`resignApk failed: ${(e as Error).message}`);
    }
  }

  /**
   * 清理隔离目录
   */
  private async cleanupWorkDir(workDir: string): Promise<void> {
    try {
      await fs.rm(workDir, { recursive: true, force: true });
    } catch (e) {
      this.logger.error(`清理隔离目录失败: ${(e as Error).message}`);
    }
  }
}
