import { Injectable, Logger, PayloadTooLargeException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as yauzl from 'yauzl';
import { PrismaService } from '../prisma/prisma.service';
import { PackerValidators, XCJ_DEFENDER_SDK_AAR_WHITELIST } from './packer-validators';
import { DexInjector } from './dex-injector';
import { SoInjector } from './so-injector';
import { DefenderConfigGenerator, DefenderConfigInput } from './defender-config-generator';
import { PackerLogService } from './packer-log.service';
import type { AppConfig } from '../config/configuration';

/**
 * Packer 主服务(ADR 0081 + ADR 0088)
 *
 * 封装流程(七锁校验 + defender-sdk 注入):
 *  1. 上传 APK + Keystore + 凭证
 *  2. 锁 1:对象锁定(三重校验)
 *  3. 锁 2:内容锁定(注入内容为固定 classes-xcj.dex + classes-defender.dex)
 *  4. 锁 3:入口锁定(Manifest 修改范围)
 *  5. dex 注入(auth + defender)+ .so 注入(30 池随机名)+ Manifest 修改
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
    private readonly soInjector: SoInjector,
    private readonly defenderConfigGenerator: DefenderConfigGenerator,
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
    // ADR 0088:defender-sdk 注入(可选)
    defenderEnabled?: boolean;
    defenderConfig?: DefenderConfigInput;
    defenderAarPath?: string; // defender-sdk .aar 路径(含 .so,从配置读)
    defenderDex?: Buffer; // defender-sdk classes-defender.dex(预编译)
  }): Promise<{
    taskId: string;
    packedApk: Buffer;
    packedApkHash: string;
    injectedDexHash: string;
    injectedDefenderDexHash: string | null;
    injectedSoHash: string | null;
    defenderSoName: string | null;
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
      defenderEnabled = false,
      defenderConfig,
      defenderAarPath,
      defenderDex,
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
      const app = await this.validators.validateObjectLock(developerId, packageName, signatureHash);

      // 锁 5:权限锁定(JWT 开发者 = 应用所有者)
      this.validators.validatePermissionLock(developerId, app.id);

      // 锁 2:内容锁定(注入 dex hash 白名单)
      const injectedDexHash = crypto.createHash('sha256').update(xcjAuthSdkDex).digest('hex');
      this.validators.validateContentLock(injectedDexHash);

      // 锁 7:客户端签名自检(配置预期 hash)
      const clientCheckConfig = this.validators.configureClientSignatureCheck(signatureHash);

      // 复制工作副本
      await fs.copyFile(apkPath, packedPath);

      // L8:回滚机制说明 -- 所有注入操作(dex/.so/config/Manifest)都在隔离目录 workDir
      // 的 packedPath 副本上进行。任一步抛异常时,finally 块 cleanupWorkDir 会删除整个
      // workDir(含半注入的 APK),用户始终拿不到不一致的 APK,故无需逐步回滚。

      // dex 注入(锁 2 + 锁 3)
      const multidexInfo = await this.dexInjector.detectMultidex(packedPath);
      await this.dexInjector.injectDex(packedPath, xcjAuthSdkDex, multidexInfo.nextDexName);

      // ============= ADR 0088:defender-sdk 注入(可选) =============
      let injectedDefenderDexHash: string | null = null;
      let injectedSoHash: string | null = null;
      let defenderSoName: string | null = null;

      if (defenderEnabled) {
        this.logger.log('defender-sdk 注入启用(ADR 0088)');

        // defender dex 注入(预编译 classes-defender.dex)
        if (defenderDex) {
          // 锁 2 扩展:defender dex 白名单校验(注入前校验,失败则 APK 未被修改)
          const preCheckHash = crypto.createHash('sha256').update(defenderDex).digest('hex');
          this.validators.validateDefenderContentLock(preCheckHash);

          // 计算下一个 dex 名(auth dex 已占一个)
          const authDexNum = this.parseDexNumber(multidexInfo.nextDexName);
          const defenderDexName = `classes${authDexNum + 1}.dex`;
          const defenderResult = await this.dexInjector.injectDex(
            packedPath,
            defenderDex,
            defenderDexName,
          );
          injectedDefenderDexHash = defenderResult.injectedDexHash;
          this.logger.log(`defender dex 注入完成:${defenderDexName}`);
        }

        // .so 注入(30 池随机名)
        if (defenderAarPath) {
          // .aar 白名单校验(锁 2 扩展)
          await this.soInjector.validateAarHash(defenderAarPath, XCJ_DEFENDER_SDK_AAR_WHITELIST);
          // 提取 .so
          const { abis } = await this.soInjector.extractSoFromAar(defenderAarPath, workDir);
          // 注入 .so(随机名)
          const soResult = await this.soInjector.injectSo(packedPath, abis, workDir);
          injectedSoHash = soResult.injectedSoHash;
          defenderSoName = soResult.randomSoName;
          this.logger.log(`defender .so 注入完成:${defenderSoName}`);
        }

        // defender-config.json 注入(写入签名 hash + integrity 预期表)
        if (defenderConfig) {
          defenderConfig.signatureExpectedHash = signatureHash;

          // M6:遍历当前 APK entry 生成 integrity 预期表(CRC + 文件列表)。
          // 在 config 注入前生成,排除 META-INF/(重签后变)和 assets/defender-config.json(本步注入)。
          const tables = await this.generateIntegrityTables(packedPath);
          defenderConfig.integrityCrcTable = tables.crcTable;
          defenderConfig.integrityFileList = tables.fileList;
          this.logger.log(
            `integrity 预期表生成: crc=${tables.crcTable.length} files=${tables.fileList.length}`,
          );

          const configJson = this.defenderConfigGenerator.generate(defenderConfig);
          await this.defenderConfigGenerator.injectConfig(packedPath, configJson, workDir);
        }
      }

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
        defenderConfig: defenderEnabled
          ? { enabled: true, randomSoName: defenderSoName ?? 'libsec_helper.so' }
          : undefined,
      });

      // 锁 3:入口锁定校验
      this.validators.validateEntryLock(manifestChanges);

      // 重打包(apktool b,smali -> dex + 文本 XML -> 二进制 AXML)
      await this.dexInjector.repackApk(packedPath, workDir);

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
      const packedApkHash = crypto.createHash('sha256').update(packedApk).digest('hex');

      // 自动入白名单(封装后 APK hash)
      await this.prisma.application.update({
        where: { id: app.id },
        data: {
          signHashAllowList: { push: packedApkHash },
        },
      });

      // keystore 指纹(不存密码)
      const keystoreFingerprint = crypto.createHash('sha256').update(keystoreBuffer).digest('hex');

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
        injectedDefenderDexHash,
        injectedSoHash,
        defenderSoName,
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
      const { stdout } = await execFileAsync(apksignerPath, ['verify', '--print-certs', apkPath], {
        timeout: 30_000,
        maxBuffer: 1024 * 1024,
      });
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
   * M6:遍历 APK entry 生成 integrity 预期表
   *
   * 用于 Native 层完整性校验(H5 框架):
   *  - crcTable:每个 .dex 的 "entry名:crc32hex"(ZIP 记录的未压缩 CRC32)
   *  - fileList:所有 entry 名(检测额外/缺失文件)
   *
   * 排除 META-INF/(签名文件,重签后会变)和 assets/defender-config.json(本步注入)。
   */
  private generateIntegrityTables(apkPath: string): Promise<{
    crcTable: string[];
    fileList: string[];
  }> {
    return new Promise((resolve, reject) => {
      const crcTable: string[] = [];
      const fileList: string[] = [];

      yauzl.open(apkPath, { lazyEntries: true }, (err, zipfile) => {
        if (err) {
          reject(err);
          return;
        }
        zipfile.on('entry', (entry) => {
          const name = entry.fileName;
          // 排除签名文件(重签后变)和 config(本步注入)
          const excluded =
            name.startsWith('META-INF/') || name === 'assets/defender-config.json';
          if (!excluded) {
            fileList.push(name);
            // .dex 收集 CRC32(ZIP entry 的未压缩 CRC,十六进制小写)
            if (name.toLowerCase().endsWith('.dex')) {
              crcTable.push(`${name}:${(entry.crc32 >>> 0).toString(16).padStart(8, '0')}`);
            }
          }
          zipfile.readEntry();
        });
        zipfile.on('end', () => resolve({ crcTable, fileList }));
        zipfile.on('error', reject);
        zipfile.readEntry();
      });
    });
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

  /**
   * 从 dex 文件名提取编号(classes.dex -> 1, classes2.dex -> 2)
   */
  private parseDexNumber(dexName: string): number {
    const m = dexName.match(/classes(\d*)\.dex/);
    if (!m) return 1;
    return m[1] ? parseInt(m[1], 10) : 1;
  }
}
