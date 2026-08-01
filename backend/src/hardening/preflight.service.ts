import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { execFile } from 'child_process';
import * as fs from 'fs/promises';
import * as path from 'path';

/** 手动包装 execFile 为 Promise(避免 promisify 在 jest mock 下的兼容问题) */
function execFileAsync(
  cmd: string,
  args: string[],
  opts: { timeout?: number } = {},
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, opts, (err, stdout, stderr) => {
      if (err) reject(err);
      else resolve({ stdout, stderr });
    });
  });
}

/** APK magic bytes: PK\x03\x04 */
const APK_MAGIC = Buffer.from([0x50, 0x4b, 0x03, 0x04]);

/**
 * 加固前预检服务
 *
 * 在加固开始前一次性检查所有前置条件，快速失败（~3s），
 * 避免用户等 2-3 分钟后才在 apksigner 步骤报错。
 */
@Injectable()
export class PreflightService {
  private readonly logger = new Logger(PreflightService.name);

  /**
   * 验证 Keystore: 密码正确 + 别名存在
   */
  async validateKeystore(
    ksPath: string,
    ksPassword: string,
    alias: string,
  ): Promise<void> {
    try {
      const { stdout, stderr } = await execFileAsync('keytool', [
        '-list',
        '-keystore', ksPath,
        '-storepass', ksPassword,
        '-alias', alias,
      ], { timeout: 10_000 });

      const output = stdout + stderr;
      // keytool 密码错时 stderr 含 "password was incorrect" 或中文
      if (output.includes('incorrect') || output.includes('密码不正确') || output.includes('error')) {
        if (output.includes('incorrect') || output.includes('密码')) {
          throw new BadRequestException('Keystore 密码错误');
        }
      }

      // 检查别名是否在输出中
      if (!output.includes(alias) && !output.includes('别名: ' + alias) && !output.includes('Alias name: ' + alias)) {
        // keytool 用 -alias 参数时,如果别名不存在会报错到 stderr
        // 但如果 keytool 没报错且输出不含别名,可能是格式问题
        // 宽松检查: 只要 keytool exit 0 就认为存在
      }
    } catch (e) {
      if (e instanceof BadRequestException) throw e;
      const err = e as Error & { stderr?: string };
      const combined = `${err.message} ${err.stderr ?? ''}`;
      if (combined.includes('incorrect') || combined.includes('password') || combined.includes('密码')) {
        throw new BadRequestException('Keystore 密码错误');
      }
      if (combined.includes('does not exist') || combined.includes('不存在') || combined.includes('not found')) {
        throw new BadRequestException(`别名 '${alias}' 不存在于 Keystore 中`);
      }
      throw new BadRequestException(`Keystore 验证失败: ${err.message}`);
    }
  }

  /**
   * 验证 APK: magic bytes + 已加固检测
   */
  async validateApk(apkPath: string): Promise<void> {
    // 文件大小
    const stat = await fs.stat(apkPath);
    if (stat.size < 1024) {
      throw new BadRequestException('APK 文件损坏(过小)');
    }

    // Magic bytes
    const fd = await fs.open(apkPath, 'r');
    try {
      const header = Buffer.alloc(4);
      await fd.read(header, 0, 4, 0);
      if (!header.equals(APK_MAGIC)) {
        throw new BadRequestException('APK 文件损坏(非 ZIP 格式)');
      }
    } finally {
      await fd.close();
    }

    // 已加固检测: 检查 zip 中是否含 classes-xcj.dex
    try {
      const AdmZip = (await import('adm-zip')).default;
      const zip = new AdmZip(apkPath);
      const entries = zip.getEntries().map((e) => e.entryName);
      if (entries.includes('classes-xcj.dex')) {
        throw new BadRequestException('APK 已加固(含 classes-xcj.dex),请勿重复加固');
      }
    } catch (e) {
      if (e instanceof BadRequestException) throw e;
      // adm-zip 读不了就跳过此检查
      this.logger.warn(`已加固检测跳过: ${(e as Error).message}`);
    }
  }

  /**
   * 验证 SDK 产物存在
   */
  async validateSdkArtifacts(): Promise<void> {
    const candidates = [
      path.resolve(process.cwd(), 'sdk-artifacts', 'classes-xcj.dex'),
      path.resolve(process.cwd(), '..', 'sdk-android', 'defender-sdk', 'build',
        'intermediates', 'aar_main_jar', 'release', 'classes.jar'),
    ];
    let found = false;
    for (const p of candidates) {
      try {
        await fs.stat(p);
        found = true;
        break;
      } catch { /* not found */ }
    }
    if (!found) {
      throw new BadRequestException('SDK 未构建: 找不到 classes-xcj.dex 或 classes.jar');
    }
  }

  /**
   * 运行全部预检
   */
  async runAll(
    apkPath: string,
    ksPath: string,
    ksPassword: string,
    alias: string,
  ): Promise<void> {
    // 并行执行独立检查
    await Promise.all([
      this.validateKeystore(ksPath, ksPassword, alias),
      this.validateApk(apkPath),
      this.validateSdkArtifacts(),
    ]);
    this.logger.log('预检全部通过');
  }
}
