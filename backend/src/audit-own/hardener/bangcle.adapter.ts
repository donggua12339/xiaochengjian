import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';
import * as yauzl from 'yauzl';

/**
 * 梆梆加固自检适配器(ADR 0078)
 *
 * 锁 C:仅完整性报告,不输出反编译源码
 *
 * 对自有梆梆加固 APK 做:
 *  - 梆梆 so 文件完整性扫描(SHA-256 + 大小 + 加载路径)
 *  - 可疑 API 调用扫描(静态规则,不运行 APK)
 *  - APK 签名完整性验证
 *
 * 不做(红线):
 *  - 通用脱壳(还原 dex)
 *  - 反编译加固 so 还原源码
 *  - 动态运行 APK
 *  - 输出反编译源码 / smali
 */

export interface BangcleSoReport {
  name: string;
  sha256: string;
  size: number;
  loadPath: string;
}

export interface BangcleIntegrityReport {
  hardener: 'bangcle';
  soFiles: BangcleSoReport[];
  entryClass: string | null;
  signatures: {
    v1: boolean;
    v2: boolean;
    v3: boolean;
  };
  suspiciousCalls: {
    type: string;
    symbol: string;
    count: number;
  }[];
  scanVersion: string;
  scanTime: string;
}

export interface BangcleScanInput {
  /** APK zip 内的所有 entry 路径 */
  apkEntries: string[];
  /** APK buffer(用于读取 so 文件内容算 hash) */
  apkBuffer: Buffer;
  /** AndroidManifest 中 <application android:name> 的值 */
  applicationClassName?: string;
  /** 签名块检测结果(由调用方提供,adapter 不重复检测) */
  signatures: { v1: boolean; v2: boolean; v3: boolean };
}

@Injectable()
export class BangcleAdapter {
  private readonly logger = new Logger(BangcleAdapter.name);

  private readonly SCAN_VERSION = '1.0.0';

  /**
   * 梆梆加固 so 文件名匹配(与 hardener-detector 一致)
   */
  private readonly bangcleSoPatterns = [
    /lib\/[^/]+\/libSecShell\.so$/i,
    /lib\/[^/]+\/libDexHelper\.so$/i,
    /lib\/[^/]+\/libNative\.so$/i,
  ];

  /**
   * 生成梆梆加固完整性报告
   *
   * 锁 C 约束:仅输出完整性数据 + so/API 扫描结果,不输出反编译源码
   *
   * @param input 扫描输入
   * @returns 完整性报告(JSON 可序列化)
   */
  async generateReport(input: BangcleScanInput): Promise<BangcleIntegrityReport> {
    const { apkEntries, apkBuffer, applicationClassName, signatures } = input;

    // 1. 提取梆梆 so 文件列表 + 用 yauzl 读取真实内容算 SHA-256
    const bangcleSos = apkEntries.filter((entry) =>
      this.bangcleSoPatterns.some((pattern) => pattern.test(entry)),
    );

    const soReports: BangcleSoReport[] = [];
    for (const entry of bangcleSos) {
      const parts = entry.split('/');
      const name = parts[parts.length - 1];
      const loadPath = parts.slice(0, -1).join('/') + '/';

      try {
        const soContent = await this.extractFileFromZip(apkBuffer, entry);
        const sha256 = crypto.createHash('sha256').update(soContent).digest('hex');
        soReports.push({ name, sha256, size: soContent.length, loadPath });
      } catch (e) {
        this.logger.warn(`读取 so 失败: ${entry} - ${(e as Error).message}`);
        soReports.push({ name, sha256: 'unknown', size: 0, loadPath });
      }
    }

    // 2. 可疑 API 调用扫描(M15:静态规则,扫描 AndroidManifest 高风险权限)
    const suspiciousCalls = await this.scanSuspiciousManifest(apkBuffer);

    const report: BangcleIntegrityReport = {
      hardener: 'bangcle',
      soFiles: soReports,
      entryClass: applicationClassName ?? null,
      signatures,
      suspiciousCalls,
      scanVersion: this.SCAN_VERSION,
      scanTime: new Date().toISOString(),
    };

    this.logger.log(
      `梆梆完整性报告生成:soFiles=${soReports.length} entryClass=${applicationClassName ?? '(none)'}`,
    );

    return report;
  }

  /**
   * M15:可疑 API 调用静态扫描
   *
   * 从 AndroidManifest.xml 提取 ASCII 字符串,匹配高风险权限。
   * 这些权限常被恶意 SDK 滥用(悬浮窗/无障碍/读短信等),
   * 提示开发者注意自有 APK 是否被植入了可疑权限。
   *
   * 注:仅静态扫描 Manifest 权限声明,不反编译 dex(锁 C 约束)。
   */
  private async scanSuspiciousManifest(
    apkBuffer: Buffer,
  ): Promise<BangcleIntegrityReport['suspiciousCalls']> {
    const suspicious: BangcleIntegrityReport['suspiciousCalls'] = [];

    /* 高风险权限规则(常被恶意 SDK 滥用) */
    const riskyPermissions = [
      'android.permission.SYSTEM_ALERT_WINDOW',
      'android.permission.BIND_ACCESSIBILITY_SERVICE',
      'android.permission.READ_SMS',
      'android.permission.RECEIVE_SMS',
      'android.permission.SEND_SMS',
      'android.permission.READ_CONTACTS',
      'android.permission.RECORD_AUDIO',
      'android.permission.CAMERA',
      'android.permission.READ_PHONE_STATE',
      'android.permission.REQUEST_INSTALL_PACKAGES',
    ];

    try {
      const manifest = await this.extractFileFromZip(apkBuffer, 'AndroidManifest.xml');

      /* 从二进制 AXML 提取 ASCII 字符串 */
      const strings: string[] = [];
      let current = '';
      for (const byte of manifest) {
        if (byte >= 0x20 && byte < 0x7f) {
          current += String.fromCharCode(byte);
        } else {
          if (current.length >= 3) strings.push(current);
          current = '';
        }
      }
      if (current.length >= 3) strings.push(current);
      const manifestText = strings.join(' ');

      for (const perm of riskyPermissions) {
        if (manifestText.includes(perm)) {
          suspicious.push({ type: 'risky_permission', symbol: perm, count: 1 });
        }
      }
    } catch (e) {
      this.logger.warn(`扫描 AndroidManifest 失败: ${(e as Error).message}`);
    }

    return suspicious;
  }

  /**
   * 从 APK zip 中提取指定 entry 的内容(Buffer)
   *
   * 用 yauzl 流式读取,避免大 so 文件 OOM
   */
  private extractFileFromZip(apkBuffer: Buffer, entryName: string): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      yauzl.fromBuffer(apkBuffer, { lazyEntries: true }, (err, zipfile) => {
        if (err) {
          reject(err);
          return;
        }

        let resolved = false;
        zipfile.on('entry', (entry) => {
          if (entry.fileName === entryName && !resolved) {
            resolved = true;
            zipfile.openReadStream(entry, (readErr, readStream) => {
              if (readErr) {
                reject(readErr);
                return;
              }
              const chunks: Buffer[] = [];
              readStream.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
              readStream.on('end', () => {
                zipfile.close();
                resolve(Buffer.concat(chunks));
              });
              readStream.on('error', (e) => reject(e));
            });
          } else {
            zipfile.readEntry();
          }
        });

        zipfile.on('end', () => {
          if (!resolved) {
            reject(new Error(`entry not found: ${entryName}`));
          }
        });

        zipfile.on('error', (e) => {
          if (!resolved) {
            reject(e);
          }
        });

        zipfile.readEntry();
      });
    });
  }
}
