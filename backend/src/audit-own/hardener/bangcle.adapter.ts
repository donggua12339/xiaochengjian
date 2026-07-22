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

    // 2. 可疑 API 调用扫描(静态规则,扫描 AndroidManifest 字符串)
    // MVP:返回空数组,实际规则在 ADR 0078 §6 内部维护(不公开)
    const suspiciousCalls: BangcleIntegrityReport['suspiciousCalls'] = [];

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
