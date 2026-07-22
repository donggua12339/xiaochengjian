import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

/**
 * dex 注入器(ADR 0081 锁 2 + 锁 3)
 *
 * 功能:
 *  1. 解包 APK(zip)
 *  2. 检测 MultiDex 结构
 *  3. 注入 classes-xcj.dex(从白名单路径读取)
 *  4. 修改原 Application 的 superclass 为 XcjApplication(需 dexlib2,MVP 阶段先跳过)
 *  5. 修改 AndroidManifest.xml(Application 类名 + Meta-data)
 *  6. 重打包
 *
 * MVP 实现:
 *  - dex 注入:用 yazl 把 classes-xcj.dex 加到 APK zip
 *  - superclass 修改:需 dexlib2(Java),MVP 阶段先跳过,假设原 APK 无自定义 Application
 *  - Manifest 修改:需 AXMLParser(二进制 XML),MVP 阶段用占位逻辑
 *
 * 生产实现:
 *  - 用 apktool 反编译 + smali 修改 + 重打包
 *  - 或用 dexlib2 CLI 直接改 superclass
 */
@Injectable()
export class DexInjector {
  private readonly logger = new Logger(DexInjector.name);

  /**
   * 检测 APK 的 MultiDex 结构
   * @param apkPath APK 路径
   * @returns dex 文件列表 + 是否 MultiDex
   */
  async detectMultidex(apkPath: string): Promise<{
    dexFiles: string[];
    isMultidex: boolean;
    nextDexName: string;
  }> {
    const { stdout } = await execFileAsync('unzip', ['-l', apkPath], {
      timeout: 30_000,
      maxBuffer: 1024 * 1024,
    });

    const dexFiles: string[] = [];
    const lines = stdout.split('\n').slice(3, -2);
    for (const line of lines) {
      const entry = line.trim().split(/\s+/).slice(3).join(' ');
      if (entry && entry.endsWith('.dex')) {
        dexFiles.push(entry);
      }
    }

    // 排序:classes.dex, classes2.dex, classes3.dex, ...
    dexFiles.sort((a, b) => {
      const getNum = (s: string): number => {
        const m = s.match(/classes(\d*)\.dex/);
        return m ? (m[1] ? parseInt(m[1], 10) : 1) : 0;
      };
      return getNum(a) - getNum(b);
    });

    const isMultidex = dexFiles.length > 1;
    const maxNum = dexFiles.reduce((max, f) => {
      const m = f.match(/classes(\d*)\.dex/);
      const n = m ? (m[1] ? parseInt(m[1], 10) : 1) : 0;
      return Math.max(max, n);
    }, 1);
    const nextDexName = `classes${maxNum + 1}.dex`;

    this.logger.log(
      `MultiDex 检测:${dexFiles.length} 个 dex,${isMultidex ? 'MultiDex' : '单 Dex'},下一个: ${nextDexName}`,
    );

    return { dexFiles, isMultidex, nextDexName };
  }

  /**
   * 注入 classes-xcj.dex 到 APK
   *
   * @param apkPath APK 路径
   * @param dexContent classes-xcj.dex 内容(Buffer)
   * @param dexName 注入后的 dex 文件名(如 classes2.dex)
   * @returns 注入的 dex SHA-256
   */
  async injectDex(
    apkPath: string,
    dexContent: Buffer,
    dexName: string,
  ): Promise<{ injectedDexHash: string }> {
    const crypto = await import('crypto');
    const injectedDexHash = crypto.createHash('sha256').update(dexContent).digest('hex');

    // 用 zip 命令把 dex 加到 APK(unzip -l 已验证 APK 是 zip 格式)
    const tmpDex = path.join(path.dirname(apkPath), dexName);
    await fs.writeFile(tmpDex, dexContent);

    try {
      await execFileAsync('zip', ['-j', apkPath, tmpDex], { timeout: 30_000 });
      this.logger.log(`dex 注入完成:${dexName} (SHA-256: ${injectedDexHash.slice(0, 16)}...)`);
    } catch (e) {
      throw new BadRequestException('DEX_INJECT_FAILED', {
        cause: `failed to inject dex: ${(e as Error).message}`,
      });
    } finally {
      await fs.unlink(tmpDex).catch(() => {});
    }

    return { injectedDexHash };
  }

  /**
   * 修改 AndroidManifest.xml(锁 3 入口锁定)
   *
   * MVP 实现:占位逻辑(实际需 AXMLParser 解析二进制 XML)
   * 生产实现:用 apktool 反编译 -> 改 XML -> 重打包
   *
   * 允许的修改(锁 3 + ADR 0088 扩展):
   *  - <application android:name="..."> 改为 XcjApplication
   *  - <meta-data android:name="xcj.*" />(含 xcj.defender.lib)
   *  - <uses-permission android:name="android.permission.INTERNET" />
   *  - <provider android:name="com.xcj.defender.DefenderInitProvider" />(ADR 0088)
   *
   * @returns Manifest 修改项(供锁 3 校验)
   */
  async patchManifest(params: {
    apkPath: string;
    workDir: string;
    originalApplicationName: string | null;
    xcjConfig: {
      appId: string;
      serverUrl: string;
      expectedSignatureHash: string;
    };
    defenderConfig?: {
      enabled: boolean;
      randomSoName: string;
    };
  }): Promise<{
    applicationNameChanged: boolean;
    metaDataAdded: string[];
    permissionsAdded: string[];
    defenderProviderAdded: boolean;
    otherChanges: string[];
  }> {
    const { apkPath, workDir, originalApplicationName, xcjConfig, defenderConfig } = params;

    // MVP:记录修改项,实际 XML 修改需 AXMLParser
    this.logger.warn('patchManifest MVP 实现:实际 XML 修改需 AXMLParser/apktool,当前仅记录修改项');

    // 解压 AndroidManifest.xml 查看原 Application
    try {
      await execFileAsync('unzip', ['-o', apkPath, 'AndroidManifest.xml', '-d', workDir], {
        timeout: 30_000,
      });
    } catch (e) {
      this.logger.warn(`解压 AndroidManifest.xml 失败: ${(e as Error).message}`);
    }

    const metaDataAdded = [
      'xcj.appId',
      'xcj.serverUrl',
      'xcj.expectedSignatureHash',
      'xcj.actionOnMismatch',
    ];
    const defenderProviderAdded = defenderConfig?.enabled === true;

    if (defenderConfig?.enabled) {
      // defender-sdk 启用:加 xcj.defender.lib meta-data + DefenderInitProvider
      metaDataAdded.push('xcj.defender.lib');
      this.logger.log(
        `defender-sdk 启用:meta-data xcj.defender.lib=${defenderConfig.randomSoName} + DefenderInitProvider`,
      );
    }

    const changes = {
      applicationNameChanged: originalApplicationName !== null,
      metaDataAdded,
      permissionsAdded: ['android.permission.INTERNET'],
      defenderProviderAdded,
      otherChanges: [] as string[],
    };

    // 写入 xcj 配置(供 SDK 读取)
    const configPath = path.join(workDir, 'xcj-config.json');
    await fs.writeFile(
      configPath,
      JSON.stringify(
        {
          appId: xcjConfig.appId,
          serverUrl: xcjConfig.serverUrl,
          expectedSignatureHash: xcjConfig.expectedSignatureHash,
          actionOnMismatch: 'PACKAGE_TAMPERED',
          defenderEnabled: defenderConfig?.enabled ?? false,
          defenderLibName: defenderConfig?.enabled ? defenderConfig.randomSoName : null,
        },
        null,
        2,
      ),
    );

    this.logger.log(`Manifest 修改项记录完成(锁 3 校验用):${JSON.stringify(changes)}`);
    return changes;
  }

  /**
   * 重打包 APK(注入 dex + 修改 Manifest 后)
   *
   * MVP 实现:dex 已用 zip 命令注入,Manifest 修改占位,无需额外重打包
   * 生产实现:用 apktool 重打包
   */
  async repackApk(_apkPath: string): Promise<void> {
    this.logger.log('重打包完成(MVP:dex 已注入,Manifest 修改占位)');
  }
}
