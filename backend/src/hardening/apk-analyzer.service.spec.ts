import { BadRequestException } from '@nestjs/common';
import { ApkAnalyzerService } from './apk-analyzer.service';
import { execFile } from 'child_process';
import * as fs from 'fs/promises';

jest.mock('child_process');
jest.mock('fs/promises');

const mockExecFile = execFile as unknown as jest.Mock;

/** 构造 unzip -l 输出(parseZipEntries: slice(3,-2), parts[0]=size parts[3+]=name) */
function zipListing(names: string[]): string {
  const header = [
    'Archive:  /tmp/a.apk',
    '  Length      Date    Time    Name',
    '---------  ---------- -----   ----',
  ];
  const rows = names.map((n) => `     1000  2026-01-01 12:00   ${n}`);
  const footer = [
    '---------                     -------',
    `     ${names.length}000                     ${names.length} files`,
  ];
  return [...header, ...rows, ...footer].join('\n');
}

describe('ApkAnalyzerService', () => {
  let service: ApkAnalyzerService;
  const svc = () => service as unknown as Record<string, (...a: unknown[]) => unknown>;

  beforeEach(() => {
    jest.clearAllMocks();
    service = new ApkAnalyzerService();
    (fs.stat as jest.Mock).mockResolvedValue({ size: 5000 });
    (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
    (fs.rm as jest.Mock).mockResolvedValue(undefined);
  });

  /** execFile 路由:unzip → 列表;aapt badging/xmltree → manifest/sdk
   *  注:jest.mock 丢掉了 execFile 的 promisify.custom 符号,
   *  promisify(execFile) 退化为只取回调第一个结果参数,故把 {stdout,stderr} 作为该参数传入 */
  function mockExec(opts: {
    entries: string[];
    pkg?: string;
    minSdk?: number;
    targetSdk?: number;
    appName?: string;
  }) {
    const reply = (cb: unknown, stdout: string) =>
      (cb as (e: null, r: { stdout: string; stderr: string }) => void)(null, {
        stdout,
        stderr: '',
      });
    mockExecFile.mockImplementation((_cmd: string, args: string[], _o: unknown, cb: unknown) => {
      const call = (args || []).join(' ');
      if (call.startsWith('-l')) {
        reply(cb, zipListing(opts.entries));
      } else if (call.includes('badging')) {
        reply(
          cb,
          `package: name='${opts.pkg ?? 'com.test.app'}' versionCode='1'\n` +
            `sdkVersion:'${opts.minSdk ?? 21}'\ntargetSdkVersion:'${opts.targetSdk ?? 33}'`,
        );
      } else if (call.includes('xmltree')) {
        reply(
          cb,
          opts.appName
            ? `E: manifest\n  E: application\n    A: android:name(0x01010003)=(type 0x3)"${opts.appName}"`
            : 'E: manifest\n  E: application',
        );
      } else {
        reply(cb, '');
      }
      return undefined;
    });
  }

  describe('analyze', () => {
    it('完整分析:包名/DEX/ABI/SDK/推荐配置', async () => {
      mockExec({
        entries: [
          'classes.dex',
          'classes2.dex',
          'lib/arm64-v8a/libfoo.so',
          'lib/armeabi-v7a/libfoo.so',
          'AndroidManifest.xml',
        ],
        pkg: 'com.foo.bar',
        minSdk: 24,
        targetSdk: 34,
        appName: 'com.foo.bar.App',
      });
      const r = await service.analyze('/tmp/a.apk');
      expect(r.packageName).toBe('com.foo.bar');
      expect(r.originalApplicationName).toBe('com.foo.bar.App');
      expect(r.dexFiles).toEqual(['classes.dex', 'classes2.dex']);
      expect(r.isMultidex).toBe(true);
      expect(r.nativeAbis).toEqual(['arm64-v8a', 'armeabi-v7a']);
      expect(r.alreadyHardened).toBe(false);
      expect(r.minSdkVersion).toBe(24);
      expect(r.targetSdkVersion).toBe(34);
      expect(r.apkSize).toBe(5000);
      expect(r.recommendedConfig.productLine).toBe('xuanjia');
    });

    it('检测到梆梆加固应标记 alreadyHardened', async () => {
      mockExec({ entries: ['classes.dex', 'lib/arm64-v8a/libbangcle.so'] });
      const r = await service.analyze('/tmp/a.apk');
      expect(r.alreadyHardened).toBe(true);
      expect(r.detectedHardener).toBe('bangcle');
    });

    it('检测到自家 xcj-defender 应标记(SO 随机名,认 config/loader 特征)', async () => {
      mockExec({
        entries: ['classes.dex', 'assets/defender-config.json', 'lib/arm64-v8a/libmedia.so'],
      });
      const r = await service.analyze('/tmp/a.apk');
      expect(r.alreadyHardened).toBe(true);
      expect(r.detectedHardener).toBe('xcj-defender');
    });

    it('APK 过小应抛 APK_TOO_SMALL', async () => {
      (fs.stat as jest.Mock).mockResolvedValue({ size: 100 });
      await expect(service.analyze('/tmp/a.apk')).rejects.toThrow(BadRequestException);
    });

    it('APK 过大应抛 APK_TOO_LARGE', async () => {
      (fs.stat as jest.Mock).mockResolvedValue({ size: 600 * 1024 * 1024 });
      await expect(service.analyze('/tmp/a.apk')).rejects.toThrow('APK_TOO_LARGE');
    });

    it('无 DEX 应抛 NO_DEX_FILES', async () => {
      mockExec({ entries: ['AndroidManifest.xml', 'res/x.png'] });
      await expect(service.analyze('/tmp/a.apk')).rejects.toThrow('NO_DEX_FILES');
    });

    it('进度回调应被调用', async () => {
      mockExec({ entries: ['classes.dex'] });
      const cb = jest.fn();
      await service.analyze('/tmp/a.apk', cb);
      expect(cb).toHaveBeenCalled();
      const steps = cb.mock.calls.map((c) => c[0]);
      expect(steps).toContain('unzip');
      expect(steps).toContain('dex');
    });
  });

  describe('纯 helper', () => {
    it('detectAbis 提取并排序 ABI', () => {
      const abis = svc().detectAbis([
        { name: 'lib/armeabi-v7a/a.so' },
        { name: 'lib/arm64-v8a/a.so' },
        { name: 'classes.dex' },
      ]);
      expect(abis).toEqual(['arm64-v8a', 'armeabi-v7a']);
    });

    it('detectHardener 匹配各厂商特征', () => {
      expect(svc().detectHardener([{ name: 'lib/arm64-v8a/libjiagu.so' }])).toEqual({
        name: 'qihoo360',
      });
      expect(svc().detectHardener([{ name: 'lib/libshell.so' }])).toEqual({ name: 'legu' });
      expect(svc().detectHardener([{ name: 'classes.dex' }])).toEqual({ name: null });
    });

    it('detectHardener 识别 xcj-defender 双特征', () => {
      expect(
        svc().detectHardener([{ name: 'assets/defender-config.json' }, { name: 'classes.dex' }]),
      ).toEqual({ name: 'xcj-defender' });
      expect(svc().detectHardener([{ name: 'lib/armeabi-v7a/libxcj_loader.so' }])).toEqual({
        name: 'xcj-defender',
      });
    });

    it('buildUnavailableList: 已加固 → all', () => {
      const list = svc().buildUnavailableList(['arm64-v8a'], 'bangcle', 24) as Array<{
        feature: string;
      }>;
      expect(list.some((l) => l.feature === 'all')).toBe(true);
    });

    it('buildUnavailableList: 无 arm64 + 低 minSdk', () => {
      const list = svc().buildUnavailableList(['armeabi-v7a'], null, 21) as Array<{
        feature: string;
      }>;
      const feats = list.map((l) => l.feature);
      expect(feats).toContain('x0_soEncrypt');
      expect(feats).toContain('t1_customLinker');
      expect(feats).toContain('x4_antiDynamic');
    });

    it('buildRecommendedConfig: 已加固全禁用', () => {
      const cfg = svc().buildRecommendedConfig('bangcle', ['arm64-v8a'], [{ feature: 'all' }]) as {
        xuanjia: Record<string, boolean>;
      };
      expect(Object.values(cfg.xuanjia).every((v) => v === false)).toBe(true);
    });

    it('buildRecommendedConfig: 按不可用项禁用', () => {
      const cfg = svc().buildRecommendedConfig(
        null,
        ['arm64-v8a'],
        [{ feature: 'x0_soEncrypt' }],
      ) as {
        xuanjia: Record<string, boolean>;
      };
      expect(cfg.xuanjia.x0_soEncrypt).toBe(false);
      expect(cfg.xuanjia.x4_antiDynamic).toBe(true);
    });

    it('parseZipEntries 解析 unzip 输出', () => {
      const entries = svc().parseZipEntries(
        zipListing(['classes.dex', 'lib/arm64-v8a/a.so']),
      ) as Array<{ name: string }>;
      expect(entries.map((e) => e.name)).toEqual(['classes.dex', 'lib/arm64-v8a/a.so']);
    });
  });

  describe('aapt 不可用降级', () => {
    it('aapt 失败时 manifest/sdk 应降级为 unknown/默认值', async () => {
      mockExecFile.mockImplementation((_cmd: string, args: string[], _o: unknown, cb: unknown) => {
        const call = (args || []).join(' ');
        const done = cb as (e: Error | null, r?: { stdout: string; stderr: string }) => void;
        if (call.startsWith('-l')) {
          done(null, { stdout: zipListing(['classes.dex']), stderr: '' });
        } else {
          done(new Error('aapt not found'));
        }
        return undefined;
      });
      const analyzer = new ApkAnalyzerService();
      const r = await analyzer.analyze('/tmp/a.apk');
      expect(r.packageName).toBe('unknown');
      expect(r.originalApplicationName).toBeNull();
      expect(r.minSdkVersion).toBe(21);
      expect(r.targetSdkVersion).toBe(35);
    });
  });
});
