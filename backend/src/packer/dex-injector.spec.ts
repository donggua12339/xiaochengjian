import { DexInjector } from './dex-injector';
import { execFile } from 'child_process';
import * as fs from 'fs/promises';
import * as crypto from 'crypto';

jest.mock('child_process');
jest.mock('fs/promises');

const mockExecFile = execFile as unknown as jest.Mock;

function zipListing(names: string[]): string {
  const header = [
    'Archive:  a.apk',
    '  Length      Date    Time    Name',
    '----  ---- ----   ----',
  ];
  const rows = names.map((n) => `     100  2026-01-01 12:00   ${n}`);
  const footer = ['----  ---- ----', '     100   1 files'];
  return [...header, ...rows, ...footer].join('\n');
}

describe('DexInjector', () => {
  let injector: DexInjector;

  /** promisify.custom 丢失 → 把 {stdout,stderr} 作为回调第一个结果参数 */
  function routeExec(handler: (cmd: string, args: string[]) => { stdout?: string; err?: Error }) {
    mockExecFile.mockImplementation((cmd: string, args: string[], _o: unknown, cb: unknown) => {
      const done = cb as (e: Error | null, r: { stdout: string; stderr: string }) => void;
      const r = handler(cmd, args || []);
      if (r.err) done(r.err, { stdout: '', stderr: '' });
      else done(null, { stdout: r.stdout ?? '', stderr: '' });
      return undefined;
    });
  }

  beforeEach(() => {
    jest.clearAllMocks();
    injector = new DexInjector();
    (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
    (fs.unlink as jest.Mock).mockResolvedValue(undefined);
    (fs.copyFile as jest.Mock).mockResolvedValue(undefined);
  });

  describe('detectMultidex', () => {
    it('单 dex:isMultidex=false, nextDexName=classes2.dex', async () => {
      routeExec(() => ({ stdout: zipListing(['classes.dex', 'AndroidManifest.xml']) }));
      const r = await injector.detectMultidex('/tmp/a.apk');
      expect(r.dexFiles).toEqual(['classes.dex']);
      expect(r.isMultidex).toBe(false);
      expect(r.nextDexName).toBe('classes2.dex');
    });

    it('多 dex:排序 + isMultidex=true + nextDexName 递增', async () => {
      routeExec(() => ({ stdout: zipListing(['classes3.dex', 'classes.dex', 'classes2.dex']) }));
      const r = await injector.detectMultidex('/tmp/a.apk');
      expect(r.dexFiles).toEqual(['classes.dex', 'classes2.dex', 'classes3.dex']);
      expect(r.isMultidex).toBe(true);
      expect(r.nextDexName).toBe('classes4.dex');
    });
  });

  describe('injectDex', () => {
    it('成功应返回 dex 的 SHA-256', async () => {
      routeExec(() => ({ stdout: '' }));
      const content = Buffer.from('dex-bytes');
      const expected = crypto.createHash('sha256').update(content).digest('hex');
      const r = await injector.injectDex('/tmp/a.apk', content, 'classes2.dex');
      expect(r.injectedDexHash).toBe(expected);
      expect(fs.writeFile).toHaveBeenCalled();
      expect(fs.unlink).toHaveBeenCalled();
    });

    it('zip 失败应抛 DEX_INJECT_FAILED', async () => {
      routeExec(() => ({ err: new Error('zip boom') }));
      await expect(
        injector.injectDex('/tmp/a.apk', Buffer.from('x'), 'classes2.dex'),
      ).rejects.toThrow('DEX_INJECT_FAILED');
    });
  });

  describe('patchManifest', () => {
    const baseParams = {
      apkPath: '/tmp/a.apk',
      workDir: '/tmp/work',
      originalApplicationName: null as string | null,
      xcjConfig: {
        appId: 'app-1',
        serverUrl: 'https://xcj.test',
        expectedSignatureHash: 'hash123',
      },
    };
    const manifestXml =
      '<manifest xmlns:android="x" package="com.test.app"><application android:label="A"></application></manifest>';

    it('无 defender:插入 4 个 meta-data + INTERNET,defenderProviderAdded=false', async () => {
      routeExec(() => ({ stdout: '' }));
      (fs.readFile as jest.Mock).mockResolvedValue(manifestXml);
      const r = await injector.patchManifest(baseParams);
      expect(r.applicationNameChanged).toBe(false);
      expect(r.metaDataAdded).toEqual([
        'xcj.appId',
        'xcj.serverUrl',
        'xcj.expectedSignatureHash',
        'xcj.actionOnMismatch',
      ]);
      expect(r.permissionsAdded).toEqual(['android.permission.INTERNET']);
      expect(r.defenderProviderAdded).toBe(false);
      expect(r.otherChanges).toEqual([]);
      // 写回 manifest + 配置
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('defender 启用:多加 xcj.defender.lib + provider', async () => {
      routeExec(() => ({ stdout: '' }));
      (fs.readFile as jest.Mock).mockResolvedValue(manifestXml);
      const r = await injector.patchManifest({
        ...baseParams,
        originalApplicationName: 'com.test.App',
        defenderConfig: { enabled: true, randomSoName: 'librand.so' },
      });
      expect(r.applicationNameChanged).toBe(true);
      expect(r.defenderProviderAdded).toBe(true);
      expect(r.metaDataAdded).toContain('xcj.defender.lib');
    });

    it('无 <application> 标签应抛 MANIFEST_NO_APPLICATION_TAG', async () => {
      routeExec(() => ({ stdout: '' }));
      (fs.readFile as jest.Mock).mockResolvedValue('<manifest package="com.x"></manifest>');
      await expect(injector.patchManifest(baseParams)).rejects.toThrow(
        'MANIFEST_NO_APPLICATION_TAG',
      );
    });

    it('apktool d 失败应抛 APKTOOL_DECODE_FAILED', async () => {
      routeExec((cmd) => (cmd === 'apktool' ? { err: new Error('decode boom') } : { stdout: '' }));
      await expect(injector.patchManifest(baseParams)).rejects.toThrow('APKTOOL_DECODE_FAILED');
    });
  });

  describe('repackApk', () => {
    it('成功应 apktool b + 覆盖原 APK', async () => {
      routeExec(() => ({ stdout: '' }));
      await injector.repackApk('/tmp/a.apk', '/tmp/work');
      expect(fs.copyFile).toHaveBeenCalled();
    });

    it('apktool b 失败应抛 APKTOOL_BUILD_FAILED', async () => {
      routeExec(() => ({ err: new Error('build boom') }));
      await expect(injector.repackApk('/tmp/a.apk', '/tmp/work')).rejects.toThrow(
        'APKTOOL_BUILD_FAILED',
      );
    });
  });
});
