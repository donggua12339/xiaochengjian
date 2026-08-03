import { BadRequestException } from '@nestjs/common';
import { SoInjector } from './so-injector';
import { execFile } from 'child_process';
import * as fs from 'fs/promises';
import * as crypto from 'crypto';

jest.mock('child_process');
jest.mock('fs/promises');

const mockExecFile = execFile as unknown as jest.Mock;

describe('SoInjector', () => {
  let injector: SoInjector;

  function routeExec(handler: (cmd: string) => { err?: Error }) {
    mockExecFile.mockImplementation((cmd: string, _args: string[], _o: unknown, cb: unknown) => {
      const done = cb as (e: Error | null, r: { stdout: string; stderr: string }) => void;
      const r = handler(cmd);
      if (r.err) done(r.err, { stdout: '', stderr: '' });
      else done(null, { stdout: '', stderr: '' });
      return undefined;
    });
  }

  beforeEach(() => {
    jest.clearAllMocks();
    injector = new SoInjector();
    (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
    (fs.rm as jest.Mock).mockResolvedValue(undefined);
    (fs.copyFile as jest.Mock).mockResolvedValue(undefined);
    (fs.readFile as jest.Mock).mockResolvedValue(Buffer.from('so-content'));
  });

  describe('pickRandomSoName', () => {
    it('应返回池内 .so 名(.so 结尾)', () => {
      for (let i = 0; i < 20; i++) {
        expect(injector.pickRandomSoName()).toMatch(/^lib.*\.so$/);
      }
    });
  });

  describe('extractSoFromAar', () => {
    it('双 ABI 都在应返回 2 个', async () => {
      routeExec(() => ({}));
      (fs.access as jest.Mock).mockResolvedValue(undefined);
      const r = await injector.extractSoFromAar('/tmp/d.aar', '/tmp/work');
      expect(r.abis).toHaveLength(2);
      expect(r.abis.map((a) => a.abi)).toEqual(['arm64-v8a', 'armeabi-v7a']);
    });

    it('仅 arm64 应返回 1 个', async () => {
      routeExec(() => ({}));
      (fs.access as jest.Mock).mockImplementation((p: string) =>
        String(p).includes('arm64-v8a')
          ? Promise.resolve(undefined)
          : Promise.reject(new Error('ENOENT')),
      );
      const r = await injector.extractSoFromAar('/tmp/d.aar', '/tmp/work');
      expect(r.abis).toHaveLength(1);
      expect(r.abis[0].abi).toBe('arm64-v8a');
    });

    it('一个都没有应抛 NO_SO_IN_AAR', async () => {
      routeExec(() => ({}));
      (fs.access as jest.Mock).mockRejectedValue(new Error('ENOENT'));
      await expect(injector.extractSoFromAar('/tmp/d.aar', '/tmp/work')).rejects.toThrow(
        'NO_SO_IN_AAR',
      );
    });

    it('unzip 失败应抛 AAR_EXTRACT_FAILED', async () => {
      routeExec(() => ({ err: new Error('unzip boom') }));
      await expect(injector.extractSoFromAar('/tmp/d.aar', '/tmp/work')).rejects.toThrow(
        'AAR_EXTRACT_FAILED',
      );
    });
  });

  describe('injectSo', () => {
    const abis = [
      { abi: 'arm64-v8a', soPath: '/tmp/work/aar-extracted/jni/arm64-v8a/libxcj_defender.so' },
      { abi: 'armeabi-v7a', soPath: '/tmp/work/aar-extracted/jni/armeabi-v7a/libxcj_defender.so' },
    ];

    it('成功应返回随机名 + SHA-256', async () => {
      routeExec(() => ({}));
      const content = Buffer.from('so-bytes');
      (fs.readFile as jest.Mock).mockResolvedValue(content);
      const expected = crypto.createHash('sha256').update(content).digest('hex');
      const r = await injector.injectSo('/tmp/a.apk', abis, '/tmp/work');
      expect(r.randomSoName).toMatch(/^lib.*\.so$/);
      expect(r.injectedSoHash).toBe(expected);
      expect(fs.copyFile).toHaveBeenCalledTimes(2);
    });

    it('zip 失败应抛 SO_INJECT_FAILED', async () => {
      routeExec((cmd) => (cmd === 'zip' ? { err: new Error('zip boom') } : {}));
      await expect(injector.injectSo('/tmp/a.apk', abis, '/tmp/work')).rejects.toThrow(
        'SO_INJECT_FAILED',
      );
    });
  });

  describe('validateAarHash', () => {
    it('白名单为空应跳过校验返回 hash', async () => {
      const content = Buffer.from('aar');
      (fs.readFile as jest.Mock).mockResolvedValue(content);
      const expected = crypto.createHash('sha256').update(content).digest('hex');
      const r = await injector.validateAarHash('/tmp/d.aar', []);
      expect(r.aarHash).toBe(expected);
    });

    it('在白名单内应通过(大小写不敏感)', async () => {
      const content = Buffer.from('aar');
      (fs.readFile as jest.Mock).mockResolvedValue(content);
      const hash = crypto.createHash('sha256').update(content).digest('hex');
      await expect(injector.validateAarHash('/tmp/d.aar', [hash.toUpperCase()])).resolves.toEqual({
        aarHash: hash,
      });
    });

    it('不在白名单应抛 DEFENDER_AAR_NOT_WHITELISTED', async () => {
      (fs.readFile as jest.Mock).mockResolvedValue(Buffer.from('aar'));
      await expect(injector.validateAarHash('/tmp/d.aar', ['deadbeef'])).rejects.toThrow(
        BadRequestException,
      );
    });
  });
});
