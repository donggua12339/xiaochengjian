import { BadRequestException } from '@nestjs/common';
import { DefenderConfigGenerator } from './defender-config-generator';
import * as fs from 'fs/promises';
import { execFile } from 'child_process';

jest.mock('fs/promises');
jest.mock('child_process');

const mockExecFile = execFile as unknown as jest.Mock;

describe('DefenderConfigGenerator', () => {
  let gen: DefenderConfigGenerator;

  beforeEach(() => {
    jest.clearAllMocks();
    gen = new DefenderConfigGenerator();
    (fs.rm as jest.Mock).mockResolvedValue(undefined);
    (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
    (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
  });

  const base = { appId: 'app-1', serverUrl: 'https://xcj.test' };

  describe('generate', () => {
    it('最小输入应填充全部默认值', () => {
      const out = JSON.parse(gen.generate(base));
      expect(out.version).toBe(1);
      expect(out.appId).toBe('app-1');
      expect(out.serverUrl).toBe('https://xcj.test');
      expect(out.signatureExpectedHash).toBe('');
      expect(out.signatureVerify).toEqual({ enabled: true, onViolation: 'kill' });
      expect(out.antiDebug).toEqual({ enabled: false, onViolation: 'kill' });
      expect(out.antiFrida).toEqual({ enabled: false, onViolation: 'kill' });
      expect(out.antiDump).toEqual({ enabled: false, onViolation: 'kill' });
      expect(out.rootDetect).toEqual({ enabled: false, onViolation: 'warn' });
      expect(out.xposedDetect).toEqual({ enabled: false, onViolation: 'kill', killThreshold: 70 });
      expect(out.emulatorDetect).toEqual({ enabled: false, onViolation: 'warn' });
      expect(out.integrityCheck).toEqual({ enabled: true, onViolation: 'kill' });
      expect(out.secureScreen).toEqual({ enabled: false, excludeActivities: [] });
      expect(out.onViolationKill).toEqual({
        delayMinMs: 3000,
        delayMaxMs: 15000,
        method: 'sigabrt',
        showToast: true,
        toastMessage: '检测到安全风险',
      });
      expect(out.report).toEqual({ enabled: false, throttleMs: 300000 });
      expect(out.integrityCrcTable).toEqual([]);
      expect(out.integrityFileList).toEqual([]);
    });

    it('覆盖字段应优先于默认值(模块级)', () => {
      const out = JSON.parse(
        gen.generate({
          ...base,
          signatureExpectedHash: 'abc123',
          antiFrida: { enabled: true, onViolation: 'warn' },
          rootDetect: { enabled: true, onViolation: 'kill' },
        }),
      );
      expect(out.signatureExpectedHash).toBe('abc123');
      expect(out.antiFrida).toEqual({ enabled: true, onViolation: 'warn' });
      expect(out.rootDetect).toEqual({ enabled: true, onViolation: 'kill' });
    });

    it('xposedDetect / secureScreen / onViolationKill / report 应合并默认值', () => {
      const out = JSON.parse(
        gen.generate({
          ...base,
          xposedDetect: { enabled: true, onViolation: 'kill', killThreshold: 90 },
          secureScreen: { enabled: true, excludeActivities: ['.MainActivity'] },
          onViolationKill: { delayMinMs: 1000 },
          report: { enabled: true },
        }),
      );
      expect(out.xposedDetect.killThreshold).toBe(90);
      expect(out.xposedDetect.enabled).toBe(true);
      expect(out.secureScreen).toEqual({ enabled: true, excludeActivities: ['.MainActivity'] });
      // onViolationKill 合并:覆盖 delayMinMs,保留其余默认
      expect(out.onViolationKill.delayMinMs).toBe(1000);
      expect(out.onViolationKill.delayMaxMs).toBe(15000);
      expect(out.onViolationKill.method).toBe('sigabrt');
      // report 合并:覆盖 enabled,保留 throttleMs
      expect(out.report.enabled).toBe(true);
      expect(out.report.throttleMs).toBe(300000);
    });

    it('secureScreen 仅传 enabled 时 excludeActivities 默认空数组', () => {
      const out = JSON.parse(gen.generate({ ...base, secureScreen: { enabled: true } }));
      expect(out.secureScreen.excludeActivities).toEqual([]);
    });

    it('integrity 表传入应保留', () => {
      const out = JSON.parse(
        gen.generate({
          ...base,
          integrityCrcTable: [{ path: 'classes.dex', crc: 123 }],
          integrityFileList: ['classes.dex'],
        } as never),
      );
      expect(out.integrityCrcTable).toHaveLength(1);
      expect(out.integrityFileList).toEqual(['classes.dex']);
    });
  });

  describe('validateInput(锁 6)', () => {
    it('模块 onViolation 非法应抛 INVALID_DEFENDER_CONFIG', () => {
      expect(() =>
        gen.generate({ ...base, antiDebug: { enabled: true, onViolation: 'explode' as never } }),
      ).toThrow(BadRequestException);
    });

    it('xposedDetect.killThreshold 超界应抛错', () => {
      expect(() =>
        gen.generate({
          ...base,
          xposedDetect: { enabled: true, onViolation: 'kill', killThreshold: 101 },
        }),
      ).toThrow(BadRequestException);
      expect(() =>
        gen.generate({
          ...base,
          xposedDetect: { enabled: true, onViolation: 'kill', killThreshold: -1 },
        }),
      ).toThrow(BadRequestException);
    });

    it('onViolationKill.delayMinMs 负值应抛错', () => {
      expect(() => gen.generate({ ...base, onViolationKill: { delayMinMs: -1 } })).toThrow(
        BadRequestException,
      );
    });

    it('onViolationKill.delayMaxMs < delayMinMs 应抛错', () => {
      expect(() =>
        gen.generate({ ...base, onViolationKill: { delayMinMs: 5000, delayMaxMs: 1000 } }),
      ).toThrow(BadRequestException);
    });

    it('合法边界值(killThreshold=0/100)应通过', () => {
      expect(() =>
        gen.generate({
          ...base,
          xposedDetect: { enabled: true, onViolation: 'kill', killThreshold: 0 },
        }),
      ).not.toThrow();
      expect(() =>
        gen.generate({
          ...base,
          xposedDetect: { enabled: true, onViolation: 'kill', killThreshold: 100 },
        }),
      ).not.toThrow();
    });
  });

  describe('injectConfig', () => {
    it('成功应写 config + zip 注入', async () => {
      mockExecFile.mockImplementation((_c: string, _a: string[], _o: unknown, cb: unknown) => {
        (cb as (e: null, r: { stdout: string; stderr: string }) => void)(null, {
          stdout: '',
          stderr: '',
        });
        return undefined;
      });
      await expect(gen.injectConfig('/tmp/a.apk', '{"a":1}', '/tmp/work')).resolves.toBeUndefined();
      expect(fs.writeFile).toHaveBeenCalled();
      expect(mockExecFile).toHaveBeenCalled();
    });

    it('zip 失败应抛 CONFIG_INJECT_FAILED', async () => {
      mockExecFile.mockImplementation((_c: string, _a: string[], _o: unknown, cb: unknown) => {
        (cb as (e: Error) => void)(new Error('zip boom'));
        return undefined;
      });
      await expect(gen.injectConfig('/tmp/a.apk', '{}', '/tmp/work')).rejects.toThrow(
        'CONFIG_INJECT_FAILED',
      );
    });
  });
});
