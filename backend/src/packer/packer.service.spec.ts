import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { PayloadTooLargeException } from '@nestjs/common';
import { EventEmitter } from 'events';
import { PackerService } from './packer.service';
import { PrismaService } from '../prisma/prisma.service';
import { PackerValidators } from './packer-validators';
import { DexInjector } from './dex-injector';
import { SoInjector } from './so-injector';
import { DefenderConfigGenerator } from './defender-config-generator';
import { PackerLogService } from './packer-log.service';
import * as fs from 'fs/promises';
import { execFile } from 'child_process';
import * as yauzl from 'yauzl';

jest.mock('fs/promises');
jest.mock('child_process');
jest.mock('yauzl');

const mockExecFile = execFile as unknown as jest.Mock;

describe('PackerService', () => {
  let service: PackerService;
  let prisma: { application: { update: jest.Mock } };
  let validators: Record<string, jest.Mock>;
  let dexInjector: Record<string, jest.Mock>;
  let soInjector: Record<string, jest.Mock>;
  let configGen: Record<string, jest.Mock>;
  let packerLog: { record: jest.Mock };
  const configMap: Record<string, unknown> = {
    auditMaxApkSizeMb: 200,
    auditTmpRoot: '/tmp/audit',
    apksignerPath: '/opt/apksigner',
  };

  beforeEach(async () => {
    jest.clearAllMocks();
    prisma = { application: { update: jest.fn().mockResolvedValue({}) } };
    validators = {
      validateSignLock: jest.fn(),
      validateDataLock: jest.fn(),
      validateObjectLock: jest.fn().mockResolvedValue({ id: 'app-1' }),
      validatePermissionLock: jest.fn(),
      validateContentLock: jest.fn(),
      validateEntryLock: jest.fn(),
      configureClientSignatureCheck: jest
        .fn()
        .mockReturnValue({ expectedSignatureHash: 'exp-hash' }),
      validateDefenderContentLock: jest.fn(),
    };
    dexInjector = {
      detectMultidex: jest.fn().mockResolvedValue({
        dexFiles: ['classes.dex'],
        isMultidex: false,
        nextDexName: 'classes2.dex',
      }),
      injectDex: jest.fn().mockResolvedValue({ injectedDexHash: 'dexhash' }),
      patchManifest: jest.fn().mockResolvedValue({
        applicationNameChanged: false,
        metaDataAdded: [],
        permissionsAdded: [],
        defenderProviderAdded: false,
        otherChanges: [],
      }),
      repackApk: jest.fn().mockResolvedValue(undefined),
    };
    soInjector = {
      validateAarHash: jest.fn().mockResolvedValue({ aarHash: 'aarhash' }),
      extractSoFromAar: jest
        .fn()
        .mockResolvedValue({ abis: [{ abi: 'arm64-v8a', soPath: '/tmp/a.so' }] }),
      injectSo: jest
        .fn()
        .mockResolvedValue({ randomSoName: 'librand.so', injectedSoHash: 'sohash' }),
    };
    configGen = {
      generate: jest.fn().mockReturnValue('{}'),
      injectConfig: jest.fn().mockResolvedValue(undefined),
    };
    packerLog = { record: jest.fn().mockResolvedValue(undefined) };

    // fs 默认成功
    (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
    (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
    (fs.copyFile as jest.Mock).mockResolvedValue(undefined);
    (fs.rm as jest.Mock).mockResolvedValue(undefined);
    // readFile:manifest 返回含包名的 buffer(非打印字节隔离),其余返回 packed apk
    (fs.readFile as jest.Mock).mockImplementation((p: string) => {
      if (String(p).endsWith('AndroidManifest.xml')) {
        return Promise.resolve(Buffer.from('\x00\x00com.test.app\x00\x00', 'latin1'));
      }
      return Promise.resolve(Buffer.from('packed-apk'));
    });

    // execFile 默认成功(apksigner verify / unzip / sign)
    mockExecFile.mockImplementation((_c: string, _a: string[], _o: unknown, cb: unknown) => {
      (cb as (e: null, r: { stdout: string; stderr: string }) => void)(null, {
        stdout: 'SHA-256 digest: aa:bb:cc',
        stderr: '',
      });
      return undefined;
    });

    // yauzl 默认返回空 zip(让 generateIntegrityTables 快速 resolve)
    (yauzl.open as unknown as jest.Mock).mockImplementation(
      (_p: string, _o: unknown, cb: (e: null, z: unknown) => void) => {
        const zip = new EventEmitter() as EventEmitter & { readEntry: () => void };
        zip.readEntry = () => process.nextTick(() => zip.emit('end'));
        cb(null, zip);
      },
    );

    const module = await Test.createTestingModule({
      providers: [
        PackerService,
        { provide: PrismaService, useValue: prisma },
        { provide: PackerValidators, useValue: validators },
        { provide: DexInjector, useValue: dexInjector },
        { provide: SoInjector, useValue: soInjector },
        { provide: DefenderConfigGenerator, useValue: configGen },
        { provide: PackerLogService, useValue: packerLog },
        { provide: ConfigService, useValue: { get: jest.fn((k: string) => configMap[k]) } },
      ],
    }).compile();
    service = module.get(PackerService);
  });

  const baseParams = () => ({
    developerId: 'dev-1',
    apkBuffer: Buffer.from('apk-content'),
    originalName: 'app.apk',
    keystoreBuffer: Buffer.from('keystore'),
    keystorePassword: 'kspass',
    keyAlias: 'key0',
    keyPassword: 'keypass',
    sdkConfig: { serverUrl: 'https://xcj.test' },
    xcjAuthSdkDex: Buffer.from('xcj-dex'),
    ip: '1.2.3.4',
  });

  describe('pack - 输入校验', () => {
    it('APK 超大应抛 PayloadTooLargeException', async () => {
      const p = baseParams();
      p.apkBuffer = Buffer.alloc(201 * 1024 * 1024);
      await expect(service.pack(p)).rejects.toThrow(PayloadTooLargeException);
    });

    it('validateSignLock 失败应传播', async () => {
      validators.validateSignLock.mockImplementation(() => {
        throw new Error('no keystore');
      });
      await expect(service.pack(baseParams())).rejects.toThrow('no keystore');
    });
  });

  describe('pack - 成功路径(无 defender)', () => {
    it('应跑完七锁 + 返回结果 + 入白名单 + 审计', async () => {
      const r = await service.pack(baseParams());
      expect(r.taskId).toMatch(/^packer-/);
      expect(r.packedApkHash).toBeTruthy();
      expect(r.injectedDexHash).toBeTruthy();
      expect(r.injectedDefenderDexHash).toBeNull();
      expect(r.injectedSoHash).toBeNull();
      expect(r.defenderSoName).toBeNull();
      expect(r.keystoreFingerprint).toBeTruthy();
      expect(validators.validateObjectLock).toHaveBeenCalled();
      expect(validators.validateContentLock).toHaveBeenCalled();
      expect(validators.validateEntryLock).toHaveBeenCalled();
      expect(dexInjector.injectDex).toHaveBeenCalled();
      expect(prisma.application.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ signHashAllowList: expect.anything() }),
        }),
      );
      expect(packerLog.record).toHaveBeenCalledWith(expect.objectContaining({ status: 'SUCCESS' }));
    });

    it('应清理隔离目录(finally)', async () => {
      await service.pack(baseParams());
      expect(fs.rm).toHaveBeenCalled();
    });
  });

  describe('pack - defender 注入路径', () => {
    it('defender 全启用应注入 dex + so + config', async () => {
      const p = {
        ...baseParams(),
        defenderEnabled: true,
        defenderDex: Buffer.from('defender-dex'),
        defenderAarPath: '/tmp/defender.aar',
        defenderConfig: { appId: 'app-1', serverUrl: 'https://xcj.test' },
      };
      const r = await service.pack(p);
      expect(r.injectedDefenderDexHash).toBe('dexhash');
      expect(r.injectedSoHash).toBe('sohash');
      expect(r.defenderSoName).toBe('librand.so');
      expect(validators.validateDefenderContentLock).toHaveBeenCalled();
      expect(soInjector.validateAarHash).toHaveBeenCalled();
      expect(soInjector.injectSo).toHaveBeenCalled();
      expect(configGen.generate).toHaveBeenCalled();
      expect(configGen.injectConfig).toHaveBeenCalled();
    });

    it('defender 仅启用(无 dex/aar/config)应跳过注入', async () => {
      const p = { ...baseParams(), defenderEnabled: true };
      const r = await service.pack(p);
      expect(r.injectedDefenderDexHash).toBeNull();
      expect(r.injectedSoHash).toBeNull();
      expect(soInjector.injectSo).not.toHaveBeenCalled();
    });
  });

  describe('parseDexNumber', () => {
    it('classes.dex → 1, classes2.dex → 2, classes10.dex → 10', () => {
      const fn = (
        service as unknown as { parseDexNumber: (s: string) => number }
      ).parseDexNumber.bind(service);
      expect(fn('classes.dex')).toBe(1);
      expect(fn('classes2.dex')).toBe(2);
      expect(fn('classes10.dex')).toBe(10);
      expect(fn('not-a-dex')).toBe(1);
    });
  });

  describe('extractSignatureHash', () => {
    it('应解析 SHA-256 并去冒号小写', async () => {
      const fn = (
        service as unknown as { extractSignatureHash: (p: string) => Promise<string> }
      ).extractSignatureHash.bind(service);
      await expect(fn('/tmp/a.apk')).resolves.toBe('aabbcc');
    });

    it('无匹配应抛错', async () => {
      mockExecFile.mockImplementation((_c: string, _a: string[], _o: unknown, cb: unknown) => {
        (cb as (e: null, r: { stdout: string; stderr: string }) => void)(null, {
          stdout: 'no digest',
          stderr: '',
        });
        return undefined;
      });
      const fn = (
        service as unknown as { extractSignatureHash: (p: string) => Promise<string> }
      ).extractSignatureHash.bind(service);
      await expect(fn('/tmp/a.apk')).rejects.toThrow('extractSignatureHash failed');
    });
  });

  describe('parsePackageName', () => {
    it('应从 manifest ASCII 串提取包名', async () => {
      (fs.readFile as jest.Mock).mockResolvedValue(
        Buffer.from('\x00\x00com.test.app\x00\x00', 'latin1'),
      );
      const fn = (
        service as unknown as { parsePackageName: (a: string, w: string) => Promise<string> }
      ).parsePackageName.bind(service);
      await expect(fn('/tmp/a.apk', '/tmp/work')).resolves.toBe('com.test.app');
    });

    it('找不到包名应抛错', async () => {
      (fs.readFile as jest.Mock).mockResolvedValue(
        Buffer.from('\x00\x00zzz-only-no-dot\x00\x00', 'latin1'),
      );
      const fn = (
        service as unknown as { parsePackageName: (a: string, w: string) => Promise<string> }
      ).parsePackageName.bind(service);
      await expect(fn('/tmp/a.apk', '/tmp/work')).rejects.toThrow('parsePackageName failed');
    });
  });

  describe('resignApk', () => {
    it('成功应调用 apksigner sign', async () => {
      const fn = (service as unknown as { resignApk: (p: object) => Promise<void> }).resignApk.bind(
        service,
      );
      await expect(
        fn({
          apkPath: '/tmp/a.apk',
          keystorePath: '/tmp/k.jks',
          keystorePassword: 'p',
          keyAlias: 'a',
          keyPassword: 'p',
        }),
      ).resolves.toBeUndefined();
    });

    it('apksigner 失败应抛错', async () => {
      mockExecFile.mockImplementation((_c: string, _a: string[], _o: unknown, cb: unknown) => {
        (cb as (e: Error) => void)(new Error('sign boom'));
        return undefined;
      });
      const fn = (service as unknown as { resignApk: (p: object) => Promise<void> }).resignApk.bind(
        service,
      );
      await expect(
        fn({
          apkPath: '/tmp/a.apk',
          keystorePath: '/tmp/k.jks',
          keystorePassword: 'p',
          keyAlias: 'a',
          keyPassword: 'p',
        }),
      ).rejects.toThrow('resignApk failed');
    });
  });

  describe('generateIntegrityTables', () => {
    function fakeZip(entries: { fileName: string; crc32: number }[]) {
      const zip = new EventEmitter() as EventEmitter & { readEntry: () => void };
      let idx = 0;
      zip.readEntry = () => {
        if (idx < entries.length) {
          const e = entries[idx++];
          process.nextTick(() => zip.emit('entry', e));
        } else {
          process.nextTick(() => zip.emit('end'));
        }
      };
      return zip;
    }

    it('应收集 fileList + dex CRC,排除 META-INF 和 defender-config', async () => {
      (yauzl.open as unknown as jest.Mock).mockImplementation(
        (_p: string, _o: unknown, cb: (e: null, z: unknown) => void) => {
          cb(
            null,
            fakeZip([
              { fileName: 'classes.dex', crc32: 0x12345678 },
              { fileName: 'META-INF/CERT.SF', crc32: 0x1 },
              { fileName: 'assets/defender-config.json', crc32: 0x2 },
              { fileName: 'lib/arm64-v8a/lib.so', crc32: 0x3 },
            ]),
          );
        },
      );
      const fn = (
        service as unknown as {
          generateIntegrityTables: (
            p: string,
          ) => Promise<{ crcTable: string[]; fileList: string[] }>;
        }
      ).generateIntegrityTables.bind(service);
      const r = await fn('/tmp/a.apk');
      expect(r.fileList).toEqual(['classes.dex', 'lib/arm64-v8a/lib.so']);
      expect(r.crcTable).toEqual(['classes.dex:12345678']);
    });

    it('yauzl 打开失败应 reject', async () => {
      (yauzl.open as unknown as jest.Mock).mockImplementation(
        (_p: string, _o: unknown, cb: (e: Error) => void) => {
          cb(new Error('zip open boom'));
        },
      );
      const fn = (
        service as unknown as { generateIntegrityTables: (p: string) => Promise<unknown> }
      ).generateIntegrityTables.bind(service);
      await expect(fn('/tmp/a.apk')).rejects.toThrow('zip open boom');
    });
  });

  describe('cleanupWorkDir', () => {
    it('rm 失败应吞错(仅日志)', async () => {
      (fs.rm as jest.Mock).mockRejectedValue(new Error('rm boom'));
      const fn = (
        service as unknown as { cleanupWorkDir: (p: string) => Promise<void> }
      ).cleanupWorkDir.bind(service);
      await expect(fn('/tmp/work')).resolves.toBeUndefined();
    });
  });
});
