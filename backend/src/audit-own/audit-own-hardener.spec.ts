import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { BadRequestException } from '@nestjs/common';
import { EventEmitter } from 'events';
import { Readable } from 'stream';
import { AuditOwnService } from './audit-own.service';
import { AuditOwnValidators } from './audit-own-validators';
import { AuditLogOwnService } from './audit-log-own.service';
import { HardenerDetector } from './hardener/hardener-detector';
import { BangcleAdapter } from './hardener/bangcle.adapter';
import { PrismaService } from '../prisma/prisma.service';
import * as fs from 'fs/promises';
import { execFile } from 'child_process';
import * as yauzl from 'yauzl';

jest.mock('fs/promises');
jest.mock('child_process');
jest.mock('yauzl');

const mockExecFile = execFile as unknown as jest.Mock;

type Zip = EventEmitter & {
  readEntry: () => void;
  openReadStream?: (e: unknown, cb: unknown) => void;
};

function fakeZip(
  entries: { fileName: string; crc32?: number }[],
  withStream = false,
  readError = false,
): Zip {
  const zip = new EventEmitter() as Zip;
  let idx = 0;
  zip.readEntry = () => {
    if (idx < entries.length) {
      const e = entries[idx++];
      process.nextTick(() => zip.emit('entry', e));
    } else {
      process.nextTick(() => zip.emit('end'));
    }
  };
  if (withStream) {
    zip.openReadStream = (_e: unknown, cb: unknown) => {
      if (readError) {
        process.nextTick(() => (cb as (err: Error) => void)(new Error('read stream boom')));
        return;
      }
      const s = new Readable();
      s.push('content');
      s.push(null);
      process.nextTick(() => (cb as (err: null, stream: Readable) => void)(null, s));
    };
  }
  return zip;
}

describe('AuditOwnService(hardener/私有方法)', () => {
  let service: AuditOwnService;
  let validators: Record<string, jest.Mock>;
  let auditLog: { record: jest.Mock };
  let hardenerDetector: { detect: jest.Mock };
  let bangcleAdapter: { generateReport: jest.Mock };

  beforeEach(async () => {
    validators = {
      validatePackageName: jest
        .fn()
        .mockResolvedValue({ id: 'app-1', name: 'Test', signHashAllowList: ['h'] }),
      validateSignatureHash: jest.fn().mockResolvedValue(undefined),
      validateDirectoryIsolation: jest.fn().mockReturnValue(true),
    };
    auditLog = { record: jest.fn().mockResolvedValue(undefined) };
    hardenerDetector = { detect: jest.fn().mockReturnValue({ hardener: 'bangcle' }) };
    bangcleAdapter = {
      generateReport: jest.fn().mockResolvedValue({ soFiles: [], scanVersion: '1.0.0' }),
    };

    (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
    (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
    (fs.rm as jest.Mock).mockResolvedValue(undefined);
    // manifest 路径返回带包名的 buffer(供 parsePackageName 提取),其余返回普通 buffer
    (fs.readFile as jest.Mock).mockImplementation((p: string) => {
      if (String(p).endsWith('AndroidManifest.xml')) {
        return Promise.resolve(Buffer.from('\x00\x00com.test.app\x00\x00', 'latin1'));
      }
      return Promise.resolve(Buffer.from('x'));
    });
    // execFile 默认返回 apksigner verify 输出(含 SHA-256 + v1/v2/v3)
    mockExecFile.mockImplementation((_c: string, _a: string[], _o: unknown, cb: unknown) => {
      (cb as (e: null, r: { stdout: string; stderr: string }) => void)(null, {
        stdout:
          'SHA-256 digest: aa:bb\nv1 scheme (APK Signature Scheme v1): true\nv2 scheme (APK Signature Scheme v2): true\nv3 scheme (APK Signature Scheme v3): false',
        stderr: '',
      });
      return undefined;
    });

    const moduleRef = await Test.createTestingModule({
      providers: [
        AuditOwnService,
        { provide: AuditOwnValidators, useValue: validators },
        { provide: AuditLogOwnService, useValue: auditLog },
        {
          provide: PrismaService,
          useValue: { application: { update: jest.fn().mockResolvedValue({}) } },
        },
        { provide: HardenerDetector, useValue: hardenerDetector },
        { provide: BangcleAdapter, useValue: bangcleAdapter },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn(
              (k: string) =>
                ({
                  auditMaxApkSizeMb: 200,
                  auditTmpRoot: '/tmp/audit',
                  apksignerPath: '/usr/bin/apksigner',
                })[k],
            ),
          },
        },
      ],
    }).compile();
    service = moduleRef.get(AuditOwnService);
  });

  const baseParams = () => ({
    developerId: 'dev-1',
    apkBuffer: Buffer.from('fake-apk'),
    originalName: 'a.apk',
    ip: '1.2.3.4',
    hardener: 'bangcle' as const,
  });

  describe('analyzeHardener', () => {
    it('厂商匹配应生成完整性报告 + 审计', async () => {
      (yauzl.open as unknown as jest.Mock).mockImplementation(
        (_p: string, _o: unknown, cb: (e: null, z: Zip) => void) =>
          cb(
            null,
            fakeZip([{ fileName: 'classes.dex' }, { fileName: 'lib/arm64-v8a/libSecShell.so' }]),
          ),
      );
      const r = await service.analyzeHardener(baseParams());
      expect(r.taskId).toMatch(/^audit-/);
      expect(r.report.hardener).toBe('bangcle');
      expect(r.report.hardenerReport).toBeDefined();
      expect(bangcleAdapter.generateReport).toHaveBeenCalled();
      expect(auditLog.record).toHaveBeenCalledWith(expect.objectContaining({ status: 'SUCCESS' }));
    });

    it('厂商不匹配应抛 HARDENER_NOT_DETECTED', async () => {
      hardenerDetector.detect.mockReturnValue({ hardener: 'legu' });
      (yauzl.open as unknown as jest.Mock).mockImplementation(
        (_p: string, _o: unknown, cb: (e: null, z: Zip) => void) =>
          cb(null, fakeZip([{ fileName: 'classes.dex' }])),
      );
      await expect(service.analyzeHardener(baseParams())).rejects.toThrow('HARDENER_NOT_DETECTED');
    });

    it('未检测到加固应抛 HARDENER_NOT_DETECTED', async () => {
      hardenerDetector.detect.mockReturnValue({ hardener: null });
      (yauzl.open as unknown as jest.Mock).mockImplementation(
        (_p: string, _o: unknown, cb: (e: null, z: Zip) => void) =>
          cb(null, fakeZip([{ fileName: 'classes.dex' }])),
      );
      await expect(service.analyzeHardener(baseParams())).rejects.toThrow(BadRequestException);
    });
  });

  describe('listApkEntries(私有)', () => {
    const call = (p: string) =>
      (
        (service as unknown as { listApkEntries: (x: string) => Promise<string[]> })
          .listApkEntries as (x: string) => Promise<string[]>
      ).call(service, p);

    it('应返回 entry 列表', async () => {
      (yauzl.open as unknown as jest.Mock).mockImplementation(
        (_p: string, _o: unknown, cb: (e: null, z: Zip) => void) =>
          cb(null, fakeZip([{ fileName: 'classes.dex' }, { fileName: 'res/a.png' }])),
      );
      await expect(call('/tmp/a.apk')).resolves.toEqual(['classes.dex', 'res/a.png']);
    });

    it('yauzl 打开失败应返回空数组', async () => {
      (yauzl.open as unknown as jest.Mock).mockImplementation(
        (_p: string, _o: unknown, cb: (e: Error) => void) => cb(new Error('open boom')),
      );
      await expect(call('/tmp/a.apk')).resolves.toEqual([]);
    });
  });

  describe('getSignatureStatus(私有)', () => {
    const call = (p: string) =>
      (
        (service as unknown as { getSignatureStatus: (x: string) => Promise<unknown> })
          .getSignatureStatus as (x: string) => Promise<unknown>
      ).call(service, p);

    it('应解析 v1/v2/v3 状态', async () => {
      await expect(call('/tmp/a.apk')).resolves.toEqual({ v1: true, v2: true, v3: false });
    });

    it('apksigner 失败应返回全 false', async () => {
      mockExecFile.mockImplementation((_c: string, _a: string[], _o: unknown, cb: unknown) => {
        (cb as (e: Error) => void)(new Error('verify boom'));
        return undefined;
      });
      await expect(call('/tmp/a.apk')).resolves.toEqual({ v1: false, v2: false, v3: false });
    });
  });

  describe('computeNonMetaInfHash(私有)', () => {
    const call = (p: string) =>
      (
        (service as unknown as { computeNonMetaInfHash: (x: string) => Promise<string> })
          .computeNonMetaInfHash as (x: string) => Promise<string>
      ).call(service, p);

    it('应累加非 META-INF entry 内容 hash', async () => {
      (yauzl.open as unknown as jest.Mock).mockImplementation(
        (_p: string, _o: unknown, cb: (e: null, z: Zip) => void) =>
          cb(null, fakeZip([{ fileName: 'classes.dex' }, { fileName: 'META-INF/CERT.SF' }], true)),
      );
      const h = await call('/tmp/a.apk');
      expect(h).toMatch(/^[0-9a-f]{64}$/);
    });

    it('yauzl 打开失败应 reject', async () => {
      (yauzl.open as unknown as jest.Mock).mockImplementation(
        (_p: string, _o: unknown, cb: (e: Error) => void) => cb(new Error('hash open boom')),
      );
      await expect(call('/tmp/a.apk')).rejects.toThrow('hash open boom');
    });

    it('openReadStream 失败应 reject', async () => {
      (yauzl.open as unknown as jest.Mock).mockImplementation(
        (_p: string, _o: unknown, cb: (e: null, z: Zip) => void) =>
          cb(null, fakeZip([{ fileName: 'classes.dex' }], true, true)),
      );
      await expect(call('/tmp/a.apk')).rejects.toThrow('read stream boom');
    });
  });

  describe('resign - RESIGN_CONTENT_CHANGED', () => {
    it('重签改了非 META-INF 内容应抛 RESIGN_CONTENT_CHANGED', async () => {
      // computeNonMetaInfHash 前后返回不同值 → 触发 RESIGN_CONTENT_CHANGED
      const hashSpy = jest
        .spyOn(
          service as unknown as { computeNonMetaInfHash: (p: string) => Promise<string> },
          'computeNonMetaInfHash',
        )
        .mockResolvedValueOnce('pre-hash')
        .mockResolvedValueOnce('post-hash-different');

      await expect(
        service.resign({
          developerId: 'dev-1',
          apkBuffer: Buffer.from('fake-apk'),
          originalName: 'a.apk',
          keystoreBuffer: Buffer.from('keystore'),
          keystorePassword: 'p',
          keyAlias: 'a',
          keyPassword: 'p',
          ip: '1.2.3.4',
        }),
      ).rejects.toThrow('RESIGN_CONTENT_CHANGED');
      hashSpy.mockRestore();
    });
  });
});
