import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { AuditOwnService } from './audit-own.service';
import { AuditOwnValidators } from './audit-own-validators';
import { AuditLogOwnService } from './audit-log-own.service';
import { HardenerDetector } from './hardener/hardener-detector';
import { BangcleAdapter } from './hardener/bangcle.adapter';
import { PrismaService } from '../prisma/prisma.service';
import * as fs from 'fs/promises';
import { execFile } from 'child_process';

jest.mock('fs/promises');
jest.mock('child_process');

const mockExecFile = execFile as unknown as jest.Mock;

// manifest ASCII:包名 + 权限 + 安全属性
const MANIFEST = Buffer.from(
  '\x00com.test.app\x00android.permission.CAMERA\x00android.permission.INTERNET\x00debuggable\x00allowBackup\x00',
  'latin1',
);

describe('AuditOwnService(analyze 流 + 私有 helper)', () => {
  let service: AuditOwnService;
  let validators: Record<string, jest.Mock>;
  let auditLog: { record: jest.Mock };

  beforeEach(async () => {
    validators = {
      validatePackageName: jest
        .fn()
        .mockResolvedValue({ id: 'app-1', name: 'Test', signHashAllowList: ['h'] }),
      validateSignatureHash: jest.fn().mockResolvedValue(undefined),
      validateDirectoryIsolation: jest.fn().mockReturnValue(true),
    };
    auditLog = { record: jest.fn().mockResolvedValue(undefined) };

    (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
    (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
    (fs.rm as jest.Mock).mockResolvedValue(undefined);
    (fs.readFile as jest.Mock).mockResolvedValue(MANIFEST);
    mockExecFile.mockImplementation((_c: string, _a: string[], _o: unknown, cb: unknown) => {
      (cb as (e: null, r: { stdout: string; stderr: string }) => void)(null, {
        stdout: 'Signer #1 certificate SHA-256 digest: aa:bb:cc',
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
        { provide: HardenerDetector, useValue: { detect: jest.fn() } },
        { provide: BangcleAdapter, useValue: { generateReport: jest.fn() } },
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

  type Priv = Record<string, (...a: unknown[]) => unknown>;

  describe('parsePackageName(私有)', () => {
    const call = (p: string, w: string) =>
      (
        (service as unknown as Priv).parsePackageName as (a: string, b: string) => Promise<string>
      ).call(service, p, w);

    it('应提取最短包名', async () => {
      await expect(call('/tmp/a.apk', '/tmp/work')).resolves.toBe('com.test.app');
    });

    it('无包名应抛 MANIFEST_PARSE_FAILED', async () => {
      (fs.readFile as jest.Mock).mockResolvedValue(Buffer.from('\x00zzz\x00', 'latin1'));
      await expect(call('/tmp/a.apk', '/tmp/work')).rejects.toThrow('MANIFEST_PARSE_FAILED');
    });
  });

  describe('extractSignatureHash(私有)', () => {
    const call = (p: string) =>
      ((service as unknown as Priv).extractSignatureHash as (x: string) => Promise<string>).call(
        service,
        p,
      );

    it('应解析并去冒号小写', async () => {
      await expect(call('/tmp/a.apk')).resolves.toBe('aabbcc');
    });

    it('无 digest 应抛 SIGNATURE_EXTRACT_FAILED', async () => {
      mockExecFile.mockImplementation((_c: string, _a: string[], _o: unknown, cb: unknown) => {
        (cb as (e: null, r: { stdout: string; stderr: string }) => void)(null, {
          stdout: 'none',
          stderr: '',
        });
        return undefined;
      });
      await expect(call('/tmp/a.apk')).rejects.toThrow('SIGNATURE_EXTRACT_FAILED');
    });
  });

  describe('extractPermissions / extractSecurityFlags(私有)', () => {
    it('extractPermissions 应提取 android.permission.* 并去重', async () => {
      const fn = (service as unknown as Priv).extractPermissions as (
        w: string,
      ) => Promise<string[]>;
      const r = await fn.call(service, '/tmp/work');
      expect(r).toContain('android.permission.CAMERA');
      expect(r).toContain('android.permission.INTERNET');
    });

    it('extractPermissions 读取失败应返回空数组', async () => {
      (fs.readFile as jest.Mock).mockRejectedValue(new Error('ENOENT'));
      const fn = (service as unknown as Priv).extractPermissions as (
        w: string,
      ) => Promise<string[]>;
      await expect(fn.call(service, '/tmp/work')).resolves.toEqual([]);
      (fs.readFile as jest.Mock).mockResolvedValue(MANIFEST);
    });

    it('extractSecurityFlags 应检出 debuggable/allowBackup 声明', async () => {
      const fn = (service as unknown as Priv).extractSecurityFlags as (
        w: string,
      ) => Promise<unknown>;
      const r = (await fn.call(service, '/tmp/work')) as Record<string, unknown>;
      expect(r.debuggable).toBe('declared');
      expect(r.backupEnabled).toBe('declared');
      expect(r.cleartextTraffic).toBeNull();
    });

    it('extractSecurityFlags 读取失败应返回全 null', async () => {
      (fs.readFile as jest.Mock).mockRejectedValue(new Error('ENOENT'));
      const fn = (service as unknown as Priv).extractSecurityFlags as (
        w: string,
      ) => Promise<unknown>;
      await expect(fn.call(service, '/tmp/work')).resolves.toEqual({
        cleartextTraffic: null,
        debuggable: null,
        backupEnabled: null,
      });
      (fs.readFile as jest.Mock).mockResolvedValue(MANIFEST);
    });
  });

  describe('analyze(成功路径)', () => {
    it('应返回 report 含 apkInfo + manifest + securityFindings + 审计', async () => {
      const r = await service.analyze({
        developerId: 'dev-1',
        apkBuffer: Buffer.from('fake-apk'),
        originalName: 'a.apk',
        ip: '1.2.3.4',
      });
      expect(r.taskId).toMatch(/^audit-/);
      expect(r.report.apkInfo).toMatchObject({ packageName: 'com.test.app' });
      expect((r.report.manifest as { permissions: string[] }).permissions).toContain(
        'android.permission.CAMERA',
      );
      expect(auditLog.record).toHaveBeenCalledWith(expect.objectContaining({ status: 'SUCCESS' }));
    });
  });
});
