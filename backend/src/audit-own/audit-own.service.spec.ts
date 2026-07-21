import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import {
  BadRequestException,
  ForbiddenException,
  PayloadTooLargeException,
} from '@nestjs/common';
import * as crypto from 'crypto';
import { AuditOwnService } from './audit-own.service';
import { AuditOwnValidators } from './audit-own-validators';
import { AuditLogOwnService } from './audit-log-own.service';
import { HardenerDetector } from './hardener/hardener-detector';
import { BangcleAdapter } from './hardener/bangcle.adapter';
import { PrismaService } from '../prisma/prisma.service';

/**
 * AuditOwnService 单元测试(ADR 0077)
 *
 * 覆盖:
 *  - prepareApk: 大小限制 + SHA-256 hash + 隔离目录创建
 *  - runTripleCheck: 校验 1 失败 / 校验 2 失败 / 全通过
 *  - analyze: 成功路径(mock 三重校验 + 报告生成)
 *  - resign: keystore 缺失 / 三重校验失败 / 成功路径(含白名单更新)
 *
 * 注意:文件系统 + apksigner 调用通过 mock 或临时目录隔离,
 * 实际集成测试在生产部署后补(Dockerfile 装 build-tools)。
 */
describe('AuditOwnService', () => {
  let service: AuditOwnService;
  let validators: jest.Mocked<AuditOwnValidators>;
  let auditLog: jest.Mocked<AuditLogOwnService>;
  let prisma: { application: { update: jest.Mock } };
  let configService: { get: jest.Mock };
  let hardenerDetector: { detect: jest.Mock };
  let bangcleAdapter: { generateReport: jest.Mock };

  beforeEach(async () => {
    validators = {
      validatePackageName: jest.fn(),
      validateSignatureHash: jest.fn(),
      validateDirectoryIsolation: jest.fn().mockReturnValue(true),
    } as unknown as jest.Mocked<AuditOwnValidators>;

    auditLog = {
      record: jest.fn().mockResolvedValue(undefined),
      listByDeveloper: jest.fn().mockResolvedValue([]),
    } as unknown as jest.Mocked<AuditLogOwnService>;

    prisma = {
      application: { update: jest.fn().mockResolvedValue({}) },
    };

    hardenerDetector = {
      detect: jest.fn(),
    };

    bangcleAdapter = {
      generateReport: jest.fn().mockResolvedValue({
        soFiles: [],
        entryClass: null,
        signatures: { v1: true, v2: true, v3: true },
        suspiciousCalls: [],
        scanVersion: '1.0.0',
        scanTime: '2026-07-20T00:00:00Z',
      }),
    };

    configService = {
      get: jest.fn((key: string) => {
        const config: Record<string, unknown> = {
          auditMaxApkSizeMb: 200,
          auditTmpRoot: '/tmp/audit-test',
          apksignerPath: '/usr/bin/apksigner',
          auditReportRetentionHours: 24,
          auditMaxConcurrentPerDeveloper: 1,
          auditTimeoutSeconds: 1800,
        };
        return config[key];
      }),
    };

    const moduleRef = await Test.createTestingModule({
      providers: [
        AuditOwnService,
        { provide: AuditOwnValidators, useValue: validators },
        { provide: AuditLogOwnService, useValue: auditLog },
        { provide: PrismaService, useValue: prisma },
        { provide: HardenerDetector, useValue: hardenerDetector },
        { provide: BangcleAdapter, useValue: bangcleAdapter },
        {
          provide: ConfigService,
          useValue: configService,
        },
      ],
    }).compile();
    service = moduleRef.get(AuditOwnService);
  });

  describe('prepareApk', () => {
    it('APK 超大小限制应抛 PayloadTooLargeException', async () => {
      // 201MB buffer
      const bigBuffer = Buffer.alloc(201 * 1024 * 1024, 0);
      await expect(
        service.prepareApk({
          developerId: 'dev-1',
          apkBuffer: bigBuffer,
          originalName: 'big.apk',
          operation: 'ANALYZE',
        }),
      ).rejects.toThrow(PayloadTooLargeException);
    });

    it('正常应返回 taskId + workDir + apkHash + apkSize', async () => {
      const apkBuffer = Buffer.from('fake-apk-content');
      const result = await service.prepareApk({
        developerId: 'dev-1',
        apkBuffer,
        originalName: 'test.apk',
        operation: 'ANALYZE',
      });
      expect(result.taskId).toMatch(/^audit-/);
      expect(result.apkHash).toBe(
        crypto.createHash('sha256').update(apkBuffer).digest('hex'),
      );
      expect(result.apkSize).toBe(apkBuffer.length);
      expect(result.workDir).toMatch(/[/\\]audit-test[/\\]audit-/);
      expect(result.apkPath).toContain('test.apk');
    });
  });

  describe('resign - 输入校验', () => {
    it('keystore 为空应抛 BadRequestException', async () => {
      await expect(
        service.resign({
          developerId: 'dev-1',
          apkBuffer: Buffer.from('apk'),
          originalName: 'test.apk',
          keystoreBuffer: Buffer.alloc(0),
          keystorePassword: 'pass',
          keyAlias: 'alias',
          keyPassword: 'pass',
          ip: '1.2.3.4',
        }),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('runTripleCheck - 校验 1 失败', () => {
    it('包名不在白名单应抛 ForbiddenException + 记录 REJECTED 日志', async () => {
      validators.validatePackageName.mockRejectedValue(
        new ForbiddenException('APP_NOT_OWNED'),
      );

      // 准备一个最小的 APK buffer(让 prepareApk 通过)
      const apkBuffer = Buffer.from('fake-apk');

      // 用 service 内部的 prepareApk 准备,然后直接调 runTripleCheck
      const prepared = await service.prepareApk({
        developerId: 'dev-1',
        apkBuffer,
        originalName: 'test.apk',
        operation: 'ANALYZE',
      });

      // mock parsePackageName 返回一个包名(实际实现读 Manifest,这里通过 spy 替换)
      const parseSpy = jest.spyOn(
        service as unknown as { parsePackageName: (a: string, b: string) => Promise<string> },
        'parsePackageName',
      );
      parseSpy.mockResolvedValue('com.evil.app');

      await expect(
        service.runTripleCheck({
          developerId: 'dev-1',
          apkPath: prepared.apkPath,
          workDir: prepared.workDir,
          apkHash: prepared.apkHash,
          apkSize: prepared.apkSize,
          operation: 'ANALYZE',
          ip: '1.2.3.4',
        }),
      ).rejects.toThrow(ForbiddenException);

      expect(auditLog.record).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'REJECTED',
          rejectReason: 'APP_NOT_OWNED',
          check1Passed: false,
        }),
      );

      parseSpy.mockRestore();
    });
  });

  describe('runTripleCheck - 校验 2 失败', () => {
    it('签名 hash 不匹配应抛 ForbiddenException + 记录 REJECTED 日志', async () => {
      validators.validatePackageName.mockResolvedValue({
        id: 'app-1',
        name: 'Test',
        signHashAllowList: ['expected-hash'],
      });
      validators.validateSignatureHash.mockRejectedValue(
        new ForbiddenException('SIGNATURE_MISMATCH'),
      );

      const apkBuffer = Buffer.from('fake-apk');
      const prepared = await service.prepareApk({
        developerId: 'dev-1',
        apkBuffer,
        originalName: 'test.apk',
        operation: 'ANALYZE',
      });

      const parseSpy = jest.spyOn(
        service as unknown as { parsePackageName: (a: string, b: string) => Promise<string> },
        'parsePackageName',
      );
      parseSpy.mockResolvedValue('com.test.app');

      const sigSpy = jest.spyOn(
        service as unknown as { extractSignatureHash: (a: string) => Promise<string> },
        'extractSignatureHash',
      );
      sigSpy.mockResolvedValue('wrong-hash');

      await expect(
        service.runTripleCheck({
          developerId: 'dev-1',
          apkPath: prepared.apkPath,
          workDir: prepared.workDir,
          apkHash: prepared.apkHash,
          apkSize: prepared.apkSize,
          operation: 'ANALYZE',
          ip: '1.2.3.4',
        }),
      ).rejects.toThrow(ForbiddenException);

      expect(auditLog.record).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'REJECTED',
          rejectReason: 'SIGNATURE_MISMATCH',
          check1Passed: true,
          check2Passed: false,
        }),
      );

      parseSpy.mockRestore();
      sigSpy.mockRestore();
    });
  });

  describe('runTripleCheck - 全通过', () => {
    it('三重校验全通过应返回 app + packageName + signatureHash', async () => {
      validators.validatePackageName.mockResolvedValue({
        id: 'app-1',
        name: 'Test',
        signHashAllowList: ['sig-hash'],
      });
      validators.validateSignatureHash.mockResolvedValue(undefined);

      const apkBuffer = Buffer.from('fake-apk');
      const prepared = await service.prepareApk({
        developerId: 'dev-1',
        apkBuffer,
        originalName: 'test.apk',
        operation: 'ANALYZE',
      });

      const parseSpy = jest.spyOn(
        service as unknown as { parsePackageName: (a: string, b: string) => Promise<string> },
        'parsePackageName',
      );
      parseSpy.mockResolvedValue('com.test.app');

      const sigSpy = jest.spyOn(
        service as unknown as { extractSignatureHash: (a: string) => Promise<string> },
        'extractSignatureHash',
      );
      sigSpy.mockResolvedValue('sig-hash');

      const result = await service.runTripleCheck({
        developerId: 'dev-1',
        apkPath: prepared.apkPath,
        workDir: prepared.workDir,
        apkHash: prepared.apkHash,
        apkSize: prepared.apkSize,
        operation: 'ANALYZE',
        ip: '1.2.3.4',
      });

      expect(result.app.id).toBe('app-1');
      expect(result.packageName).toBe('com.test.app');
      expect(result.signatureHash).toBe('sig-hash');

      parseSpy.mockRestore();
      sigSpy.mockRestore();
    });
  });

  describe('analyze - 成功路径', () => {
    it('三重校验通过 + 报告生成 + 审计日志 SUCCESS', async () => {
      validators.validatePackageName.mockResolvedValue({
        id: 'app-1',
        name: 'Test',
        signHashAllowList: ['sig-hash'],
      });
      validators.validateSignatureHash.mockResolvedValue(undefined);

      const parseSpy = jest.spyOn(
        service as unknown as { parsePackageName: (a: string, b: string) => Promise<string> },
        'parsePackageName',
      );
      parseSpy.mockResolvedValue('com.test.app');

      const sigSpy = jest.spyOn(
        service as unknown as { extractSignatureHash: (a: string) => Promise<string> },
        'extractSignatureHash',
      );
      sigSpy.mockResolvedValue('sig-hash');

      const reportSpy = jest.spyOn(
        service as unknown as {
          generateReport: (p: unknown) => Promise<Record<string, unknown>>;
        },
        'generateReport',
      );
      reportSpy.mockResolvedValue({ taskId: 't-1', apkInfo: { packageName: 'com.test.app' } });

      const result = await service.analyze({
        developerId: 'dev-1',
        apkBuffer: Buffer.from('fake-apk'),
        originalName: 'test.apk',
        ip: '1.2.3.4',
      });

      expect(result.taskId).toMatch(/^audit-/);
      expect(result.report).toBeDefined();
      expect(auditLog.record).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'SUCCESS',
          operation: 'ANALYZE',
          appId: 'app-1',
        }),
      );

      parseSpy.mockRestore();
      sigSpy.mockRestore();
      reportSpy.mockRestore();
    });
  });

  describe('resign - 成功路径(mock execFileAsync 私有方法)', () => {
    it('三重校验通过 + apksigner 重签 + 白名单更新 + 审计日志 RESIGN', async () => {
      validators.validatePackageName.mockResolvedValue({
        id: 'app-1',
        name: 'Test',
        signHashAllowList: ['old-hash'],
      });
      validators.validateSignatureHash.mockResolvedValue(undefined);

      const parseSpy = jest.spyOn(
        service as unknown as { parsePackageName: (a: string, b: string) => Promise<string> },
        'parsePackageName',
      );
      parseSpy.mockResolvedValue('com.test.app');

      const sigSpy = jest.spyOn(
        service as unknown as { extractSignatureHash: (a: string) => Promise<string> },
        'extractSignatureHash',
      );
      sigSpy.mockResolvedValue('old-hash');

      // mock execFileAsync 私有方法(已重构为可 mock)
      const execSpy = jest.spyOn(
        service as unknown as { execFileAsync: (...args: unknown[]) => Promise<{ stdout: string; stderr: string }> },
        'execFileAsync',
      );
      execSpy.mockResolvedValue({ stdout: '', stderr: '' });

      // mock fs.copyFile + fs.readFile(让 resign 流程跑通)
      const fs = require('fs/promises');
      const copySpy = jest.spyOn(fs, 'copyFile').mockResolvedValue(undefined);
      // apksigner --out resignedPath,service 后续 readFile 读它
      // 让 readFile 返回固定内容(模拟 apksigner 已写出)
      const readSpy = jest.spyOn(fs, 'readFile').mockResolvedValue(Buffer.from('resigned-apk-content'));
      const writeSpy = jest.spyOn(fs, 'writeFile').mockResolvedValue(undefined);
      const rmSpy = jest.spyOn(fs, 'rm').mockResolvedValue(undefined);

      const result = await service.resign({
        developerId: 'dev-1',
        apkBuffer: Buffer.from('fake-apk'),
        originalName: 'test.apk',
        keystoreBuffer: Buffer.from('keystore'),
        keystorePassword: 'pass',
        keyAlias: 'key0',
        keyPassword: 'pass',
        ip: '1.2.3.4',
      });

      expect(result.taskId).toMatch(/^audit-/);
      expect(result.oldHash).toBeTruthy();
      expect(result.newHash).toBeTruthy();
      expect(result.newHash).not.toBe(result.oldHash);
      expect(prisma.application.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'app-1' },
          data: expect.objectContaining({
            signHashAllowList: { push: result.newHash },
          }),
        }),
      );
      expect(auditLog.record).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'RESIGN',
          operation: 'RESIGN',
          appId: 'app-1',
          resignFromHash: result.oldHash,
          resignToHash: result.newHash,
        }),
      );
      // 隔离目录应被清理
      expect(rmSpy).toHaveBeenCalled();

      parseSpy.mockRestore();
      sigSpy.mockRestore();
      execSpy.mockRestore();
      copySpy.mockRestore();
      readSpy.mockRestore();
      writeSpy.mockRestore();
      rmSpy.mockRestore();
    });

    it('apksigner 失败应抛错 + 不更新白名单 + 仍清理目录', async () => {
      validators.validatePackageName.mockResolvedValue({
        id: 'app-1',
        name: 'Test',
        signHashAllowList: ['old-hash'],
      });
      validators.validateSignatureHash.mockResolvedValue(undefined);

      const parseSpy = jest.spyOn(
        service as unknown as { parsePackageName: (a: string, b: string) => Promise<string> },
        'parsePackageName',
      );
      parseSpy.mockResolvedValue('com.test.app');

      const sigSpy = jest.spyOn(
        service as unknown as { extractSignatureHash: (a: string) => Promise<string> },
        'extractSignatureHash',
      );
      sigSpy.mockResolvedValue('old-hash');

      const execSpy = jest.spyOn(
        service as unknown as { execFileAsync: (...args: unknown[]) => Promise<{ stdout: string; stderr: string }> },
        'execFileAsync',
      );
      execSpy.mockRejectedValue(new Error('apksigner failed'));

      const fs = require('fs/promises');
      const copySpy = jest.spyOn(fs, 'copyFile').mockResolvedValue(undefined);
      const writeSpy = jest.spyOn(fs, 'writeFile').mockResolvedValue(undefined);
      const rmSpy = jest.spyOn(fs, 'rm').mockResolvedValue(undefined);

      await expect(
        service.resign({
          developerId: 'dev-1',
          apkBuffer: Buffer.from('fake-apk'),
          originalName: 'test.apk',
          keystoreBuffer: Buffer.from('keystore'),
          keystorePassword: 'pass',
          keyAlias: 'key0',
          keyPassword: 'pass',
          ip: '1.2.3.4',
        }),
      ).rejects.toThrow('apksigner failed');

      expect(prisma.application.update).not.toHaveBeenCalled();
      expect(rmSpy).toHaveBeenCalled();

      parseSpy.mockRestore();
      sigSpy.mockRestore();
      execSpy.mockRestore();
      copySpy.mockRestore();
      writeSpy.mockRestore();
      rmSpy.mockRestore();
    });
  });

  describe('analyzeBangcle - 梆梆加固自检(ADR 0078)', () => {
    it('三重校验通过 + 检测到梆梆 + 生成报告 + 审计日志 SUCCESS', async () => {
      validators.validatePackageName.mockResolvedValue({
        id: 'app-1',
        name: 'Test',
        signHashAllowList: ['sig-hash'],
      });
      validators.validateSignatureHash.mockResolvedValue(undefined);

      const parseSpy = jest.spyOn(
        service as unknown as { parsePackageName: (a: string, b: string) => Promise<string> },
        'parsePackageName',
      );
      parseSpy.mockResolvedValue('com.test.app');

      const sigSpy = jest.spyOn(
        service as unknown as { extractSignatureHash: (a: string) => Promise<string> },
        'extractSignatureHash',
      );
      sigSpy.mockResolvedValue('sig-hash');

      // mock listApkEntries + getSignatureStatus
      const listSpy = jest.spyOn(
        service as unknown as { listApkEntries: (a: string) => Promise<string[]> },
        'listApkEntries',
      );
      listSpy.mockResolvedValue(['lib/arm64-v8a/libSecShell.so', 'classes.dex']);

      const sigStatusSpy = jest.spyOn(
        service as unknown as {
          getSignatureStatus: (a: string) => Promise<{ v1: boolean; v2: boolean; v3: boolean }>;
        },
        'getSignatureStatus',
      );
      sigStatusSpy.mockResolvedValue({ v1: true, v2: true, v3: false });

      // 锁 A:检测到梆梆
      hardenerDetector.detect.mockReturnValue({
        hardener: 'bangcle',
        evidence: ['so: lib/arm64-v8a/libSecShell.so'],
      });

      const result = await service.analyzeHardener({
        developerId: 'dev-1',
        apkBuffer: Buffer.from('fake-apk'),
        originalName: 'test.apk',
        ip: '1.2.3.4',
        hardener: 'bangcle',
      });

      expect(result.taskId).toMatch(/^audit-/);
      expect(result.report.hardener).toBe('bangcle');
      expect(bangcleAdapter.generateReport).toHaveBeenCalledWith(
        expect.objectContaining({
          apkEntries: ['lib/arm64-v8a/libSecShell.so', 'classes.dex'],
        }),
      );
      expect(auditLog.record).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'SUCCESS',
          operation: 'ANALYZE',
          appId: 'app-1',
        }),
      );

      parseSpy.mockRestore();
      sigSpy.mockRestore();
      listSpy.mockRestore();
      sigStatusSpy.mockRestore();
    });

    it('检测到非梆梆加固应抛 UNSUPPORTED_HARDENER(detector 内部抛)', async () => {
      validators.validatePackageName.mockResolvedValue({
        id: 'app-1',
        name: 'Test',
        signHashAllowList: ['sig-hash'],
      });
      validators.validateSignatureHash.mockResolvedValue(undefined);

      const parseSpy = jest.spyOn(
        service as unknown as { parsePackageName: (a: string, b: string) => Promise<string> },
        'parsePackageName',
      );
      parseSpy.mockResolvedValue('com.test.app');

      const sigSpy = jest.spyOn(
        service as unknown as { extractSignatureHash: (a: string) => Promise<string> },
        'extractSignatureHash',
      );
      sigSpy.mockResolvedValue('sig-hash');

      const listSpy = jest.spyOn(
        service as unknown as { listApkEntries: (a: string) => Promise<string[]> },
        'listApkEntries',
      );
      listSpy.mockResolvedValue(['lib/arm64-v8a/libjiagu.so']);

      // 锁 A:检测到 360 抛 UNSUPPORTED_HARDENER
      hardenerDetector.detect.mockImplementation(() => {
        throw new ForbiddenException('UNSUPPORTED_HARDENER');
      });

      await expect(
        service.analyzeHardener({
          developerId: 'dev-1',
          apkBuffer: Buffer.from('fake-apk'),
          originalName: 'test.apk',
          ip: '1.2.3.4',
          hardener: 'bangcle',
        }),
      ).rejects.toThrow(ForbiddenException);

      expect(bangcleAdapter.generateReport).not.toHaveBeenCalled();

      parseSpy.mockRestore();
      sigSpy.mockRestore();
      listSpy.mockRestore();
    });

    it('APK 无梆梆加固特征应抛 HARDENER_NOT_DETECTED', async () => {
      validators.validatePackageName.mockResolvedValue({
        id: 'app-1',
        name: 'Test',
        signHashAllowList: ['sig-hash'],
      });
      validators.validateSignatureHash.mockResolvedValue(undefined);

      const parseSpy = jest.spyOn(
        service as unknown as { parsePackageName: (a: string, b: string) => Promise<string> },
        'parsePackageName',
      );
      parseSpy.mockResolvedValue('com.test.app');

      const sigSpy = jest.spyOn(
        service as unknown as { extractSignatureHash: (a: string) => Promise<string> },
        'extractSignatureHash',
      );
      sigSpy.mockResolvedValue('sig-hash');

      const listSpy = jest.spyOn(
        service as unknown as { listApkEntries: (a: string) => Promise<string[]> },
        'listApkEntries',
      );
      listSpy.mockResolvedValue(['classes.dex', 'AndroidManifest.xml']);

      // 无加固特征
      hardenerDetector.detect.mockReturnValue({ hardener: null });

      await expect(
        service.analyzeHardener({
          developerId: 'dev-1',
          apkBuffer: Buffer.from('fake-apk'),
          originalName: 'test.apk',
          ip: '1.2.3.4',
          hardener: 'bangcle',
        }),
      ).rejects.toThrow('HARDENER_NOT_DETECTED');

      expect(bangcleAdapter.generateReport).not.toHaveBeenCalled();

      parseSpy.mockRestore();
      sigSpy.mockRestore();
      listSpy.mockRestore();
    });

    it('三重校验失败应抛错 + 不调 detector', async () => {
      validators.validatePackageName.mockRejectedValue(
        new ForbiddenException('APP_NOT_OWNED'),
      );

      const parseSpy = jest.spyOn(
        service as unknown as { parsePackageName: (a: string, b: string) => Promise<string> },
        'parsePackageName',
      );
      parseSpy.mockResolvedValue('com.evil.app');

      await expect(
        service.analyzeHardener({
          developerId: 'dev-1',
          apkBuffer: Buffer.from('fake-apk'),
          originalName: 'test.apk',
          ip: '1.2.3.4',
          hardener: 'bangcle',
        }),
      ).rejects.toThrow(ForbiddenException);

      expect(hardenerDetector.detect).not.toHaveBeenCalled();
      expect(bangcleAdapter.generateReport).not.toHaveBeenCalled();

      parseSpy.mockRestore();
    });
  });
});
