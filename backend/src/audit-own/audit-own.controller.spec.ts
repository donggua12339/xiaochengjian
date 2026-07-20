import { Test } from '@nestjs/testing';
import { BadRequestException } from '@nestjs/common';
import { AuditOwnController } from './audit-own.controller';
import { AuditOwnService } from './audit-own.service';
import { AuditLogOwnService } from './audit-log-own.service';

/**
 * AuditOwnController 单元测试(ADR 0077)
 *
 * 覆盖:
 *  - analyze: 缺 file / 正常调 service
 *  - resign: 缺 file / 缺 keystore / 缺凭证 / 正常
 *  - listLogs: 默认分页 / 自定义 / 非法 limit / 非法 offset
 */
describe('AuditOwnController', () => {
  let controller: AuditOwnController;
  let auditOwnService: jest.Mocked<AuditOwnService>;
  let auditLogOwnService: jest.Mocked<AuditLogOwnService>;

  beforeEach(async () => {
    auditOwnService = {
      analyze: jest.fn().mockResolvedValue({ taskId: 't-1', report: { foo: 'bar' } }),
      resign: jest.fn().mockResolvedValue({
        taskId: 't-2',
        resignedApk: Buffer.from('resigned'),
        newHash: 'newhash',
        oldHash: 'oldhash',
      }),
    } as unknown as jest.Mocked<AuditOwnService>;

    auditLogOwnService = {
      listByDeveloper: jest.fn().mockResolvedValue([]),
    } as unknown as jest.Mocked<AuditLogOwnService>;

    const moduleRef = await Test.createTestingModule({
      controllers: [AuditOwnController],
      providers: [
        { provide: AuditOwnService, useValue: auditOwnService },
        { provide: AuditLogOwnService, useValue: auditLogOwnService },
      ],
    }).compile();
    controller = moduleRef.get(AuditOwnController);
  });

  function makeReq(headers: Record<string, string> = {}) {
    return {
      headers,
      ip: '1.2.3.4',
    } as any;
  }

  describe('analyze', () => {
    it('缺 file 应抛 BadRequestException', async () => {
      await expect(
        controller.analyze('dev-1', makeReq(), 'test.apk', undefined as any),
      ).rejects.toThrow(BadRequestException);
    });

    it('正常应调 service.analyze 并返回 taskId + report', async () => {
      const file = { buffer: Buffer.from('apk'), originalname: 'test.apk' } as any;
      const result = await controller.analyze(
        'dev-1',
        makeReq({ 'x-forwarded-for': '5.6.7.8' }),
        'test.apk',
        file,
      );
      expect(auditOwnService.analyze).toHaveBeenCalledWith(
        expect.objectContaining({ developerId: 'dev-1', apkBuffer: file.buffer }),
      );
      expect(result.taskId).toBe('t-1');
      expect(result.report).toEqual({ foo: 'bar' });
    });

    it('originalName 缺失时用 file.originalname', async () => {
      const file = { buffer: Buffer.from('apk'), originalname: 'fallback.apk' } as any;
      await controller.analyze('dev-1', makeReq(), undefined as any, file);
      expect(auditOwnService.analyze).toHaveBeenCalledWith(
        expect.objectContaining({ originalName: 'fallback.apk' }),
      );
    });
  });

  describe('resign', () => {
    const validBody = {
      keystorePassword: 'pass',
      keyAlias: 'key0',
      keyPassword: 'pass',
    };

    it('缺 APK file 应抛 BadRequestException', async () => {
      await expect(
        controller.resign('dev-1', makeReq(), validBody, {} as any, undefined as any),
      ).rejects.toThrow(BadRequestException);
    });

    it('缺 keystore file 应抛 BadRequestException', async () => {
      const file = { buffer: Buffer.from('apk'), originalname: 'a.apk' } as any;
      await expect(
        controller.resign('dev-1', makeReq(), validBody, undefined as any, file),
      ).rejects.toThrow(BadRequestException);
    });

    it('缺凭证应抛 BadRequestException', async () => {
      const file = { buffer: Buffer.from('apk'), originalname: 'a.apk' } as any;
      const ks = { buffer: Buffer.from('ks') } as any;
      await expect(
        controller.resign(
          'dev-1',
          makeReq(),
          { keystorePassword: '', keyAlias: '', keyPassword: '' },
          ks,
          file,
        ),
      ).rejects.toThrow(BadRequestException);
    });

    it('正常应调 service.resign 返回 base64', async () => {
      const file = { buffer: Buffer.from('apk'), originalname: 'a.apk' } as any;
      const ks = { buffer: Buffer.from('ks') } as any;
      const result = await controller.resign('dev-1', makeReq(), validBody, ks, file);
      expect(auditOwnService.resign).toHaveBeenCalledWith(
        expect.objectContaining({ developerId: 'dev-1' }),
      );
      expect(result.taskId).toBe('t-2');
      expect(result.resignedApkBase64).toBe(Buffer.from('resigned').toString('base64'));
      expect(result.resignedApkSize).toBe(8);
    });
  });

  describe('listLogs', () => {
    it('默认分页(limit=50, offset=0)', async () => {
      await controller.listLogs('dev-1');
      expect(auditLogOwnService.listByDeveloper).toHaveBeenCalledWith('dev-1', {
        limit: 50,
        offset: 0,
      });
    });

    it('自定义分页', async () => {
      await controller.listLogs('dev-1', '10', '20');
      expect(auditLogOwnService.listByDeveloper).toHaveBeenCalledWith('dev-1', {
        limit: 10,
        offset: 20,
      });
    });

    it('limit 非法应抛 BadRequestException', async () => {
      await expect(controller.listLogs('dev-1', 'abc')).rejects.toThrow(BadRequestException);
    });

    it('limit < 1 应抛 BadRequestException', async () => {
      await expect(controller.listLogs('dev-1', '0')).rejects.toThrow(BadRequestException);
    });

    it('limit > 200 应抛 BadRequestException', async () => {
      await expect(controller.listLogs('dev-1', '201')).rejects.toThrow(BadRequestException);
    });

    it('offset 非法应抛 BadRequestException', async () => {
      await expect(controller.listLogs('dev-1', '10', 'abc')).rejects.toThrow(BadRequestException);
    });

    it('offset < 0 应抛 BadRequestException', async () => {
      await expect(controller.listLogs('dev-1', '10', '-1')).rejects.toThrow(BadRequestException);
    });
  });
});
