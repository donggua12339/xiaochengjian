import { Test } from '@nestjs/testing';
import { AuditLogOwnService } from './audit-log-own.service';
import { PrismaService } from '../prisma/prisma.service';

/**
 * AuditLogOwnService 单元测试(ADR 0077 §4)
 *
 * 覆盖:
 *  - record: 正常写入 / 可选字段为 null / 写入失败不抛错
 *  - listByDeveloper: 分页查询
 */
describe('AuditLogOwnService', () => {
  let service: AuditLogOwnService;
  let prisma: {
    auditLogOwn: { create: jest.Mock; findMany: jest.Mock };
  };

  beforeEach(async () => {
    prisma = {
      auditLogOwn: {
        create: jest.fn().mockResolvedValue(undefined),
        findMany: jest.fn().mockResolvedValue([]),
      },
    };
    const moduleRef = await Test.createTestingModule({
      providers: [
        AuditLogOwnService,
        { provide: PrismaService, useValue: prisma },
      ],
    }).compile();
    service = moduleRef.get(AuditLogOwnService);
  });

  it('record 正常应写入 auditLogOwn', async () => {
    await service.record({
      developerId: 'dev-1',
      appId: 'app-1',
      apkHash: 'sha256:abc',
      apkSize: 1024,
      packageName: 'com.test',
      signatureHash: 'sha256:def',
      check1Passed: true,
      check2Passed: true,
      check3Passed: true,
      status: 'SUCCESS',
      operation: 'ANALYZE',
      ip: '1.2.3.4',
    });
    expect(prisma.auditLogOwn.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        developerId: 'dev-1',
        appId: 'app-1',
        apkHash: 'sha256:abc',
        status: 'SUCCESS',
        operation: 'ANALYZE',
        rejectReason: null,
        reportPath: null,
        resignFromHash: null,
        resignToHash: null,
        keystoreFingerprint: null,
        userAgent: null,
      }),
    });
  });

  it('record RESIGN 操作应写入回填字段', async () => {
    await service.record({
      developerId: 'dev-1',
      appId: 'app-1',
      apkHash: 'old-hash',
      apkSize: 1024,
      packageName: 'com.test',
      signatureHash: 'sig-hash',
      check1Passed: true,
      check2Passed: true,
      check3Passed: true,
      status: 'RESIGN',
      operation: 'RESIGN',
      resignFromHash: 'old-hash',
      resignToHash: 'new-hash',
      keystoreFingerprint: 'ks-fp',
      ip: '1.2.3.4',
    });
    const call = prisma.auditLogOwn.create.mock.calls[0][0];
    expect(call.data.status).toBe('RESIGN');
    expect(call.data.resignFromHash).toBe('old-hash');
    expect(call.data.resignToHash).toBe('new-hash');
    expect(call.data.keystoreFingerprint).toBe('ks-fp');
  });

  it('record 写入失败不应抛错(不阻塞主流程)', async () => {
    prisma.auditLogOwn.create.mockRejectedValue(new Error('DB down'));
    await expect(
      service.record({
        developerId: 'dev-1',
        appId: 'app-1',
        apkHash: 'h',
        apkSize: 1,
        packageName: 'p',
        signatureHash: 's',
        check1Passed: true,
        check2Passed: true,
        check3Passed: true,
        status: 'SUCCESS',
        operation: 'ANALYZE',
        ip: '1.2.3.4',
      }),
    ).resolves.toBeUndefined();
  });

  it('listByDeveloper 应使用默认分页', async () => {
    prisma.auditLogOwn.findMany.mockResolvedValue([{ id: 'log-1' }]);
    const result = await service.listByDeveloper('dev-1');
    expect(prisma.auditLogOwn.findMany).toHaveBeenCalledWith({
      where: { developerId: 'dev-1' },
      orderBy: { createdAt: 'desc' },
      take: 50,
      skip: 0,
    });
    expect(result).toEqual([{ id: 'log-1' }]);
  });

  it('listByDeveloper 应支持自定义分页', async () => {
    await service.listByDeveloper('dev-1', { limit: 10, offset: 20 });
    expect(prisma.auditLogOwn.findMany).toHaveBeenCalledWith({
      where: { developerId: 'dev-1' },
      orderBy: { createdAt: 'desc' },
      take: 10,
      skip: 20,
    });
  });
});
