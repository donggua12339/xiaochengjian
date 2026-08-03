import { PackerLogService } from './packer-log.service';
import { PrismaService } from '../prisma/prisma.service';

describe('PackerLogService', () => {
  let service: PackerLogService;
  let prisma: { packerLog: { create: jest.Mock; findMany: jest.Mock } };

  beforeEach(() => {
    prisma = { packerLog: { create: jest.fn().mockResolvedValue(undefined), findMany: jest.fn() } };
    service = new PackerLogService(prisma as unknown as PrismaService);
  });

  const baseRecord = {
    developerId: 'dev-1',
    appId: 'app-1',
    apkHash: 'apkhash',
    apkSize: 1234,
    packageName: 'com.test',
    signatureHash: 'sighash',
    check1Passed: true,
    check2Passed: true,
    check3Passed: true,
    check4Passed: true,
    check5Passed: true,
    check6Passed: true,
    check7Passed: true,
    status: 'SUCCESS' as const,
    dexInjected: true,
    multidexHandled: false,
    ip: '1.2.3.4',
  };

  describe('record', () => {
    it('应写入 packer_log,缺省可选字段补 null', async () => {
      await service.record(baseRecord);
      expect(prisma.packerLog.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          developerId: 'dev-1',
          appId: 'app-1',
          status: 'SUCCESS',
          rejectReason: null,
          injectedDexHash: null,
          resignedApkHash: null,
          keystoreFingerprint: null,
          userAgent: null,
        }),
      });
    });

    it('可选字段传入应保留', async () => {
      await service.record({
        ...baseRecord,
        rejectReason: 'lock2 failed',
        injectedDexHash: 'dexhash',
        resignedApkHash: 'resigned',
        keystoreFingerprint: 'ksfp',
        userAgent: 'UA',
      });
      expect(prisma.packerLog.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          rejectReason: 'lock2 failed',
          injectedDexHash: 'dexhash',
          resignedApkHash: 'resigned',
          keystoreFingerprint: 'ksfp',
          userAgent: 'UA',
        }),
      });
    });

    it('prisma 写入失败应吞掉异常(不抛出)', async () => {
      prisma.packerLog.create.mockRejectedValue(new Error('db down'));
      await expect(service.record(baseRecord)).resolves.toBeUndefined();
    });
  });

  describe('listByDeveloper', () => {
    it('默认 limit=50 offset=0', async () => {
      prisma.packerLog.findMany.mockResolvedValue([]);
      await service.listByDeveloper('dev-1');
      expect(prisma.packerLog.findMany).toHaveBeenCalledWith({
        where: { developerId: 'dev-1' },
        orderBy: { createdAt: 'desc' },
        take: 50,
        skip: 0,
      });
    });

    it('自定义 limit/offset', async () => {
      prisma.packerLog.findMany.mockResolvedValue([]);
      await service.listByDeveloper('dev-1', { limit: 10, offset: 20 });
      expect(prisma.packerLog.findMany).toHaveBeenCalledWith(
        expect.objectContaining({ take: 10, skip: 20 }),
      );
    });
  });
});
