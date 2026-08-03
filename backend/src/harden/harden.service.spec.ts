import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { HardenService } from './harden.service';
import { PrismaService } from '../prisma/prisma.service';

describe('HardenService', () => {
  let service: HardenService;
  let prisma: {
    application: { findFirst: jest.Mock };
    hardenConfig: { findUnique: jest.Mock; upsert: jest.Mock };
    qualityReport: { create: jest.Mock; findMany: jest.Mock };
  };

  beforeEach(() => {
    prisma = {
      application: { findFirst: jest.fn() },
      hardenConfig: { findUnique: jest.fn(), upsert: jest.fn() },
      qualityReport: { create: jest.fn(), findMany: jest.fn() },
    };
    service = new HardenService(prisma as unknown as PrismaService);
  });

  const owned = () =>
    prisma.application.findFirst.mockResolvedValue({ id: 'app-1', developerId: 'dev-1' });

  describe('verifyOwnership(经各方法触发)', () => {
    it('非本人应用应抛 APP_NOT_OWNED', async () => {
      prisma.application.findFirst.mockResolvedValue(null);
      await expect(service.getConfig('dev-1', 'app-1')).rejects.toThrow(ForbiddenException);
    });
  });

  describe('getConfig', () => {
    it('无配置应返回默认配置', async () => {
      owned();
      prisma.hardenConfig.findUnique.mockResolvedValue(null);
      const cfg = await service.getConfig('dev-1', 'app-1');
      expect(cfg.appId).toBe('app-1');
      expect(cfg.encryptStrings).toBe(true);
      expect(cfg.strength).toBe('standard');
      expect(cfg.detectionModules).toHaveProperty('antiFrida');
    });

    it('有配置应原样返回', async () => {
      owned();
      const existing = { appId: 'app-1', encryptStrings: false, strength: 'paranoid' };
      prisma.hardenConfig.findUnique.mockResolvedValue(existing);
      await expect(service.getConfig('dev-1', 'app-1')).resolves.toEqual(existing);
    });
  });

  describe('upsertConfig', () => {
    it('应仅映射已定义字段并 upsert', async () => {
      owned();
      prisma.hardenConfig.upsert.mockResolvedValue({});
      await service.upsertConfig('dev-1', 'app-1', {
        encryptStrings: true,
        strength: 'aggressive',
      });
      expect(prisma.hardenConfig.upsert).toHaveBeenCalledWith({
        where: { appId: 'app-1' },
        create: expect.objectContaining({
          appId: 'app-1',
          developerId: 'dev-1',
          encryptStrings: true,
          strength: 'aggressive',
        }),
        update: expect.objectContaining({ encryptStrings: true, strength: 'aggressive' }),
      });
      // 未传字段不应出现在 update
      const update = prisma.hardenConfig.upsert.mock.calls[0][0].update;
      expect(update).not.toHaveProperty('vmpProtect');
    });

    it('全字段映射', async () => {
      owned();
      prisma.hardenConfig.upsert.mockResolvedValue({});
      await service.upsertConfig('dev-1', 'app-1', {
        encryptStrings: false,
        vmpProtect: true,
        segmentStrings: true,
        soEncrypt: false,
        detectionModules: { antiDebug: true },
        killAction: 'warn',
        weakThreshold: 50,
        delayMinMs: 100,
        delayMaxMs: 200,
        strength: 'basic',
      });
      const update = prisma.hardenConfig.upsert.mock.calls[0][0].update;
      expect(update).toEqual({
        encryptStrings: false,
        vmpProtect: true,
        segmentStrings: true,
        soEncrypt: false,
        detectionModules: { antiDebug: true },
        killAction: 'warn',
        weakThreshold: 50,
        delayMinMs: 100,
        delayMaxMs: 200,
        strength: 'basic',
      });
    });
  });

  describe('submitReport', () => {
    it('配置不存在应抛 HARDEN_CONFIG_NOT_FOUND', async () => {
      owned();
      prisma.hardenConfig.findUnique.mockResolvedValue(null);
      await expect(
        service.submitReport('dev-1', 'app-1', {
          overallScore: 80,
          grade: 'B',
          dimensions: {},
          raw: {},
        }),
      ).rejects.toThrow(NotFoundException);
    });

    it('成功应创建质量报告', async () => {
      owned();
      prisma.hardenConfig.findUnique.mockResolvedValue({ id: 'cfg-1' });
      prisma.qualityReport.create.mockResolvedValue({ id: 'r-1' });
      await service.submitReport('dev-1', 'app-1', {
        overallScore: 90,
        grade: 'A',
        dimensions: { d: 1 },
        raw: { r: 2 },
      });
      expect(prisma.qualityReport.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          appId: 'app-1',
          configId: 'cfg-1',
          overallScore: 90,
          grade: 'A',
        }),
      });
    });
  });

  describe('getReports', () => {
    it('默认 limit=10 倒序查询', async () => {
      owned();
      prisma.qualityReport.findMany.mockResolvedValue([]);
      await service.getReports('dev-1', 'app-1');
      expect(prisma.qualityReport.findMany).toHaveBeenCalledWith({
        where: { appId: 'app-1' },
        orderBy: { createdAt: 'desc' },
        take: 10,
      });
    });

    it('自定义 limit', async () => {
      owned();
      prisma.qualityReport.findMany.mockResolvedValue([]);
      await service.getReports('dev-1', 'app-1', 5);
      expect(prisma.qualityReport.findMany).toHaveBeenCalledWith(
        expect.objectContaining({ take: 5 }),
      );
    });
  });
});
