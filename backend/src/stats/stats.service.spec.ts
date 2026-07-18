import { Test } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { StatsService } from './stats.service';
import { TenantPrismaService } from '../tenant/tenant-prisma.service';

/**
 * StatsService 单元测试
 *
 * 覆盖:
 *  - appOverview: APP_NOT_FOUND / 正常(卡密分组/激活数/活跃设备/今日验证/失败率)
 *  - validationTrend: APP_NOT_FOUND / 正常(原生 SQL 聚合)
 *  - activationTrend: APP_NOT_FOUND / 正常(按天聚合激活数)
 *  - developerOverview: 正常(全局统计 + top 10 应用)
 */
describe('StatsService', () => {
  let service: StatsService;
  let tenantPrisma: { tx: jest.Mock };

  const developerId = 'dev-1';
  const appId = 'app-1';

  /** 构建 mock tx */
  function buildTx(opts: {
    application?: any | null;
    cardKeyGroupByStatus?: any[];
    cardKeyGroupByType?: any[];
    cardKeyCount?: number;
    deviceCount?: number;
    validationLogCount?: number;
    cardTemplateCount?: number;
    applicationList?: any[];
    queryRawResult?: any[];
  } = {}) {
    return {
      application: {
        findUnique: jest.fn().mockResolvedValue(opts.application === undefined ? { id: appId } : opts.application),
        findMany: jest.fn().mockResolvedValue(opts.applicationList ?? []),
        count: jest.fn().mockResolvedValue(opts.applicationList?.length ?? 0),
      },
      cardKey: {
        groupBy: jest.fn().mockImplementation(({ by }: { by: string[] }) => {
          if (by[0] === 'status') return opts.cardKeyGroupByStatus ?? [];
          if (by[0] === 'type') return opts.cardKeyGroupByType ?? [];
          return [];
        }),
        count: jest.fn().mockResolvedValue(opts.cardKeyCount ?? 0),
      },
      device: {
        count: jest.fn().mockResolvedValue(opts.deviceCount ?? 0),
      },
      validationLog: {
        count: jest.fn().mockResolvedValue(opts.validationLogCount ?? 0),
      },
      cardTemplate: {
        count: jest.fn().mockResolvedValue(opts.cardTemplateCount ?? 0),
      },
      $queryRaw: jest.fn().mockResolvedValue(opts.queryRawResult ?? []),
    };
  }

  function setTxMock(tx: any) {
    tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
      fn(tx),
    );
  }

  beforeEach(async () => {
    tenantPrisma = { tx: jest.fn() };
    const moduleRef = await Test.createTestingModule({
      providers: [
        StatsService,
        { provide: TenantPrismaService, useValue: tenantPrisma },
      ],
    }).compile();
    service = moduleRef.get(StatsService);
  });

  describe('appOverview', () => {
    it('APP 不存在应拒绝(APP_NOT_FOUND)', async () => {
      const tx = buildTx({ application: null });
      setTxMock(tx);
      await expect(service.appOverview(developerId, appId)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('正常应返回卡密/设备/验证统计', async () => {
      const tx = buildTx({
        cardKeyGroupByStatus: [
          { status: 'ACTIVE', _count: { id: 50 } },
          { status: 'DISABLED', _count: { id: 5 } },
        ],
        cardKeyGroupByType: [
          { type: 'MONTH', _count: { id: 30 } },
          { type: 'PERMANENT', _count: { id: 25 } },
        ],
        cardKeyCount: 30, // 已激活数
        deviceCount: 10,
        validationLogCount: 100,
      });
      setTxMock(tx);

      const result = await service.appOverview(developerId, appId);
      expect(result.cards.total).toBe(55); // 50 + 5
      expect(result.cards.byStatus).toEqual({ ACTIVE: 50, DISABLED: 5 });
      expect(result.cards.byType).toEqual({ MONTH: 30, PERMANENT: 25 });
      expect(result.cards.activated).toBe(30);
      expect(result.devices.total).toBe(10);
      expect(result.validations.today).toBe(100);
      expect(result.validations.todaySuccess).toBe(100); // mock 返回同一值
    });

    it('今日验证 0 时失败率应为 0(防除零)', async () => {
      const tx = buildTx({
        cardKeyGroupByStatus: [],
        cardKeyGroupByType: [],
        cardKeyCount: 0,
        deviceCount: 0,
        validationLogCount: 0,
      });
      setTxMock(tx);
      const result = await service.appOverview(developerId, appId);
      expect(result.validations.todayFailRate).toBe(0);
    });

    it('失败率应正确计算', async () => {
      // mock validationLog.count:第一次返回 100(总数),第二次返回 80(成功)
      let count = 0;
      const tx = buildTx({
        cardKeyGroupByStatus: [],
        cardKeyGroupByType: [],
        cardKeyCount: 0,
        deviceCount: 0,
      });
      tx.validationLog.count.mockImplementation(() => {
        count++;
        return Promise.resolve(count === 1 ? 100 : 80);
      });
      setTxMock(tx);
      const result = await service.appOverview(developerId, appId);
      // (100-80)/100 * 100 = 20
      expect(result.validations.todayFailRate).toBe(20);
    });
  });

  describe('validationTrend', () => {
    it('APP 不存在应拒绝', async () => {
      const tx = buildTx({ application: null });
      setTxMock(tx);
      await expect(service.validationTrend(developerId, appId, 7)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('正常应返回按天聚合的验证趋势', async () => {
      const tx = buildTx({
        queryRawResult: [
          { date: '2026-07-17', total: BigInt(100), success: BigInt(80), fail: BigInt(20) },
          { date: '2026-07-18', total: BigInt(50), success: BigInt(45), fail: BigInt(5) },
        ],
      });
      setTxMock(tx);

      const result = await service.validationTrend(developerId, appId, 7);
      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({ date: '2026-07-17', total: 100, success: 80, fail: 20 });
      expect(result[1]).toEqual({ date: '2026-07-18', total: 50, success: 45, fail: 5 });
    });

    it('空结果应返回空数组', async () => {
      const tx = buildTx({ queryRawResult: [] });
      setTxMock(tx);
      const result = await service.validationTrend(developerId, appId, 30);
      expect(result).toEqual([]);
    });
  });

  describe('activationTrend', () => {
    it('APP 不存在应拒绝', async () => {
      const tx = buildTx({ application: null });
      setTxMock(tx);
      await expect(service.activationTrend(developerId, appId, 7)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('正常应返回按天聚合的激活趋势', async () => {
      const tx = buildTx({
        queryRawResult: [
          { date: '2026-07-17', count: BigInt(15) },
          { date: '2026-07-18', count: BigInt(8) },
        ],
      });
      setTxMock(tx);

      const result = await service.activationTrend(developerId, appId, 7);
      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({ date: '2026-07-17', count: 15 });
      expect(result[1]).toEqual({ date: '2026-07-18', count: 8 });
    });
  });

  describe('developerOverview', () => {
    it('正常应返回全局统计 + top 10 应用', async () => {
      const tx = buildTx({
        cardKeyCount: 100,
        deviceCount: 30,
        cardTemplateCount: 5,
        applicationList: [
          {
            id: 'app-1',
            name: '应用1',
            packageName: 'com.xcj.app1',
            _count: { cardKeys: 50, devices: 15 },
          },
          {
            id: 'app-2',
            name: '应用2',
            packageName: 'com.xcj.app2',
            _count: { cardKeys: 50, devices: 15 },
          },
        ],
      });
      // application.count 返回应用数
      tx.application.count.mockResolvedValue(2);
      // validationLog.count 第一次返回最近 7 天验证数
      let vcount = 0;
      tx.validationLog.count.mockImplementation(() => {
        vcount++;
        return Promise.resolve(vcount === 1 ? 500 : 100); // 500 验证,100 激活
      });
      setTxMock(tx);

      const result = await service.developerOverview(developerId);
      expect(result.totals).toEqual({ apps: 2, cards: 100, devices: 30, templates: 5 });
      expect(result.recent7d.validations).toBe(500);
      expect(result.recent7d.activations).toBe(100);
      expect(result.topApps).toHaveLength(2);
      expect(result.topApps[0]).toEqual({
        id: 'app-1',
        name: '应用1',
        packageName: 'com.xcj.app1',
        cardsCount: 50,
        devicesCount: 15,
      });
    });

    it('无应用时应返回空 topApps', async () => {
      const tx = buildTx({
        cardKeyCount: 0,
        deviceCount: 0,
        cardTemplateCount: 0,
        applicationList: [],
      });
      tx.application.count.mockResolvedValue(0);
      setTxMock(tx);

      const result = await service.developerOverview(developerId);
      expect(result.totals).toEqual({ apps: 0, cards: 0, devices: 0, templates: 0 });
      expect(result.topApps).toEqual([]);
    });

    it('topApps 最多返回 10 个(take: 10)', async () => {
      const apps = Array.from({ length: 15 }, (_, i) => ({
        id: `app-${i}`,
        name: `应用${i}`,
        packageName: `com.xcj.app${i}`,
        _count: { cardKeys: 10, devices: 5 },
      }));
      const tx = buildTx({
        cardKeyCount: 0,
        deviceCount: 0,
        cardTemplateCount: 0,
        applicationList: apps,
      });
      tx.application.count.mockResolvedValue(15);
      setTxMock(tx);

      const result = await service.developerOverview(developerId);
      expect(result.topApps).toHaveLength(15); // findMany 返回 15 个
      expect(tx.application.findMany).toHaveBeenCalledWith(
        expect.objectContaining({ take: 10 }),
      );
    });
  });
});
