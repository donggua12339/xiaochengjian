import { Test } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { DeviceService } from './device.service';
import { TenantPrismaService } from '../tenant/tenant-prisma.service';

/**
 * DeviceService 单元测试
 *
 * 覆盖:
 *  - list: 分页 + boundCardsCount 聚合 + totalPages 边界
 *  - getById: 正常 / DEVICE_NOT_FOUND
 *  - unbindAll: 正常 / DEVICE_NOT_FOUND + 返回 unboundCount
 */
describe('DeviceService', () => {
  let service: DeviceService;
  let tenantPrisma: { tx: jest.Mock };

  const developerId = 'dev-1';
  const appId = 'app-1';

  function buildTx(opts: { device?: any[]; deletedCount?: number } = {}) {
    return {
      device: {
        findMany: jest.fn().mockResolvedValue(opts.device ?? []),
        findFirst: jest.fn().mockResolvedValue(opts.device?.[0] ?? null),
        count: jest.fn().mockResolvedValue(opts.device?.length ?? 0),
      },
      deviceBinding: {
        deleteMany: jest.fn().mockResolvedValue({ count: opts.deletedCount ?? 0 }),
      },
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
        DeviceService,
        { provide: TenantPrismaService, useValue: tenantPrisma },
      ],
    }).compile();
    service = moduleRef.get(DeviceService);
  });

  describe('list', () => {
    it('应返回分页结构 + boundCardsCount', async () => {
      const devices = [
        {
          id: 'd1',
          appId,
          machineId: 'm1',
          deviceBindings: [{ id: 'b1' }, { id: 'b2' }],
          lastSeenAt: new Date(),
        },
      ];
      const tx = buildTx({ device: devices });
      setTxMock(tx);

      const result = await service.list(developerId, appId, { page: 1, pageSize: 20 });
      expect(result.items).toHaveLength(1);
      expect(result.items[0].boundCardsCount).toBe(2);
      expect(result.total).toBe(1);
      expect(result.totalPages).toBe(1);
    });

    it('total=0 时 totalPages 应为 1', async () => {
      const tx = buildTx({ device: [] });
      setTxMock(tx);
      const result = await service.list(developerId, appId, { page: 1, pageSize: 20 });
      expect(result.totalPages).toBe(1);
    });

    it('分页参数应透传到 findMany', async () => {
      const tx = buildTx({ device: [] });
      setTxMock(tx);
      await service.list(developerId, appId, { page: 3, pageSize: 50 });
      expect(tx.device.findMany).toHaveBeenCalledWith(
        expect.objectContaining({ skip: 100, take: 50 }),
      );
    });
  });

  describe('getById', () => {
    it('正常返回设备详情(含绑定卡密)', async () => {
      const device = {
        id: 'd1',
        appId,
        machineId: 'm1',
        deviceBindings: [
          {
            id: 'b1',
            cardKey: { id: 'c1', type: 'MONTH', status: 'ACTIVE', cardKeyPrefix: 'ABCD' },
          },
        ],
      };
      const tx = buildTx({ device: [device] });
      setTxMock(tx);

      const result = await service.getById(developerId, appId, 'd1');
      expect(result.id).toBe('d1');
      expect(result.deviceBindings[0].cardKey.type).toBe('MONTH');
    });

    it('设备不存在应拒绝(DEVICE_NOT_FOUND)', async () => {
      const tx = buildTx();
      setTxMock(tx);
      await expect(service.getById(developerId, appId, 'd1')).rejects.toThrow(
        NotFoundException,
      );
    });

    it('appId 不匹配应拒绝(通过 findFirst where 过滤)', async () => {
      const tx = buildTx(); // findFirst 返回 null
      setTxMock(tx);
      await expect(service.getById(developerId, 'other-app', 'd1')).rejects.toThrow(
        NotFoundException,
      );
      expect(tx.device.findFirst).toHaveBeenCalledWith({
        where: { id: 'd1', appId: 'other-app' },
        include: expect.any(Object),
      });
    });
  });

  describe('unbindAll', () => {
    it('正常应删除所有绑定 + 返回 unboundCount', async () => {
      const tx = buildTx({
        device: [{ id: 'd1', appId }],
        deletedCount: 3,
      });
      setTxMock(tx);

      const result = await service.unbindAll(developerId, appId, 'd1');
      expect(result).toEqual({ success: true, unboundCount: 3 });
      expect(tx.deviceBinding.deleteMany).toHaveBeenCalledWith({ where: { deviceId: 'd1' } });
    });

    it('设备不存在应拒绝', async () => {
      const tx = buildTx();
      setTxMock(tx);
      await expect(service.unbindAll(developerId, appId, 'd1')).rejects.toThrow(
        NotFoundException,
      );
    });
  });
});
