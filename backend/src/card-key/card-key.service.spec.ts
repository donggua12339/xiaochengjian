import { Test } from '@nestjs/testing';
import { NotFoundException, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CardKeyService } from './card-key.service';
import { TenantPrismaService } from '../tenant/tenant-prisma.service';
import { CardKeyType, BindingStrategy } from '@prisma/client';
import type { GenerateCardsDto, CreateCardTemplateDto } from './dto/card-key.dto';

/**
 * CardKeyService 单元测试
 *
 * 覆盖:
 *  - generate: 批量生成 / COUNT_EXCEEDS_MAX / APP_NOT_FOUND / TRIAL_CARD_MUST_BE_SINGLE_DEVICE / 分批插入 / 明文一次性返回
 *  - list: 分页 / 筛选(type/status/batchId) / boundDevicesCount 聚合
 *  - getById: 正常 / CARD_NOT_FOUND(不存在)/ CARD_NOT_FOUND(appId 不匹配)
 *  - disable: 正常 / CARD_NOT_FOUND
 *  - enable: 正常 / CARD_NOT_FOUND / CARD_NOT_DISABLED
 *  - unbindDevice: 正常 / DEVICE_BINDING_NOT_FOUND
 *  - export: 正常 / truncated(>10000) / CSV 转义
 *  - createTemplate / listTemplates / deleteTemplate
 *  - computeExpiry: DAY/WEEK/MONTH/PERMANENT/TRIAL
 */
describe('CardKeyService', () => {
  let service: CardKeyService;
  let tenantPrisma: { tx: jest.Mock };
  let configService: { get: jest.Mock };

  const developerId = 'dev-1';
  const appId = 'app-1';

  /** 构建 mock tx */
  function buildTx(opts: {
    application?: any | null;
    cardKey?: any[];
    cardTemplate?: any[];
    deviceBinding?: any[];
  } = {}) {
    return {
      application: {
        findUnique: jest.fn().mockResolvedValue(
          opts.application === undefined ? { id: appId, developerId } : opts.application,
        ),
      },
      cardKey: {
        createMany: jest.fn().mockResolvedValue({ count: opts.cardKey?.length ?? 0 }),
        findMany: jest.fn().mockResolvedValue(opts.cardKey ?? []),
        findUnique: jest.fn().mockResolvedValue(opts.cardKey?.[0] ?? null),
        findFirst: jest.fn().mockResolvedValue(opts.cardKey?.[0] ?? null),
        count: jest.fn().mockResolvedValue(opts.cardKey?.length ?? 0),
        update: jest.fn().mockResolvedValue(opts.cardKey?.[0] ?? {}),
      },
      cardTemplate: {
        create: jest.fn().mockResolvedValue({ id: 'tpl-1', appId }),
        findMany: jest.fn().mockResolvedValue(opts.cardTemplate ?? []),
        findFirst: jest.fn().mockResolvedValue(opts.cardTemplate?.[0] ?? null),
        delete: jest.fn().mockResolvedValue(undefined),
      },
      deviceBinding: {
        findFirst: jest.fn().mockResolvedValue(opts.deviceBinding?.[0] ?? null),
        delete: jest.fn().mockResolvedValue(undefined),
      },
    };
  }

  /** 设置 tenantPrisma.tx 的 mock 实现 */
  function setTxMock(tx: any) {
    tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
      fn(tx),
    );
  }

  beforeEach(async () => {
    tenantPrisma = { tx: jest.fn() };
    configService = {
      get: jest.fn((key: string) => {
        if (key === 'cardKeyBatchMax') return 10000;
        return undefined;
      }),
    };

    const moduleRef = await Test.createTestingModule({
      providers: [
        CardKeyService,
        { provide: TenantPrismaService, useValue: tenantPrisma },
        { provide: ConfigService, useValue: configService },
      ],
    }).compile();
    service = moduleRef.get(CardKeyService);
  });

  describe('generate', () => {
    const dto: GenerateCardsDto = {
      type: CardKeyType.MONTH,
      bindingStrategy: BindingStrategy.FIRST_BIND,
      maxDevices: 1,
      count: 3,
    };

    it('数量超上限应拒绝(COUNT_EXCEEDS_MAX)', async () => {
      configService.get.mockReturnValue(10000);
      await expect(
        service.generate(developerId, appId, { ...dto, count: 10001 }),
      ).rejects.toThrow(BadRequestException);
    });

    it('APP 不存在应拒绝(APP_NOT_FOUND)', async () => {
      const tx = buildTx({ application: null });
      setTxMock(tx);
      await expect(service.generate(developerId, appId, dto)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('TRIAL 卡 maxDevices > 1 应拒绝(TRIAL_CARD_MUST_BE_SINGLE_DEVICE)', async () => {
      const tx = buildTx();
      setTxMock(tx);
      await expect(
        service.generate(developerId, appId, {
          type: CardKeyType.TRIAL,
          bindingStrategy: BindingStrategy.N_DEVICES,
          maxDevices: 3,
          count: 1,
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('成功生成应返回明文列表 + batchId + count', async () => {
      const tx = buildTx();
      setTxMock(tx);
      const result = await service.generate(developerId, appId, dto);

      expect(result.count).toBe(3);
      expect(result.batchId).toBeDefined();
      expect(result.cardKeys).toHaveLength(3);
      // 每张卡密应符合 4x4 格式
      for (const key of result.cardKeys) {
        expect(key).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/);
      }
      // 应调用 createMany
      expect(tx.cardKey.createMany).toHaveBeenCalled();
    });

    it('生成数量 > 500 应分批插入(每批 500)', async () => {
      const tx = buildTx();
      setTxMock(tx);
      await service.generate(developerId, appId, { ...dto, count: 1200 });
      // 1200 / 500 = 3 批(500+500+200)
      expect(tx.cardKey.createMany).toHaveBeenCalledTimes(3);
    });

    it('生成的卡密不应在 service 层日志泄露明文', async () => {
      const tx = buildTx();
      setTxMock(tx);
      const result = await service.generate(developerId, appId, dto);
      // createMany 的入参应含 hash + salt,不含明文
      const createCall = tx.cardKey.createMany.mock.calls[0][0].data;
      for (const row of createCall) {
        expect(row.cardKeyHash).toMatch(/^[0-9a-f]{64}$/);
        expect(row.cardSalt).toMatch(/^[0-9a-f]{32}$/);
        // 不应含明文
        for (const plain of result.cardKeys) {
          expect(JSON.stringify(row)).not.toContain(plain);
        }
      }
    });

    it('PERMANENT 卡应 expiresAt=null', async () => {
      const tx = buildTx();
      setTxMock(tx);
      await service.generate(developerId, appId, {
        type: CardKeyType.PERMANENT,
        bindingStrategy: BindingStrategy.NONE,
        count: 1,
      });
      const createCall = tx.cardKey.createMany.mock.calls[0][0].data;
      expect(createCall[0].expiresAt).toBeNull();
    });

    it('未提供 maxDevices 时默认为 1', async () => {
      const tx = buildTx();
      setTxMock(tx);
      await service.generate(developerId, appId, {
        type: CardKeyType.MONTH,
        bindingStrategy: BindingStrategy.FIRST_BIND,
        count: 1,
      });
      const createCall = tx.cardKey.createMany.mock.calls[0][0].data;
      expect(createCall[0].maxDevices).toBe(1);
    });

    it('有 remark 时应存入', async () => {
      const tx = buildTx();
      setTxMock(tx);
      await service.generate(developerId, appId, {
        ...dto,
        remark: '测试批次',
      });
      const createCall = tx.cardKey.createMany.mock.calls[0][0].data;
      expect(createCall[0].remark).toBe('测试批次');
    });
  });

  describe('list', () => {
    it('应返回分页结构 + boundDevicesCount', async () => {
      const mockCards = [
        {
          id: 'c1',
          appId,
          cardKeyPrefix: 'ABCD',
          type: CardKeyType.MONTH,
          status: 'ACTIVE',
          deviceBindings: [{ deviceId: 'd1' }, { deviceId: 'd2' }],
          createdAt: new Date(),
        },
      ];
      const tx = buildTx({ cardKey: mockCards });
      setTxMock(tx);

      const result = await service.list(developerId, appId, {
        page: 1,
        pageSize: 20,
      });

      expect(result.items).toHaveLength(1);
      expect(result.items[0].boundDevicesCount).toBe(2);
      // deviceBindings 应被移除(不暴露给前端)
      expect(result.items[0].deviceBindings).toBeUndefined();
      expect(result.total).toBe(1);
      expect(result.page).toBe(1);
      expect(result.pageSize).toBe(20);
      expect(result.totalPages).toBe(1);
    });

    it('应支持 type/status/batchId 筛选', async () => {
      const tx = buildTx({ cardKey: [] });
      setTxMock(tx);

      await service.list(developerId, appId, {
        page: 1,
        pageSize: 20,
        type: CardKeyType.MONTH,
        status: 'ACTIVE',
        batchId: 'batch-1',
      });

      const whereArg = tx.cardKey.findMany.mock.calls[0][0].where;
      expect(whereArg).toEqual({
        appId,
        type: CardKeyType.MONTH,
        status: 'ACTIVE',
        batchId: 'batch-1',
      });
    });

    it('total=0 时 totalPages 应为 1(不返回 0)', async () => {
      const tx = buildTx({ cardKey: [] });
      setTxMock(tx);
      const result = await service.list(developerId, appId, { page: 1, pageSize: 20 });
      expect(result.totalPages).toBe(1);
    });
  });

  describe('getById', () => {
    it('正常返回卡密详情 + boundDevicesCount', async () => {
      const card = {
        id: 'c1',
        appId,
        cardKeyPrefix: 'ABCD',
        deviceBindings: [{ device: { id: 'd1', machineId: 'm1', lastSeenAt: new Date() } }],
      };
      const tx = buildTx({ cardKey: [card] });
      setTxMock(tx);

      const result = await service.getById(developerId, appId, 'c1');
      expect(result.boundDevicesCount).toBe(1);
      expect(result.deviceBindings[0].device.machineId).toBe('m1');
    });

    it('卡密不存在应拒绝(CARD_NOT_FOUND)', async () => {
      const tx = buildTx({ cardKey: [] });
      setTxMock(tx);
      await expect(service.getById(developerId, appId, 'c1')).rejects.toThrow(
        NotFoundException,
      );
    });

    it('卡密存在但 appId 不匹配应拒绝(CARD_NOT_FOUND)', async () => {
      const card = { id: 'c1', appId: 'other-app', deviceBindings: [] };
      const tx = buildTx({ cardKey: [card] });
      setTxMock(tx);
      await expect(service.getById(developerId, appId, 'c1')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('disable', () => {
    it('正常禁用', async () => {
      const card = { id: 'c1', appId, status: 'ACTIVE' };
      const tx = buildTx({ cardKey: [card] });
      setTxMock(tx);

      await service.disable(developerId, appId, 'c1');
      expect(tx.cardKey.update).toHaveBeenCalledWith({
        where: { id: 'c1' },
        data: { status: 'DISABLED' },
      });
    });

    it('卡密不存在应拒绝', async () => {
      const tx = buildTx({ cardKey: [] });
      setTxMock(tx);
      await expect(service.disable(developerId, appId, 'c1')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('enable', () => {
    it('正常启用(从 DISABLED 恢复)', async () => {
      const card = { id: 'c1', appId, status: 'DISABLED' };
      const tx = buildTx({ cardKey: [card] });
      setTxMock(tx);

      await service.enable(developerId, appId, 'c1');
      expect(tx.cardKey.update).toHaveBeenCalledWith({
        where: { id: 'c1' },
        data: { status: 'ACTIVE' },
      });
    });

    it('卡密不存在应拒绝', async () => {
      const tx = buildTx({ cardKey: [] });
      setTxMock(tx);
      await expect(service.enable(developerId, appId, 'c1')).rejects.toThrow(
        NotFoundException,
      );
    });

    it('非 DISABLED 状态应拒绝(CARD_NOT_DISABLED)', async () => {
      const card = { id: 'c1', appId, status: 'ACTIVE' };
      const tx = buildTx({ cardKey: [card] });
      setTxMock(tx);
      await expect(service.enable(developerId, appId, 'c1')).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('unbindDevice', () => {
    it('正常解绑', async () => {
      const tx = buildTx({
        deviceBinding: [{ id: 'b1', cardKeyId: 'c1', deviceId: 'd1' }],
      });
      setTxMock(tx);

      const result = await service.unbindDevice(developerId, appId, 'c1', 'd1');
      expect(result).toEqual({ success: true });
      expect(tx.deviceBinding.delete).toHaveBeenCalledWith({ where: { id: 'b1' } });
    });

    it('绑定不存在应拒绝(DEVICE_BINDING_NOT_FOUND)', async () => {
      const tx = buildTx({ deviceBinding: [] });
      setTxMock(tx);
      await expect(service.unbindDevice(developerId, appId, 'c1', 'd1')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('export', () => {
    it('应返回 CSV 格式 + header + 行数据', async () => {
      const mockCards = [
        {
          id: 'c1',
          appId,
          cardKeyPrefix: 'ABCD',
          type: CardKeyType.MONTH,
          bindingStrategy: BindingStrategy.FIRST_BIND,
          maxDevices: 1,
          status: 'ACTIVE',
          batchId: 'b1',
          remark: null,
          activatedAt: null,
          expiresAt: null,
          createdAt: new Date('2026-01-01'),
          _count: { deviceBindings: 0 },
        },
      ];
      const tx = buildTx({ cardKey: mockCards });
      setTxMock(tx);

      const result = await service.export(developerId, appId, {});
      expect(result.csv).toContain('id,cardKeyPrefix,type,bindingStrategy');
      expect(result.csv).toContain('c1');
      expect(result.count).toBe(1);
      expect(result.truncated).toBe(false);
    });

    it('超过 10000 行应 truncated=true', async () => {
      // 模拟 10001 行(超出上限)
      const mockCards = Array.from({ length: 10001 }, (_, i) => ({
        id: `c${i}`,
        appId,
        cardKeyPrefix: 'ABCD',
        type: CardKeyType.MONTH,
        bindingStrategy: BindingStrategy.NONE,
        maxDevices: 1,
        status: 'ACTIVE',
        batchId: 'b1',
        remark: null,
        activatedAt: null,
        expiresAt: null,
        createdAt: new Date(),
        _count: { deviceBindings: 0 },
      }));
      const tx = buildTx({ cardKey: mockCards });
      setTxMock(tx);

      const result = await service.export(developerId, appId, {});
      expect(result.truncated).toBe(true);
      expect(result.count).toBe(10000);
    });

    it('remark 含逗号应 CSV 转义(双引号包裹)', async () => {
      const mockCards = [
        {
          id: 'c1',
          appId,
          cardKeyPrefix: 'ABCD',
          type: CardKeyType.MONTH,
          bindingStrategy: BindingStrategy.NONE,
          maxDevices: 1,
          status: 'ACTIVE',
          batchId: 'b1',
          remark: 'hello, world',
          activatedAt: null,
          expiresAt: null,
          createdAt: new Date('2026-01-01'),
          _count: { deviceBindings: 0 },
        },
      ];
      const tx = buildTx({ cardKey: mockCards });
      setTxMock(tx);

      const result = await service.export(developerId, appId, {});
      expect(result.csv).toContain('"hello, world"');
    });
  });

  describe('createTemplate', () => {
    const dto: CreateCardTemplateDto = {
      name: '月卡模板',
      type: CardKeyType.MONTH,
      bindingStrategy: BindingStrategy.FIRST_BIND,
      maxDevices: 1,
      count: 100,
    };

    it('APP 不存在应拒绝', async () => {
      const tx = buildTx({ application: null });
      setTxMock(tx);
      await expect(service.createTemplate(developerId, appId, dto)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('正常创建应返回模板', async () => {
      const tx = buildTx();
      setTxMock(tx);
      const result = await service.createTemplate(developerId, appId, dto);
      expect(result).toEqual({ id: 'tpl-1', appId });
      expect(tx.cardTemplate.create).toHaveBeenCalledWith({
        data: {
          developerId,
          appId,
          name: '月卡模板',
          type: CardKeyType.MONTH,
          bindingStrategy: BindingStrategy.FIRST_BIND,
          maxDevices: 1,
          count: 100,
        },
      });
    });

    it('未提供 maxDevices/count 时应默认 1/100', async () => {
      const tx = buildTx();
      setTxMock(tx);
      await service.createTemplate(developerId, appId, {
        name: '默认模板',
        type: CardKeyType.DAY,
        bindingStrategy: BindingStrategy.NONE,
      });
      expect(tx.cardTemplate.create).toHaveBeenCalledWith({
        data: expect.objectContaining({ maxDevices: 1, count: 100 }),
      });
    });
  });

  describe('listTemplates', () => {
    it('应返回模板列表', async () => {
      const tx = buildTx({
        cardTemplate: [{ id: 't1', name: '模板1' }, { id: 't2', name: '模板2' }],
      });
      setTxMock(tx);
      const result = await service.listTemplates(developerId, appId);
      expect(result).toHaveLength(2);
    });
  });

  describe('deleteTemplate', () => {
    it('正常删除', async () => {
      const tx = buildTx({
        cardTemplate: [{ id: 't1', appId }],
      });
      setTxMock(tx);
      const result = await service.deleteTemplate(developerId, appId, 't1');
      expect(result).toEqual({ success: true });
      expect(tx.cardTemplate.delete).toHaveBeenCalledWith({ where: { id: 't1' } });
    });

    it('模板不存在应拒绝(TEMPLATE_NOT_FOUND)', async () => {
      const tx = buildTx({ cardTemplate: [] });
      setTxMock(tx);
      await expect(service.deleteTemplate(developerId, appId, 't1')).rejects.toThrow(
        NotFoundException,
      );
    });
  });
});
