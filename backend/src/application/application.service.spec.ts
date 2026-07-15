import { Test } from '@nestjs/testing';
import { ApplicationService } from './application.service';
import { PrismaService } from '../prisma/prisma.service';
import { TenantPrismaService } from '../tenant/tenant-prisma.service';
import { ConfigService } from '@nestjs/config';

/**
 * ApplicationService 单测
 * 详见 ADR 0038 (测试策略)
 *
 * 注:异常路径测试需要更完整的 mock 链路,作为后续迭代任务
 */
describe('ApplicationService', () => {
  let service: ApplicationService;
  let mockTx: any;
  let mockPrisma: any;

  beforeEach(async () => {
    mockTx = {
      application: {
        count: jest.fn(), create: jest.fn(), findMany: jest.fn(),
        findUnique: jest.fn(), update: jest.fn(), delete: jest.fn(),
      },
      developer: { findUnique: jest.fn(), update: jest.fn() },
    };

    // 原始 PrismaService(developer 表无 RLS,业务代码用 this.prisma.developer.findUnique)
    mockPrisma = {
      developer: { findUnique: jest.fn() },
    };

    const tenantPrisma = {
      tx: jest.fn().mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) => fn(mockTx)),
    };

    const moduleRef = await Test.createTestingModule({
      providers: [
        ApplicationService,
        { provide: TenantPrismaService, useValue: tenantPrisma },
        { provide: PrismaService, useValue: mockPrisma },
        { provide: ConfigService, useValue: { get: () => 5 } },
      ],
    }).compile();

    service = moduleRef.get(ApplicationService);
  });

  const fullApp = {
    id: 'app1', name: 'Test', packageName: 'com.test',
    appSecretHash: 'hash', signHashAllowList: [],
    rateLimitIpPerMinute: null, rateLimitDevicePerMinute: null,
    rateLimitFailLockThreshold: null, rateLimitFailLockTtl: null,
    offlineCacheDays: 7, sdkRsaPublicKeyHash: null,
    createdAt: new Date(), updatedAt: new Date(),
  };

  it('应成功创建应用', async () => {
    mockPrisma.developer.findUnique.mockResolvedValue({ id: 'dev1', maxApps: 5 });
    mockTx.application.count.mockResolvedValue(0);
    mockTx.application.create.mockResolvedValue({ ...fullApp, appSecret: 'a'.repeat(32) });
    const result = await service.create('dev1', { name: 'Test', packageName: 'com.test' });
    expect(result.name).toBe('Test');
    expect(result.appSecret).toBeTruthy();
  });

  it('应返回应用列表(toResponse 过滤 appSecretHash)', async () => {
    mockTx.application.findMany.mockResolvedValue([fullApp]);
    const result = await service.list('dev1');
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('Test');
    expect((result[0] as any).appSecretHash).toBeUndefined();
  });
});
