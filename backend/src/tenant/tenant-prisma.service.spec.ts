import { Test } from '@nestjs/testing';
import { TenantPrismaService } from './tenant-prisma.service';
import { PrismaService } from '../prisma/prisma.service';

/**
 * TenantPrismaService 单元测试(ADR 0018 多租户)
 *
 * 覆盖:
 *  - tx: 在事务内执行 SET LOCAL app.tenant_id + 业务函数
 *  - tx: 业务函数返回值正确透传
 *  - tx: 业务函数抛错时事务回滚
 *  - raw: 返回底层 PrismaService
 */
describe('TenantPrismaService', () => {
  let service: TenantPrismaService;
  let prisma: {
    $transaction: jest.Mock;
  };

  beforeEach(async () => {
    prisma = {
      $transaction: jest.fn(),
    };
    const moduleRef = await Test.createTestingModule({
      providers: [
        TenantPrismaService,
        { provide: PrismaService, useValue: prisma },
      ],
    }).compile();
    service = moduleRef.get(TenantPrismaService);
  });

  it('tx: 应在事务内执行 set_config + 业务函数', async () => {
    const txClient = {
      $executeRaw: jest.fn().mockResolvedValue(undefined),
      application: { findFirst: jest.fn().mockResolvedValue({ id: 'app-1' }) },
    };
    prisma.$transaction.mockImplementation(async (fn) => fn(txClient));

    const result = await service.tx('dev-1', async (tx) => {
      return tx.application.findFirst({ where: { id: 'app-1' } });
    });

    expect(txClient.$executeRaw).toHaveBeenCalled();
    // Prisma 模板字面量 raw SQL 会被拆成 [sqlParts[], ...params] 形式:
    // 第一个参数是 SQL 片段数组,后续是参数值
    // 这里验证调用了 $executeRaw 且 SQL 含 set_config + tenantId 参数正确
    const rawCall = txClient.$executeRaw.mock.calls[0];
    const sqlParts = Array.isArray(rawCall[0]) ? rawCall[0] : [rawCall[0]];
    expect(sqlParts.join('')).toContain('set_config');
    expect(rawCall[1]).toBe('dev-1');
    // 第三个参数 true(LOCAL 标志)可能在 rawCall[2] 或 sqlParts 内
    expect(result).toEqual({ id: 'app-1' });
  });

  it('tx: 业务函数返回值应正确透传', async () => {
    const txClient = { $executeRaw: jest.fn().mockResolvedValue(undefined) };
    prisma.$transaction.mockImplementation(async (fn) => fn(txClient));

    const result = await service.tx('dev-1', async () => 'custom-result');
    expect(result).toBe('custom-result');
  });

  it('tx: 业务函数抛错时应传播(事务回滚由 Prisma 处理)', async () => {
    const txClient = { $executeRaw: jest.fn().mockResolvedValue(undefined) };
    prisma.$transaction.mockImplementation(async (fn) => fn(txClient));

    await expect(
      service.tx('dev-1', async () => {
        throw new Error('business error');
      }),
    ).rejects.toThrow('business error');
  });

  it('raw: 应返回底层 PrismaService', () => {
    const result = service.raw;
    expect(result).toBe(prisma);
  });
});
