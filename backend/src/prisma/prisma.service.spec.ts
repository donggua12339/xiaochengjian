import { Test } from '@nestjs/testing';
import { PrismaService } from './prisma.service';

/**
 * PrismaService 单元测试
 *
 * 覆盖:
 *  - 构造:实例化不报错(惰性连接,不调 $connect)
 *  - onModuleDestroy: 调 $disconnect + log
 */
describe('PrismaService', () => {
  let service: PrismaService;

  beforeEach(async () => {
    // PrismaClient 构造时不实际连接(惰性),但需要 DATABASE_URL
    process.env.DATABASE_URL =
      process.env.DATABASE_URL ?? 'postgresql://test:test@localhost:5432/test';
    const moduleRef = await Test.createTestingModule({
      providers: [PrismaService],
    }).compile();
    service = moduleRef.get(PrismaService);
  });

  it('应正确实例化', () => {
    expect(service).toBeDefined();
    expect(service.$connect).toBeDefined();
    expect(service.$disconnect).toBeDefined();
  });

  it('onModuleDestroy 应调 $disconnect', async () => {
    const spy = jest.spyOn(service, '$disconnect').mockResolvedValue(undefined as never);
    await service.onModuleDestroy();
    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
  });
});
