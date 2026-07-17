import { Test } from '@nestjs/testing';
import { AuditService } from './audit.service';
import { PrismaService } from '../prisma/prisma.service';

/**
 * AuditService 单元测试
 *
 * 覆盖:
 *  - record: 正常写入 / meta 序列化 / ip 默认 unknown / 写入失败不抛错
 */
describe('AuditService', () => {
  let service: AuditService;
  let prisma: { auditLog: { create: jest.Mock } };

  beforeEach(async () => {
    prisma = {
      auditLog: { create: jest.fn().mockResolvedValue(undefined) },
    };
    const moduleRef = await Test.createTestingModule({
      providers: [
        AuditService,
        { provide: PrismaService, useValue: prisma },
      ],
    }).compile();
    service = moduleRef.get(AuditService);
  });

  it('正常应写入 auditLog', async () => {
    await service.record({
      developerId: 'dev-1',
      action: 'GENERATE_CARDS' as any,
      target: 'app-1',
      ip: '1.2.3.4',
      userAgent: 'UA',
      meta: { count: 3 },
    });
    expect(prisma.auditLog.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        developerId: 'dev-1',
        action: 'GENERATE_CARDS',
        target: 'app-1',
        ip: '1.2.3.4',
        userAgent: 'UA',
        meta: { count: 3 },
      }),
    });
  });

  it('未提供 ip 时应默认 unknown', async () => {
    await service.record({
      developerId: 'dev-1',
      action: 'LOGIN' as any,
    });
    expect(prisma.auditLog.create).toHaveBeenCalledWith({
      data: expect.objectContaining({ ip: 'unknown' }),
    });
  });

  it('未提供 meta 时应传 undefined', async () => {
    await service.record({
      developerId: 'dev-1',
      action: 'LOGIN' as any,
    });
    const call = prisma.auditLog.create.mock.calls[0][0];
    expect(call.data.meta).toBeUndefined();
  });

  it('meta 含 Date 对象应被序列化为字符串(JSON.parse(JSON.stringify))', async () => {
    const date = new Date('2026-01-01');
    await service.record({
      developerId: 'dev-1',
      action: 'LOGIN' as any,
      meta: { at: date },
    });
    const call = prisma.auditLog.create.mock.calls[0][0];
    // Date 被 JSON 序列化后变字符串
    expect(call.data.meta.at).toBe('2026-01-01T00:00:00.000Z');
    expect(call.data.meta.at).not.toBeInstanceOf(Date);
  });

  it('写入失败不应抛错(不阻塞主流程)', async () => {
    prisma.auditLog.create.mockRejectedValue(new Error('DB down'));
    await expect(
      service.record({ developerId: 'dev-1', action: 'LOGIN' as any }),
    ).resolves.toBeUndefined();
  });
});
