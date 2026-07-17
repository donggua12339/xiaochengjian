import { Test } from '@nestjs/testing';
import { NotFoundException, ConflictException, BadRequestException } from '@nestjs/common';
import { MembershipService } from './membership.service';
import { PrismaService } from '../prisma/prisma.service';
import { TenantPrismaService } from '../tenant/tenant-prisma.service';
import { VipLevel } from '@prisma/client';
import type { GenerateMembershipCodesDto, RedeemMembershipCodeDto } from './dto/membership.dto';

/**
 * MembershipService 单元测试
 *
 * 覆盖:
 *  - generate: 批量生成 / 明文一次性返回 / hash + salt 存储 / batchId 生成
 *  - redeem: 激活码不存在 / 已兑换(COUNT 0)/ 正常兑换 / PERMANENT(100 年)/ 已有会员延长
 *  - list: 分页 + 筛选
 *  - disable: 正常 / 不存在 / 已使用不能禁用
 */
describe('MembershipService', () => {
  let service: MembershipService;
  let prisma: {
    membershipCode: {
      createMany: jest.Mock;
      findMany: jest.Mock;
      findUnique: jest.Mock;
      count: jest.Mock;
      updateMany: jest.Mock;
      update: jest.Mock;
    };
  };
  let tenantPrisma: { tx: jest.Mock };

  /** 构造一个已存在的激活码(供 redeem 测试用) */
  function buildExistingCode(overrides: Partial<any> = {}) {
    const plaintext = 'ABCD1234EFGH5678';
    const salt = 'salt123';
    return {
      id: 'code-1',
      codeHash: hashForTest(plaintext, salt),
      codeSalt: salt,
      level: VipLevel.VIP,
      durationDays: 30,
      ...overrides,
    };
  }

  /** 测试用 hash(和 service 内部算法一致) */
  function hashForTest(code: string, salt: string): string {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(code + salt).digest('hex');
  }

  function setTxMock(txImpl: any) {
    tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
      fn(txImpl),
    );
  }

  beforeEach(async () => {
    prisma = {
      membershipCode: {
        createMany: jest.fn().mockResolvedValue({ count: 0 }),
        findMany: jest.fn().mockResolvedValue([]),
        findUnique: jest.fn().mockResolvedValue(null),
        count: jest.fn().mockResolvedValue(0),
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
        update: jest.fn().mockResolvedValue({}),
      },
    };
    tenantPrisma = { tx: jest.fn() };

    const moduleRef = await Test.createTestingModule({
      providers: [
        MembershipService,
        { provide: PrismaService, useValue: prisma },
        { provide: TenantPrismaService, useValue: tenantPrisma },
      ],
    }).compile();
    service = moduleRef.get(MembershipService);
  });

  describe('generate', () => {
    const dto: GenerateMembershipCodesDto = {
      level: VipLevel.VIP,
      durationDays: 30,
      count: 3,
    };

    it('正常应返回明文列表 + batchId', async () => {
      const result = await service.generate('admin-1', dto);
      expect(result.count).toBe(3);
      expect(result.batchId).toBeDefined();
      expect(result.codes).toHaveLength(3);
      for (const code of result.codes) {
        expect(code).toMatch(/^[A-Z0-9]{16}$/);
      }
    });

    it('createMany 入参应含 hash + salt + prefix,不含明文', async () => {
      const result = await service.generate('admin-1', dto);
      const createCall = prisma.membershipCode.createMany.mock.calls[0][0].data;
      for (const row of createCall) {
        expect(row.codeHash).toMatch(/^[0-9a-f]{64}$/);
        expect(row.codeSalt).toMatch(/^[0-9a-f]{32}$/);
        expect(row.codePrefix).toMatch(/^[A-Z0-9]{4}$/);
        for (const plain of result.codes) {
          expect(JSON.stringify(row)).not.toContain(plain);
        }
      }
    });

    it('PERMANENT(durationDays=-1)应支持', async () => {
      await service.generate('admin-1', {
        ...dto,
        durationDays: -1,
      });
      const createCall = prisma.membershipCode.createMany.mock.calls[0][0].data;
      expect(createCall[0].durationDays).toBe(-1);
    });
  });

  describe('redeem', () => {
    const dto: RedeemMembershipCodeDto = {
      code: 'ABCD1234EFGH5678',
    };

    it('激活码不存在应拒绝(MEMBERSHIP_CODE_NOT_FOUND)', async () => {
      prisma.membershipCode.findMany.mockResolvedValue([]); // 无 UNUSED 码
      const tx = { developer: { findUnique: jest.fn(), update: jest.fn() } };
      setTxMock(tx);
      await expect(service.redeem('dev-1', dto)).rejects.toThrow(NotFoundException);
    });

    it('hash 不匹配应拒绝(激活码不存在)', async () => {
      const wrongCode = buildExistingCode({ codeSalt: 'other-salt' });
      prisma.membershipCode.findMany.mockResolvedValue([wrongCode]);
      const tx = { developer: { findUnique: jest.fn(), update: jest.fn() } };
      setTxMock(tx);
      await expect(service.redeem('dev-1', dto)).rejects.toThrow(NotFoundException);
    });

    it('已兑换(updateMany count=0)应拒绝(MEMBERSHIP_CODE_ALREADY_REDEEMED)', async () => {
      const code = buildExistingCode();
      prisma.membershipCode.findMany.mockResolvedValue([code]);
      prisma.membershipCode.updateMany.mockResolvedValue({ count: 0 }); // 并发兑换
      const tx = { developer: { findUnique: jest.fn(), update: jest.fn() } };
      setTxMock(tx);
      await expect(service.redeem('dev-1', dto)).rejects.toThrow(ConflictException);
    });

    it('正常兑换(新会员)应设置 vipLevel + vipExpiresAt', async () => {
      const code = buildExistingCode();
      prisma.membershipCode.findMany.mockResolvedValue([code]);
      prisma.membershipCode.updateMany.mockResolvedValue({ count: 1 });
      const tx = {
        developer: {
          findUnique: jest.fn().mockResolvedValue({
            id: 'dev-1',
            vipLevel: VipLevel.FREE,
            vipExpiresAt: null,
          }),
          update: jest.fn().mockResolvedValue({}),
        },
      };
      setTxMock(tx);

      const result = await service.redeem('dev-1', dto);
      expect(result.newVipLevel).toBe(VipLevel.VIP);
      expect(result.newVipExpiresAt).toBeInstanceOf(Date);
      // 应更新 developer
      expect(tx.developer.update).toHaveBeenCalledWith({
        where: { id: 'dev-1' },
        data: expect.objectContaining({
          vipLevel: VipLevel.VIP,
          vipExpiresAt: expect.any(Date),
        }),
      });
    });

    it('已有有效会员应在原到期时间基础上延长', async () => {
      const code = buildExistingCode();
      prisma.membershipCode.findMany.mockResolvedValue([code]);
      prisma.membershipCode.updateMany.mockResolvedValue({ count: 1 });
      const existingExpiry = new Date('2026-12-31');
      const tx = {
        developer: {
          findUnique: jest.fn().mockResolvedValue({
            id: 'dev-1',
            vipLevel: VipLevel.VIP,
            vipExpiresAt: existingExpiry,
          }),
          update: jest.fn().mockResolvedValue({}),
        },
      };
      setTxMock(tx);

      const result = await service.redeem('dev-1', dto);
      // 新到期时间应基于 existingExpiry(2026-12-31)+30 天,不是 now + 30 天
      expect(result.newVipExpiresAt.getTime()).toBeGreaterThan(existingExpiry.getTime());
    });

    it('PERMANENT(durationDays=-1)应设 100 年', async () => {
      const code = buildExistingCode({ durationDays: -1 });
      prisma.membershipCode.findMany.mockResolvedValue([code]);
      prisma.membershipCode.updateMany.mockResolvedValue({ count: 1 });
      const tx = {
        developer: {
          findUnique: jest.fn().mockResolvedValue({
            id: 'dev-1',
            vipLevel: VipLevel.FREE,
            vipExpiresAt: null,
          }),
          update: jest.fn().mockResolvedValue({}),
        },
      };
      setTxMock(tx);

      const result = await service.redeem('dev-1', dto);
      const now = new Date();
      const expectedYear = now.getFullYear() + 100;
      expect(result.newVipExpiresAt.getFullYear()).toBeGreaterThanOrEqual(expectedYear);
    });
  });

  describe('list', () => {
    it('应返回分页结构', async () => {
      prisma.membershipCode.findMany.mockResolvedValue([{ id: 'c1' }]);
      prisma.membershipCode.count.mockResolvedValue(1);
      const result = await service.list({ page: 1, pageSize: 20 });
      expect(result.items).toHaveLength(1);
      expect(result.total).toBe(1);
      expect(result.totalPages).toBe(1);
    });

    it('应支持 status + batchId 筛选', async () => {
      prisma.membershipCode.findMany.mockResolvedValue([]);
      await service.list({ status: 'UNUSED', batchId: 'b1' });
      const whereArg = prisma.membershipCode.findMany.mock.calls[0][0].where;
      expect(whereArg).toEqual({ status: 'UNUSED', batchId: 'b1' });
    });

    it('未提供 page/pageSize 时默认 1/20', async () => {
      prisma.membershipCode.findMany.mockResolvedValue([]);
      await service.list({});
      const findManyArg = prisma.membershipCode.findMany.mock.calls[0][0];
      expect(findManyArg.skip).toBe(0);
      expect(findManyArg.take).toBe(20);
    });
  });

  describe('disable', () => {
    it('正常禁用(UNUSED -> DISABLED)', async () => {
      prisma.membershipCode.findUnique.mockResolvedValue({
        id: 'c1',
        status: 'UNUSED',
      });
      await service.disable('c1');
      expect(prisma.membershipCode.update).toHaveBeenCalledWith({
        where: { id: 'c1' },
        data: { status: 'DISABLED' },
      });
    });

    it('激活码不存在应拒绝', async () => {
      prisma.membershipCode.findUnique.mockResolvedValue(null);
      await expect(service.disable('c1')).rejects.toThrow(NotFoundException);
    });

    it('已使用(USED)的激活码不能禁用', async () => {
      prisma.membershipCode.findUnique.mockResolvedValue({
        id: 'c1',
        status: 'USED',
      });
      await expect(service.disable('c1')).rejects.toThrow(BadRequestException);
    });
  });
});
