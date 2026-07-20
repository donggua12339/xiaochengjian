import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { HardenerEulaService, CURRENT_EULA_VERSION } from './hardener-eula.service';
import { PrismaService } from '../../prisma/prisma.service';

/**
 * HardenerEulaService 单元测试(ADR 0078 锁 B)
 *
 * 覆盖:
 *  - getCurrentEula: 返回版本号 + 文本
 *  - validateVersion: 版本号匹配通过 / 不匹配拒绝
 *  - validateAccepted: 已接受通过 / 未接受抛 EULA_REQUIRED
 *  - recordAcceptance: 写入 audit_log_own 表
 */
describe('HardenerEulaService', () => {
  let service: HardenerEulaService;
  let prisma: { auditLogOwn: { findFirst: jest.Mock; create: jest.Mock } };

  beforeEach(() => {
    prisma = {
      auditLogOwn: {
        findFirst: jest.fn(),
        create: jest.fn().mockResolvedValue(undefined),
      },
    };
    service = new HardenerEulaService(prisma as unknown as PrismaService);
  });

  describe('getCurrentEula', () => {
    it('应返回版本号 + 文本 + 生效日期', () => {
      const eula = service.getCurrentEula();
      expect(eula.version).toBe(CURRENT_EULA_VERSION);
      expect(eula.text).toContain('EULA');
      expect(eula.effectiveDate).toBe('2026-07-20');
    });
  });

  describe('validateVersion', () => {
    it('版本号匹配应通过', () => {
      expect(() => service.validateVersion(CURRENT_EULA_VERSION)).not.toThrow();
    });

    it('版本号不匹配应抛 BadRequestException', () => {
      expect(() => service.validateVersion('0.9.0')).toThrow(BadRequestException);
    });

    it('版本号为空应抛 BadRequestException', () => {
      expect(() => service.validateVersion('')).toThrow(BadRequestException);
    });
  });

  describe('validateAccepted', () => {
    it('已接受当前版本 EULA 应通过', async () => {
      prisma.auditLogOwn.findFirst.mockResolvedValue({
        id: 'log-1',
        createdAt: new Date(),
      });
      await expect(service.validateAccepted('dev-1')).resolves.toBeUndefined();
      expect(prisma.auditLogOwn.findFirst).toHaveBeenCalledWith({
        where: {
          developerId: 'dev-1',
          eulaAccepted: true,
          eulaVersion: CURRENT_EULA_VERSION,
          hardener: 'bangcle',
        },
        select: { id: true, createdAt: true },
        orderBy: { createdAt: 'desc' },
      });
    });

    it('未接受当前版本 EULA 应抛 ForbiddenException(EULA_REQUIRED)', async () => {
      prisma.auditLogOwn.findFirst.mockResolvedValue(null);
      await expect(service.validateAccepted('dev-1')).rejects.toThrow(
        ForbiddenException,
      );
    });

    it('接受的是旧版本 EULA 应拒绝(版本号不匹配)', async () => {
      // findFirst 查 eulaVersion=CURRENT,旧版本记录不会匹配
      prisma.auditLogOwn.findFirst.mockResolvedValue(null);
      await expect(service.validateAccepted('dev-1')).rejects.toThrow(
        ForbiddenException,
      );
    });
  });

  describe('recordAcceptance', () => {
    it('应写入 audit_log_own 表(operation=EULA_ACCEPT)', async () => {
      await service.recordAcceptance('dev-1', '1.2.3.4', 'UA-test');
      expect(prisma.auditLogOwn.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          developerId: 'dev-1',
          operation: 'EULA_ACCEPT',
          hardener: 'bangcle',
          eulaVersion: CURRENT_EULA_VERSION,
          eulaAccepted: true,
          ip: '1.2.3.4',
          userAgent: 'UA-test',
          status: 'SUCCESS',
        }),
      });
    });

    it('userAgent 缺失时应写 null', async () => {
      await service.recordAcceptance('dev-1', '1.2.3.4');
      const call = prisma.auditLogOwn.create.mock.calls[0][0];
      expect(call.data.userAgent).toBeNull();
    });
  });
});
