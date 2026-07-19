import { Test } from '@nestjs/testing';
import { ForbiddenException } from '@nestjs/common';
import { AuditOwnValidators } from './audit-own-validators';
import { PrismaService } from '../prisma/prisma.service';

/**
 * AuditOwnValidators 单元测试(ADR 0077 §2 三重校验)
 *
 * 覆盖:
 *  - validatePackageName: 通过 / 包名不在白名单(APP_NOT_OWNED)
 *  - validateSignatureHash: 通过 / 签名不匹配(SIGNATURE_MISMATCH)/ 白名单为空(SIGNATURE_WHITELIST_EMPTY)
 *  - validateDirectoryIsolation: 始终 true(占位)
 */
describe('AuditOwnValidators', () => {
  let service: AuditOwnValidators;
  let prisma: { application: { findFirst: jest.Mock } };

  beforeEach(async () => {
    prisma = {
      application: { findFirst: jest.fn() },
    };
    const moduleRef = await Test.createTestingModule({
      providers: [
        AuditOwnValidators,
        { provide: PrismaService, useValue: prisma },
      ],
    }).compile();
    service = moduleRef.get(AuditOwnValidators);
  });

  describe('validatePackageName', () => {
    it('包名在白名单应返回 app', async () => {
      prisma.application.findFirst.mockResolvedValue({
        id: 'app-1',
        name: 'Test',
        signHashAllowList: ['abc123'],
      });
      const result = await service.validatePackageName('dev-1', 'com.test.app');
      expect(result).toEqual({
        id: 'app-1',
        name: 'Test',
        signHashAllowList: ['abc123'],
      });
      expect(prisma.application.findFirst).toHaveBeenCalledWith({
        where: { developerId: 'dev-1', packageName: 'com.test.app' },
        select: { id: true, name: true, signHashAllowList: true },
      });
    });

    it('包名不在白名单应抛 ForbiddenException(APP_NOT_OWNED)', async () => {
      prisma.application.findFirst.mockResolvedValue(null);
      await expect(
        service.validatePackageName('dev-1', 'com.evil.app'),
      ).rejects.toThrow(ForbiddenException);
    });
  });

  describe('validateSignatureHash', () => {
    it('签名 hash 在白名单应通过(大小写不敏感)', async () => {
      await expect(
        service.validateSignatureHash(['ABC123', 'DEF456'], 'abc123'),
      ).resolves.toBeUndefined();
    });

    it('签名 hash 不在白名单应抛 ForbiddenException(SIGNATURE_MISMATCH)', async () => {
      await expect(
        service.validateSignatureHash(['abc123'], 'def456'),
      ).rejects.toThrow(ForbiddenException);
    });

    it('白名单为空应抛 ForbiddenException(SIGNATURE_WHITELIST_EMPTY)', async () => {
      await expect(
        service.validateSignatureHash([], 'abc123'),
      ).rejects.toThrow(ForbiddenException);
    });

    it('白名单为 undefined 应抛 ForbiddenException', async () => {
      await expect(
        service.validateSignatureHash(undefined as unknown as string[], 'abc123'),
      ).rejects.toThrow(ForbiddenException);
    });
  });

  describe('validateDirectoryIsolation', () => {
    it('应始终返回 true(占位,实际隔离由 AuditOwnService 保证)', () => {
      expect(service.validateDirectoryIsolation()).toBe(true);
    });
  });
});
