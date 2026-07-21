import { Test } from '@nestjs/testing';
import { ForbiddenException, BadRequestException } from '@nestjs/common';
import { PackerValidators, XCJ_AUTH_SDK_DEX_WHITELIST } from './packer-validators';
import { PrismaService } from '../prisma/prisma.service';

/**
 * PackerValidators 单元测试(ADR 0081 七锁)
 *
 * 覆盖:
 *  - 锁 1 对象锁定:三重校验(包名白名单 + 签名 hash)
 *  - 锁 2 内容锁定:注入 dex hash 白名单
 *  - 锁 3 入口锁定:Manifest 修改范围
 *  - 锁 4 签名锁定:自备 Keystore
 *  - 锁 5 权限锁定:JWT 开发者 = 应用所有者
 *  - 锁 6 数据锁定:SDK 配置仅 OAID + 包信息
 *  - 锁 7 客户端签名自检:配置预期 hash
 */
describe('PackerValidators', () => {
  let service: PackerValidators;
  let prisma: { application: { findFirst: jest.Mock } };

  beforeEach(async () => {
    prisma = {
      application: { findFirst: jest.fn() },
    };
    const moduleRef = await Test.createTestingModule({
      providers: [
        PackerValidators,
        { provide: PrismaService, useValue: prisma },
      ],
    }).compile();
    service = moduleRef.get(PackerValidators);
  });

  describe('锁 1 对象锁定', () => {
    it('包名在白名单应返回 app', async () => {
      prisma.application.findFirst.mockResolvedValue({
        id: 'app-1',
        name: 'Test',
        signHashAllowList: ['abc123'],
      });
      const result = await service.validateObjectLock('dev-1', 'com.test.app', 'abc123');
      expect(result.id).toBe('app-1');
    });

    it('包名不在白名单应抛 ForbiddenException', async () => {
      prisma.application.findFirst.mockResolvedValue(null);
      await expect(
        service.validateObjectLock('dev-1', 'com.evil.app', 'abc123'),
      ).rejects.toThrow(ForbiddenException);
    });

    it('签名 hash 不匹配应抛 ForbiddenException', async () => {
      prisma.application.findFirst.mockResolvedValue({
        id: 'app-1',
        name: 'Test',
        signHashAllowList: ['abc123'],
      });
      await expect(
        service.validateObjectLock('dev-1', 'com.test.app', 'wrong-hash'),
      ).rejects.toThrow(ForbiddenException);
    });

    it('签名白名单为空应抛 ForbiddenException', async () => {
      prisma.application.findFirst.mockResolvedValue({
        id: 'app-1',
        name: 'Test',
        signHashAllowList: [],
      });
      await expect(
        service.validateObjectLock('dev-1', 'com.test.app', 'abc123'),
      ).rejects.toThrow(ForbiddenException);
    });
  });

  describe('锁 2 内容锁定', () => {
    it('白名单为空时应放行(MVP 阶段)', () => {
      // XCJ_AUTH_SDK_DEX_WHITELIST 默认为空
      expect(XCJ_AUTH_SDK_DEX_WHITELIST.length).toBe(0);
      expect(() => service.validateContentLock('any-hash')).not.toThrow();
    });

    it('白名单非空时,hash 不在白名单应抛 ForbiddenException', () => {
      // 临时加白名单
      (XCJ_AUTH_SDK_DEX_WHITELIST as string[]).push('whitelist-hash-1');
      try {
        expect(() => service.validateContentLock('wrong-hash')).toThrow(ForbiddenException);
        expect(() => service.validateContentLock('whitelist-hash-1')).not.toThrow();
      } finally {
        // 恢复
        (XCJ_AUTH_SDK_DEX_WHITELIST as string[]).pop();
      }
    });
  });

  describe('锁 3 入口锁定', () => {
    it('仅 Application 委托 + xcj Meta-data + INTERNET 应通过', () => {
      expect(() =>
        service.validateEntryLock({
          applicationNameChanged: true,
          metaDataAdded: ['xcj.appId', 'xcj.serverUrl'],
          permissionsAdded: ['android.permission.INTERNET'],
          otherChanges: [],
        }),
      ).not.toThrow();
    });

    it('含 otherChanges 应抛 ForbiddenException', () => {
      expect(() =>
        service.validateEntryLock({
          applicationNameChanged: true,
          metaDataAdded: [],
          permissionsAdded: [],
          otherChanges: ['changed theme'],
        }),
      ).toThrow(ForbiddenException);
    });

    it('Meta-data 不以 xcj. 开头应抛 ForbiddenException', () => {
      expect(() =>
        service.validateEntryLock({
          applicationNameChanged: false,
          metaDataAdded: ['com.evil.tracker'],
          permissionsAdded: [],
          otherChanges: [],
        }),
      ).toThrow(ForbiddenException);
    });

    it('权限不在白名单应抛 ForbiddenException', () => {
      expect(() =>
        service.validateEntryLock({
          applicationNameChanged: false,
          metaDataAdded: [],
          permissionsAdded: ['android.permission.READ_CONTACTS'],
          otherChanges: [],
        }),
      ).toThrow(ForbiddenException);
    });
  });

  describe('锁 4 签名锁定', () => {
    it('keystore 为空应抛 BadRequestException', () => {
      expect(() => service.validateSignLock(Buffer.alloc(0))).toThrow(BadRequestException);
    });

    it('keystore 非空应通过', () => {
      expect(() => service.validateSignLock(Buffer.from('keystore'))).not.toThrow();
    });
  });

  describe('锁 5 权限锁定', () => {
    it('JWT 开发者 = 应用所有者应通过', () => {
      expect(() => service.validatePermissionLock('dev-1', 'dev-1')).not.toThrow();
    });

    it('JWT 开发者 ≠ 应用所有者应抛 ForbiddenException', () => {
      expect(() => service.validatePermissionLock('dev-1', 'dev-2')).toThrow(ForbiddenException);
    });
  });

  describe('锁 6 数据锁定', () => {
    it('仅含允许字段应通过', () => {
      expect(() =>
        service.validateDataLock({
          appId: 'app-1',
          serverUrl: 'https://xcj.winmelon.cn',
          offlineCacheDays: 7,
          oaidEnabled: true,
        }),
      ).not.toThrow();
    });

    it('含非允许字段应抛 ForbiddenException', () => {
      expect(() =>
        service.validateDataLock({
          appId: 'app-1',
          customField: 'evil',
        }),
      ).toThrow(ForbiddenException);
    });

    it('含敏感隐私字段(contacts)应抛 ForbiddenException', () => {
      expect(() =>
        service.validateDataLock({
          appId: 'app-1',
          contacts: [],
        }),
      ).toThrow(ForbiddenException);
    });

    it('含敏感隐私字段(location)应抛 ForbiddenException', () => {
      expect(() =>
        service.validateDataLock({
          appId: 'app-1',
          location: 'gps',
        }),
      ).toThrow(ForbiddenException);
    });
  });

  describe('锁 7 客户端签名自检', () => {
    it('64 字符 hex hash 应返回配置', () => {
      const hash = 'a'.repeat(64);
      const config = service.configureClientSignatureCheck(hash);
      expect(config.expectedSignatureHash).toBe(hash);
      expect(config.actionOnMismatch).toBe('PACKAGE_TAMPERED');
    });

    it('非 64 字符 hash 应抛 BadRequestException', () => {
      expect(() => service.configureClientSignatureCheck('short')).toThrow(BadRequestException);
    });

    it('空 hash 应抛 BadRequestException', () => {
      expect(() => service.configureClientSignatureCheck('')).toThrow(BadRequestException);
    });
  });
});
