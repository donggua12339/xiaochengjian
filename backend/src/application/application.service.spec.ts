import { Test } from '@nestjs/testing';
import {
  ConflictException,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { ApplicationService } from './application.service';
import { PrismaService } from '../prisma/prisma.service';
import { TenantPrismaService } from '../tenant/tenant-prisma.service';
import type { CreateAppDto, UpdateAppDto } from './dto/app.dto';

/**
 * ApplicationService 单元测试
 *
 * 覆盖:
 *  - create: DEVELOPER_NOT_FOUND / APP_LIMIT_REACHED / PACKAGE_NAME_ALREADY_USED / 正常(返回明文 appSecret + prefix)
 *  - list: 返回响应 DTO(不含 appSecretHash)+ hasSignHashAllowList 标志
 *  - getById: 正常 / APP_NOT_FOUND
 *  - update: 正常 / APP_NOT_FOUND / 字段透传 / 未提供字段不出现
 *  - delete: 正常 / APP_NOT_FOUND
 *  - rotateSecret: 正常 / APP_NOT_FOUND
 *  - toResponse: appSecretHash 不暴露 / appSecretPrefix 日常为空
 */
describe('ApplicationService', () => {
  let service: ApplicationService;
  let prisma: { developer: { findUnique: jest.Mock } };
  let tenantPrisma: { tx: jest.Mock };

  const developerId = 'dev-1';
  const appId = 'app-1';

  function buildAppRow(overrides: Partial<any> = {}) {
    return {
      id: appId,
      developerId,
      name: '测试应用',
      packageName: 'com.xcj.test',
      appSecretHash: '$argon2id$mock-hash',
      signHashAllowList: [],
      rateLimitIpPerMinute: null,
      rateLimitDevicePerMinute: null,
      rateLimitFailLockThreshold: null,
      rateLimitFailLockTtl: null,
      offlineCacheDays: 7,
      sdkRsaPublicKeyHash: null,
      createdAt: new Date('2026-01-01'),
      updatedAt: new Date('2026-01-01'),
      ...overrides,
    };
  }

  function buildTx(opts: { application?: any | null; count?: number } = {}) {
    return {
      application: {
        findUnique: jest.fn().mockResolvedValue(opts.application ?? null),
        findMany: jest.fn().mockResolvedValue(opts.application ? [opts.application] : []),
        create: jest.fn().mockResolvedValue({
          id: appId,
          name: '测试应用',
          packageName: 'com.xcj.test',
          offlineCacheDays: 7,
          createdAt: new Date('2026-01-01'),
          updatedAt: new Date('2026-01-01'),
        }),
        update: jest.fn().mockResolvedValue(opts.application ?? buildAppRow()),
        delete: jest.fn().mockResolvedValue(undefined),
        count: jest.fn().mockResolvedValue(opts.count ?? 0),
      },
    };
  }

  function setTxMock(tx: any) {
    tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
      fn(tx),
    );
  }

  beforeEach(async () => {
    prisma = {
      developer: {
        findUnique: jest.fn().mockResolvedValue({ id: developerId, maxApps: 10 }),
      },
    };
    tenantPrisma = { tx: jest.fn() };

    const moduleRef = await Test.createTestingModule({
      providers: [
        ApplicationService,
        { provide: PrismaService, useValue: prisma },
        { provide: TenantPrismaService, useValue: tenantPrisma },
      ],
    }).compile();
    service = moduleRef.get(ApplicationService);
  });

  describe('create', () => {
    const dto: CreateAppDto = {
      name: '测试应用',
      packageName: 'com.xcj.test',
    };

    it('developer 不存在应拒绝(DEVELOPER_NOT_FOUND)', async () => {
      prisma.developer.findUnique.mockResolvedValue(null);
      await expect(service.create(developerId, dto)).rejects.toThrow(NotFoundException);
    });

    it('达到 maxApps 上限应拒绝(APP_LIMIT_REACHED)', async () => {
      prisma.developer.findUnique.mockResolvedValue({ id: developerId, maxApps: 3 });
      const tx = buildTx({ count: 3 });
      setTxMock(tx);
      await expect(service.create(developerId, dto)).rejects.toThrow(ForbiddenException);
    });

    it('包名已存在应拒绝(PACKAGE_NAME_ALREADY_USED)', async () => {
      const tx = buildTx();
      let callCount = 0;
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) => {
        callCount++;
        if (callCount === 1) return fn(tx); // count
        // create 内部 findUnique 返回已存在
        const txWithExisting = {
          application: {
            ...tx.application,
            findUnique: jest.fn().mockResolvedValue({ id: 'other-app' }),
          },
        };
        return fn(txWithExisting);
      });
      await expect(service.create(developerId, dto)).rejects.toThrow(ConflictException);
    });

    it('正常创建应返回明文 appSecret + prefix', async () => {
      const tx = buildTx();
      let callCount = 0;
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) => {
        callCount++;
        if (callCount === 1) return fn(tx); // count
        const txCreate = {
          application: {
            ...tx.application,
            findUnique: jest.fn().mockResolvedValue(null),
          },
        };
        return fn(txCreate);
      });

      const result = await service.create(developerId, dto);
      expect(result.id).toBe(appId);
      expect(result.appSecret).toBeDefined();
      expect(result.appSecret.length).toBe(32);
      expect(result.appSecretPrefix).toBe(result.appSecret.substring(0, 4));
      expect((result as any).appSecretHash).toBeUndefined();
    });

    it('生成的 appSecret 应为字母数字(32 字符)', async () => {
      const tx = buildTx();
      let callCount = 0;
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) => {
        callCount++;
        if (callCount === 1) return fn(tx);
        const txCreate = {
          application: {
            ...tx.application,
            findUnique: jest.fn().mockResolvedValue(null),
          },
        };
        return fn(txCreate);
      });
      const result = await service.create(developerId, dto);
      expect(result.appSecret).toMatch(/^[A-Za-z0-9]{32}$/);
    });
  });

  describe('list', () => {
    it('应返回响应 DTO 列表,不含 appSecretHash', async () => {
      const tx = buildTx({ application: buildAppRow() });
      setTxMock(tx);
      const result = await service.list(developerId);
      expect(result).toHaveLength(1);
      expect(result[0].id).toBe(appId);
      expect((result[0] as any).appSecretHash).toBeUndefined();
      expect(result[0].hasSignHashAllowList).toBe(false);
    });

    it('signHashAllowList 非空时 hasSignHashAllowList 应为 true', async () => {
      const tx = buildTx({
        application: buildAppRow({ signHashAllowList: ['sha256:abc'] }),
      });
      setTxMock(tx);
      const result = await service.list(developerId);
      expect(result[0].hasSignHashAllowList).toBe(true);
    });
  });

  describe('getById', () => {
    it('正常返回应用详情', async () => {
      const tx = buildTx({ application: buildAppRow() });
      setTxMock(tx);
      const result = await service.getById(developerId, appId);
      expect(result.id).toBe(appId);
      expect((result as any).appSecretHash).toBeUndefined();
    });

    it('应用不存在应拒绝(APP_NOT_FOUND)', async () => {
      const tx = buildTx({ application: null });
      setTxMock(tx);
      await expect(service.getById(developerId, appId)).rejects.toThrow(NotFoundException);
    });
  });

  describe('update', () => {
    it('应用不存在应拒绝', async () => {
      const tx = buildTx({ application: null });
      setTxMock(tx);
      await expect(
        service.update(developerId, appId, { name: '新名称' }),
      ).rejects.toThrow(NotFoundException);
    });

    it('正常更新应透传字段', async () => {
      const tx = buildTx({ application: buildAppRow() });
      setTxMock(tx);
      const dto: UpdateAppDto = {
        name: '新名称',
        offlineCacheDays: 14,
        rateLimitIpPerMinute: 100,
        signHashAllowList: ['sha256:abc'],
      };
      await service.update(developerId, appId, dto);
      expect(tx.application.update).toHaveBeenCalledWith({
        where: { id: appId },
        data: expect.objectContaining({
          name: '新名称',
          offlineCacheDays: 14,
          rateLimitIpPerMinute: 100,
          signHashAllowList: ['sha256:abc'],
        }),
      });
    });

    it('未提供的字段不应出现在 update data', async () => {
      const tx = buildTx({ application: buildAppRow() });
      setTxMock(tx);
      await service.update(developerId, appId, { name: '只改名字' });
      const updateCall = tx.application.update.mock.calls[0][0].data;
      expect(updateCall.name).toBe('只改名字');
      expect('offlineCacheDays' in updateCall).toBe(false);
      expect('rateLimitIpPerMinute' in updateCall).toBe(false);
    });

    it('sdkRsaPublicKeyHash 可更新', async () => {
      const tx = buildTx({ application: buildAppRow() });
      setTxMock(tx);
      await service.update(developerId, appId, { sdkRsaPublicKeyHash: 'sha256:new' });
      expect(tx.application.update).toHaveBeenCalledWith({
        where: { id: appId },
        data: expect.objectContaining({ sdkRsaPublicKeyHash: 'sha256:new' }),
      });
    });
  });

  describe('delete', () => {
    it('正常删除', async () => {
      const tx = buildTx({ application: buildAppRow() });
      setTxMock(tx);
      await service.delete(developerId, appId);
      expect(tx.application.delete).toHaveBeenCalledWith({ where: { id: appId } });
    });

    it('应用不存在应拒绝', async () => {
      const tx = buildTx({ application: null });
      setTxMock(tx);
      await expect(service.delete(developerId, appId)).rejects.toThrow(NotFoundException);
    });
  });

  describe('rotateSecret', () => {
    it('正常应返回新明文 + prefix', async () => {
      const tx = buildTx({ application: buildAppRow() });
      setTxMock(tx);
      const result = await service.rotateSecret(developerId, appId);
      expect(result.appSecret).toMatch(/^[A-Za-z0-9]{32}$/);
      expect(result.appSecretPrefix).toBe(result.appSecret.substring(0, 4));
      expect(tx.application.update).toHaveBeenCalledWith({
        where: { id: appId },
        data: expect.objectContaining({ appSecretHash: expect.any(String) }),
      });
    });

    it('应用不存在应拒绝', async () => {
      const tx = buildTx({ application: null });
      setTxMock(tx);
      await expect(service.rotateSecret(developerId, appId)).rejects.toThrow(NotFoundException);
    });
  });

  describe('toResponse(通过 list/getById 间接测)', () => {
    it('appSecretHash 不应出现在响应中', async () => {
      const tx = buildTx({ application: buildAppRow() });
      setTxMock(tx);
      const result = await service.getById(developerId, appId);
      expect(JSON.stringify(result)).not.toContain('appSecretHash');
      expect(JSON.stringify(result)).not.toContain('argon2');
    });

    it('appSecretPrefix 日常查询应为空(仅创建/重置时返回)', async () => {
      const tx = buildTx({ application: buildAppRow() });
      setTxMock(tx);
      const result = await service.getById(developerId, appId);
      expect(result.appSecretPrefix).toBe('');
    });
  });
});
