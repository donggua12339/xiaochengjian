import { Test } from '@nestjs/testing';
import { NotFoundException, BadRequestException, UnauthorizedException } from '@nestjs/common';
import { SdkService } from './sdk.service';
import { TenantPrismaService } from '../tenant/tenant-prisma.service';
import { generateCardKey, generateCardSalt, hashCardKey } from '../card-key/card-key-generator';

/**
 * SdkService 单元测试
 *
 * 覆盖 ADR 0013 (卡密类型) / 0015 (设备绑定) / 0017 (离线验证) 的核心逻辑:
 *
 * activate:
 *  - 卡密格式错误(INVALID_CARD_KEY_FORMAT)
 *  - 卡密不存在(CARD_NOT_FOUND)
 *  - 卡密已禁用(CARD_DISABLED)
 *  - 试用卡已被其他设备认领(TRIAL_ALREADY_CLAIMED_BY_OTHER_DEVICE)
 *  - FIRST_BIND 策略:已绑其他设备(CARD_ALREADY_BOUND_TO_OTHER_DEVICE)
 *  - N_DEVICES 策略:超过设备数上限(MAX_DEVICES_REACHED)
 *  - 成功激活(NONE / FIRST_BIND / N_DEVICES 各一)
 *  - 首次激活设置 activatedAt + expiresAt
 *  - 重复激活不重置 expiresAt
 *
 * validate:
 *  - 卡密已过期(CARD_EXPIRED)
 *  - 设备未绑定(DEVICE_NOT_BOUND)
 *  - 成功验证 + 刷新 cacheKey
 */
describe('SdkService', () => {
  let service: SdkService;
  let tenantPrisma: {
    tx: jest.Mock;
  };

  /** 构造 mock 卡密 + 设备 + 绑定。plainKey 是卡密明文,用于算 hash + salt */
  function buildCardKeyRecord(plainKey: string, overrides: Partial<any> = {}): any {
    const salt = generateCardSalt();
    return {
      id: 'card-1',
      appId: 'app-1',
      developerId: 'dev-1',
      type: 'MONTH',
      status: 'ACTIVE',
      cardKeyHash: hashCardKey(plainKey, salt),
      cardSalt: salt,
      cardKeyPrefix: plainKey.replace(/-/g, '').substring(0, 4).toUpperCase(),
      bindingStrategy: 'NONE',
      maxDevices: 1,
      activatedAt: null,
      expiresAt: null,
      trialClaimedDeviceId: null,
      ...overrides,
    };
  }

  /** 模拟 Prisma tx 客户端 */
  function buildTx(cardKeyRecord: any | null, device: any | null = null, bindings: any[] = []) {
    const application = {
      findUnique: jest.fn().mockResolvedValue({ offlineCacheDays: 7 }),
    };
    const cardKey = {
      findMany: jest.fn().mockResolvedValue(cardKeyRecord ? [cardKeyRecord] : []),
      update: jest.fn().mockResolvedValue(undefined),
    };
    const deviceRepo = {
      upsert: jest.fn().mockResolvedValue(device ?? { id: 'dev-1', appId: 'app-1', machineId: 'm1' }),
      findUnique: jest.fn().mockResolvedValue(device),
      update: jest.fn().mockResolvedValue(undefined),
    };
    const deviceBinding = {
      findMany: jest.fn().mockResolvedValue(bindings),
      // findUnique 默认返回 bindings[0](若有),否则 null
      findUnique: jest.fn().mockResolvedValue(bindings[0] ?? null),
      create: jest.fn().mockResolvedValue(undefined),
    };
    const validationLog = {
      create: jest.fn().mockResolvedValue(undefined),
    };
    return {
      application,
      cardKey,
      device: deviceRepo,
      deviceBinding,
      validationLog,
    };
  }

  /** 从 mock tx 提取业务函数调用 */
  async function callActivate(_txMock: any, cardKeyPlain: string, machineId = 'm1') {
    return service.activate({
      appId: 'app-1',
      developerId: 'dev-1',
      cardKey: cardKeyPlain,
      machineId,
      fingerprintHash: 'fp-hash',
      ip: '127.0.0.1',
      userAgent: 'test',
    });
  }

  async function callValidate(_txMock: any, cardKeyPlain: string, machineId = 'm1') {
    return service.validate({
      appId: 'app-1',
      developerId: 'dev-1',
      cardKey: cardKeyPlain,
      machineId,
      ip: '127.0.0.1',
      userAgent: 'test',
    });
  }

  beforeEach(async () => {
    tenantPrisma = {
      tx: jest.fn().mockImplementation(async (_tenantId: string, fn: (tx: any) => Promise<any>) => {
        // 默认返回空 tx,具体由测试用 jest.mockImplementation 覆盖
        const tx = buildTx(null);
        return fn(tx);
      }),
    };

    const moduleRef = await Test.createTestingModule({
      providers: [
        SdkService,
        { provide: TenantPrismaService, useValue: tenantPrisma },
      ],
    }).compile();
    service = moduleRef.get(SdkService);
  });

  describe('activate - 错误路径', () => {
    it('卡密格式错误应拒绝(INVALID_CARD_KEY_FORMAT)', async () => {
      await expect(callActivate(buildTx(null), 'BAD-FORMAT')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('卡密不存在应拒绝(CARD_NOT_FOUND)', async () => {
      const tx = buildTx(null);
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
        fn(tx),
      );
      const validKey = generateCardKey();
      await expect(callActivate(tx, validKey)).rejects.toThrow(NotFoundException);
      // 应写入失败日志
      expect(tx.validationLog.create).toHaveBeenCalled();
    });

    it('卡密已禁用应拒绝(CARD_DISABLED)', async () => {
      const validKey = generateCardKey();
      const card = buildCardKeyRecord(validKey, { status: 'DISABLED' });
      const tx = buildTx(card);
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
        fn(tx),
      );
      await expect(callActivate(tx, validKey)).rejects.toThrow(UnauthorizedException);
    });

    it('试用卡已被其他设备认领应拒绝(TRIAL_ALREADY_CLAIMED)', async () => {
      const validKey = generateCardKey();
      const card = buildCardKeyRecord(validKey, {
        type: 'TRIAL',
        trialClaimedDeviceId: 'other-device',
      });
      const tx = buildTx(card);
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
        fn(tx),
      );
      await expect(callActivate(tx, validKey, 'm1')).rejects.toThrow(BadRequestException);
    });

    it('FIRST_BIND 策略:已绑其他设备应拒绝', async () => {
      const validKey = generateCardKey();
      const card = buildCardKeyRecord(validKey, {
        bindingStrategy: 'FIRST_BIND',
        maxDevices: 1,
      });
      // 模拟已绑定到另一个设备
      const tx = buildTx(card, { id: 'dev-1', appId: 'app-1', machineId: 'm1' }, [
        { id: 'bind-1', cardKeyId: card.id, deviceId: 'dev-other' },
      ]);
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
        fn(tx),
      );
      await expect(callActivate(tx, validKey, 'm1')).rejects.toThrow(BadRequestException);
    });

    it('N_DEVICES 策略:超过设备数上限应拒绝', async () => {
      const validKey = generateCardKey();
      const card = buildCardKeyRecord(validKey, {
        bindingStrategy: 'N_DEVICES',
        maxDevices: 2,
      });
      // 模拟已绑 2 个设备
      const bindings = [
        { id: 'b1', cardKeyId: card.id, deviceId: 'dev-1' },
        { id: 'b2', cardKeyId: card.id, deviceId: 'dev-2' },
      ];
      const tx = buildTx(card, { id: 'dev-3', appId: 'app-1', machineId: 'm3' }, bindings);
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
        fn(tx),
      );
      await expect(callActivate(tx, validKey, 'm3')).rejects.toThrow(BadRequestException);
    });
  });

  describe('activate - 成功路径', () => {
    it('NONE 策略应成功激活并返回 cacheKey + 有效期', async () => {
      const validKey = generateCardKey();
      const card = buildCardKeyRecord(validKey, { bindingStrategy: 'NONE' });
      const tx = buildTx(card, null, []);
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
        fn(tx),
      );
      const result = await callActivate(tx, validKey);
      expect(result.success).toBe(true);
      expect(result.cardType).toBe('MONTH');
      expect(result.expiresAt).toBeInstanceOf(Date);
      expect(result.cacheKey).toMatch(/^[0-9a-f]{64}$/);
      expect(result.offlineCacheDays).toBe(7);
      // 首次激活应设置 activatedAt + expiresAt
      expect(tx.cardKey.update).toHaveBeenCalledWith({
        where: { id: card.id },
        data: expect.objectContaining({
          activatedAt: expect.any(Date),
          expiresAt: expect.any(Date),
        }),
      });
    });

    it('重复激活不应重置 activatedAt + expiresAt', async () => {
      const validKey = generateCardKey();
      const originalExpiry = new Date('2026-12-31');
      const card = buildCardKeyRecord(validKey, {
        bindingStrategy: 'NONE',
        activatedAt: new Date('2026-01-01'),
        expiresAt: originalExpiry,
      });
      const tx = buildTx(card, null, []);
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
        fn(tx),
      );
      const result = await callActivate(tx, validKey);
      expect(result.expiresAt).toBe(originalExpiry);
      // 不应调用 update(因为已激活过)
      expect(tx.cardKey.update).not.toHaveBeenCalled();
    });

    it('FIRST_BIND 策略:首次绑定应成功 + 创建绑定记录', async () => {
      const validKey = generateCardKey();
      const card = buildCardKeyRecord(validKey, { bindingStrategy: 'FIRST_BIND', maxDevices: 1 });
      const device = { id: 'dev-1', appId: 'app-1', machineId: 'm1' };
      const tx = buildTx(card, device, []);
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
        fn(tx),
      );
      const result = await callActivate(tx, validKey, 'm1');
      expect(result.success).toBe(true);
      expect(tx.deviceBinding.create).toHaveBeenCalled();
    });

    it('N_DEVICES 策略:未达上限应成功 + 创建绑定记录', async () => {
      const validKey = generateCardKey();
      const card = buildCardKeyRecord(validKey, {
        bindingStrategy: 'N_DEVICES',
        maxDevices: 3,
      });
      const device = { id: 'dev-3', appId: 'app-1', machineId: 'm3' };
      // 已绑 2 个设备(< 3 上限)
      const bindings = [
        { id: 'b1', cardKeyId: card.id, deviceId: 'dev-1' },
        { id: 'b2', cardKeyId: card.id, deviceId: 'dev-2' },
      ];
      const tx = buildTx(card, device, bindings);
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
        fn(tx),
      );
      const result = await callActivate(tx, validKey, 'm3');
      expect(result.success).toBe(true);
      expect(tx.deviceBinding.create).toHaveBeenCalled();
    });

    it('N_DEVICES 策略:已绑本设备应成功(不重复创建绑定)', async () => {
      const validKey = generateCardKey();
      const card = buildCardKeyRecord(validKey, {
        bindingStrategy: 'N_DEVICES',
        maxDevices: 3,
        activatedAt: new Date('2026-01-01'),
        expiresAt: new Date('2026-12-31'),
      });
      const device = { id: 'dev-1', appId: 'app-1', machineId: 'm1' };
      // 已绑本设备
      const bindings = [{ id: 'b1', cardKeyId: card.id, deviceId: 'dev-1' }];
      const tx = buildTx(card, device, bindings);
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
        fn(tx),
      );
      const result = await callActivate(tx, validKey, 'm1');
      expect(result.success).toBe(true);
      // 不应重复创建绑定
      expect(tx.deviceBinding.create).not.toHaveBeenCalled();
    });

    it('TRIAL 卡:首次认领应成功 + 设置 trialClaimedDeviceId', async () => {
      const validKey = generateCardKey();
      const card = buildCardKeyRecord(validKey, { type: 'TRIAL', trialClaimedDeviceId: null });
      const tx = buildTx(card, null, []);
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
        fn(tx),
      );
      const result = await callActivate(tx, validKey, 'm1');
      expect(result.success).toBe(true);
      expect(tx.cardKey.update).toHaveBeenCalledWith({
        where: { id: card.id },
        data: expect.objectContaining({
          trialClaimedDeviceId: 'm1',
        }),
      });
    });

    it('PERMANENT 卡:expiresAt 应为 null', async () => {
      const validKey = generateCardKey();
      const card = buildCardKeyRecord(validKey, { type: 'PERMANENT' });
      const tx = buildTx(card, null, []);
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
        fn(tx),
      );
      const result = await callActivate(tx, validKey);
      expect(result.expiresAt).toBeNull();
    });

    it('成功激活应写入 validation_log(success=true)', async () => {
      const validKey = generateCardKey();
      const card = buildCardKeyRecord(validKey, { bindingStrategy: 'NONE' });
      const tx = buildTx(card, null, []);
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
        fn(tx),
      );
      await callActivate(tx, validKey);
      expect(tx.validationLog.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          success: true,
          failReason: null,
        }),
      });
    });
  });

  describe('validate - 错误路径', () => {
    it('卡密格式错误应拒绝', async () => {
      await expect(callValidate(buildTx(null), 'BAD')).rejects.toThrow(BadRequestException);
    });

    it('卡密不存在应拒绝', async () => {
      const tx = buildTx(null);
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
        fn(tx),
      );
      await expect(callValidate(tx, generateCardKey())).rejects.toThrow(NotFoundException);
    });

    it('卡密已禁用应返回 valid=false + CARD_DISABLED', async () => {
      const validKey = generateCardKey();
      const card = buildCardKeyRecord(validKey, { status: 'DISABLED' });
      const tx = buildTx(card);
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
        fn(tx),
      );
      const result = await callValidate(tx, validKey);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('CARD_DISABLED');
    });

    it('卡密已过期应返回 valid=false + CARD_EXPIRED', async () => {
      const validKey = generateCardKey();
      const card = buildCardKeyRecord(validKey, {
        status: 'ACTIVE',
        expiresAt: new Date('2020-01-01'), // 过期
      });
      const tx = buildTx(card);
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
        fn(tx),
      );
      const result = await callValidate(tx, validKey);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('CARD_EXPIRED');
    });

    it('设备未绑定时应返回 valid=false + DEVICE_NOT_BOUND', async () => {
      const validKey = generateCardKey();
      const card = buildCardKeyRecord(validKey, {
        status: 'ACTIVE',
        bindingStrategy: 'FIRST_BIND',
        activatedAt: new Date('2026-01-01'),
        expiresAt: new Date('2027-01-01'),
      });
      // 设备不存在 + 卡密已激活
      const tx = buildTx(card, null, []);
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
        fn(tx),
      );
      const result = await callValidate(tx, validKey, 'm-new');
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('DEVICE_NOT_BOUND');
    });
  });

  describe('validate - 成功路径', () => {
    it('有效卡密 + 已绑设备应返回 valid=true + 刷新 cacheKey', async () => {
      const validKey = generateCardKey();
      const card = buildCardKeyRecord(validKey, {
        status: 'ACTIVE',
        bindingStrategy: 'FIRST_BIND',
        activatedAt: new Date('2026-01-01'),
        expiresAt: new Date('2027-01-01'),
      });
      const device = { id: 'dev-1', appId: 'app-1', machineId: 'm1' };
      const bindings = [{ id: 'b1', cardKeyId: card.id, deviceId: 'dev-1' }];
      const tx = buildTx(card, device, bindings);
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
        fn(tx),
      );
      const result = await callValidate(tx, validKey, 'm1');
      expect(result.valid).toBe(true);
      expect(result.cacheKey).toMatch(/^[0-9a-f]{64}$/);
      expect(result.expiresAt).toEqual(card.expiresAt);
      expect(tx.device.update).toHaveBeenCalledWith({
        where: { id: device.id },
        data: { lastSeenAt: expect.any(Date) },
      });
    });

    it('NONE 策略:设备不存在时应补建设备记录', async () => {
      const validKey = generateCardKey();
      const card = buildCardKeyRecord(validKey, {
        status: 'ACTIVE',
        bindingStrategy: 'NONE',
        activatedAt: new Date('2026-01-01'),
        expiresAt: new Date('2027-01-01'),
      });
      const tx = buildTx(card, null, []);
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
        fn(tx),
      );
      const result = await callValidate(tx, validKey, 'm-new');
      expect(result.valid).toBe(true);
      expect(tx.device.upsert).toHaveBeenCalled();
    });
  });

  describe('computeExpiry - 卡密类型对应有效期', () => {
    it.each([
      ['DAY', 1],
      ['WEEK', 7],
      ['MONTH', 30],
    ])('%s 卡应激活后 %s 天后过期', async (type, days) => {
      const validKey = generateCardKey();
      const card = buildCardKeyRecord(validKey, { type: type as any });
      const tx = buildTx(card, null, []);
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
        fn(tx),
      );
      const before = Date.now();
      const result = await callActivate(tx, validKey);
      const after = Date.now();
      const expectedMin = before + days * 24 * 60 * 60 * 1000;
      const expectedMax = after + days * 24 * 60 * 60 * 1000;
      expect(result.expiresAt?.getTime()).toBeGreaterThanOrEqual(expectedMin);
      expect(result.expiresAt?.getTime()).toBeLessThanOrEqual(expectedMax);
    });

    it('PERMANENT / TRIAL 卡应 expiresAt=null', async () => {
      for (const type of ['PERMANENT', 'TRIAL']) {
        const validKey = generateCardKey();
        const card = buildCardKeyRecord(validKey, { type: type as any });
        const tx = buildTx(card, null, []);
        tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
          fn(tx),
        );
        const result = await callActivate(tx, validKey);
        expect(result.expiresAt).toBeNull();
      }
    });
  });

  describe('日志哈希不泄露明文', () => {
    it('validation_log 的 cardKeyHash 应用固定 salt,不含明文', async () => {
      const validKey = generateCardKey();
      const card = buildCardKeyRecord(validKey, { bindingStrategy: 'NONE' });
      const tx = buildTx(card, null, []);
      tenantPrisma.tx.mockImplementation(async (_t: string, fn: (tx: any) => Promise<any>) =>
        fn(tx),
      );
      await callActivate(tx, validKey);
      const logCall = tx.validationLog.create.mock.calls[0][0];
      // 日志里的 cardKeyHash = hashCardKey(plainKey, 'log'),不应含明文
      expect(logCall.data.cardKeyHash).not.toContain(validKey);
      expect(logCall.data.cardKeyHash).toBe(hashCardKey(validKey, 'log'));
    });
  });
});
