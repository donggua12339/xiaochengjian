import { Test } from '@nestjs/testing';
import { SdkController } from './sdk.controller';
import { HandshakeService } from './handshake.service';
import { SdkService } from './sdk.service';
import { SdkSignatureGuard } from './signature.guard';
import { CryptoService } from '../crypto/crypto.service';
import { PrismaService } from '../prisma/prisma.service';
import { UnauthorizedException, NotFoundException } from '@nestjs/common';

/**
 * SdkController 单元测试
 *
 * 覆盖 5 个端点的请求分发 + 响应加密:
 *  - handshake(无签名,直接调 service)
 *  - activate(需 SdkSignatureGuard,但测试绕过 guard,直接测 controller 逻辑)
 *  - validate(同上)
 *  - heartbeat(同上)
 *  - time(无签名,直接返回)
 *  - integrity(无签名,查 prisma)
 *  - encryptResponse(私有方法,通过 activate/validate 间接测)
 */
describe('SdkController', () => {
  let controller: SdkController;
  let handshakeService: { handshake: jest.Mock; refreshSession: jest.Mock };
  let sdkService: { activate: jest.Mock; validate: jest.Mock };
  let cryptoService: { aesEncrypt: jest.Mock; getPublicKeyPem: jest.Mock };
  let prismaService: { application: { findUnique: jest.Mock } };

  const aesKey = Buffer.alloc(32, 0xab);

  /** 模拟 SdkRequest(Guard 已挂载 _sdkSession) */
  function buildSdkRequest(overrides: Partial<any> = {}): any {
    return {
      _sdkSession: { aesKey, appId: 'app-1', developerId: 'dev-1' },
      headers: { 'user-agent': 'test-ua', 'x-session-id': 'sess-1' },
      body: { cardKey: 'XXXX-XXXX-XXXX-XXXX', machineId: 'm1', fingerprintHash: 'fp' },
      ...overrides,
    };
  }

  beforeEach(async () => {
    handshakeService = {
      handshake: jest.fn().mockResolvedValue({ sessionId: 'a'.repeat(64) }),
      refreshSession: jest.fn().mockResolvedValue({
        expiresAt: new Date('2026-12-31'),
      }),
    };
    sdkService = {
      activate: jest.fn().mockResolvedValue({
        success: true,
        cardType: 'MONTH',
        expiresAt: new Date('2026-12-31'),
        cacheKey: 'c'.repeat(64),
        offlineCacheDays: 7,
      }),
      validate: jest.fn().mockResolvedValue({
        success: true,
        valid: true,
        expiresAt: new Date('2026-12-31'),
        cacheKey: 'c'.repeat(64),
        offlineCacheDays: 7,
      }),
    };
    cryptoService = {
      aesEncrypt: jest.fn().mockImplementation((_key: Buffer, plaintext: Buffer) => {
        // 返回固定格式的 iv|ciphertext|tag
        const iv = Buffer.alloc(12, 0x11);
        const ciphertext = Buffer.from(plaintext); // 不真加密,只测试流程
        const tag = Buffer.alloc(16, 0x22);
        return { iv, ciphertext, tag };
      }),
      getPublicKeyPem: jest.fn().mockReturnValue(
        '-----BEGIN PUBLIC KEY-----\nMOCK_PUBLIC_KEY\n-----END PUBLIC KEY-----\n',
      ),
    };
    prismaService = {
      application: {
        findUnique: jest.fn().mockResolvedValue({
          signHashAllowList: ['sha256:abc123'],
          sdkRsaPublicKeyHash: 'sha256:def456',
        }),
      },
    };

    const moduleRef = await Test.createTestingModule({
      controllers: [SdkController],
      providers: [
        { provide: HandshakeService, useValue: handshakeService },
        { provide: SdkService, useValue: sdkService },
        { provide: CryptoService, useValue: cryptoService },
        { provide: PrismaService, useValue: prismaService },
      ],
    })
      // 跳过 SdkSignatureGuard(其逻辑在 signature.guard.spec.ts 单独测)
      .overrideGuard(SdkSignatureGuard)
      .useValue({ canActivate: () => true })
      .compile();
    controller = moduleRef.get(SdkController);
  });

  describe('handshake', () => {
    it('应调 handshakeService.handshake 并返回 sessionId', async () => {
      const result = await controller.handshake({ encryptedKey: 'base64-data', appId: 'app-1' });
      expect(result).toEqual({ sessionId: 'a'.repeat(64) });
      expect(handshakeService.handshake).toHaveBeenCalledWith('base64-data', 'app-1');
    });
  });

  describe('activate', () => {
    it('应调 sdkService.activate 并返回加密响应', async () => {
      const req = buildSdkRequest();
      const result = await controller.activate(req, req.body, '127.0.0.1');

      // 应调 sdkService.activate,参数从 _sdkSession + body + ip + ua 组装
      expect(sdkService.activate).toHaveBeenCalledWith({
        appId: 'app-1',
        developerId: 'dev-1',
        cardKey: 'XXXX-XXXX-XXXX-XXXX',
        machineId: 'm1',
        fingerprintHash: 'fp',
        deviceInfo: undefined,
        ip: '127.0.0.1',
        userAgent: 'test-ua',
      });

      // 应返回 { encryptedBody: Base64 } 格式
      expect(result).toHaveProperty('encryptedBody');
      expect(typeof result.encryptedBody).toBe('string');
      // aesEncrypt 应被调用
      expect(cryptoService.aesEncrypt).toHaveBeenCalled();
    });

    it('带 deviceInfo 应透传给 service', async () => {
      const req = buildSdkRequest({
        body: {
          cardKey: 'XXXX-XXXX-XXXX-XXXX',
          machineId: 'm1',
          fingerprintHash: 'fp',
          deviceInfo: '{"model":"Pixel"}',
        },
      });
      await controller.activate(req, req.body, '127.0.0.1');
      expect(sdkService.activate).toHaveBeenCalledWith(
        expect.objectContaining({ deviceInfo: '{"model":"Pixel"}' }),
      );
    });
  });

  describe('validate', () => {
    it('应调 sdkService.validate 并返回加密响应', async () => {
      const req = buildSdkRequest({
        body: { cardKey: 'XXXX-XXXX-XXXX-XXXX', machineId: 'm1' },
      });
      const result = await controller.validate(req, req.body, '127.0.0.1');

      expect(sdkService.validate).toHaveBeenCalledWith({
        appId: 'app-1',
        developerId: 'dev-1',
        cardKey: 'XXXX-XXXX-XXXX-XXXX',
        machineId: 'm1',
        ip: '127.0.0.1',
        userAgent: 'test-ua',
      });

      expect(result).toHaveProperty('encryptedBody');
    });
  });

  describe('heartbeat', () => {
    it('refreshSession 返回结果时应加密返回', async () => {
      const req = buildSdkRequest();
      const result = await controller.heartbeat(req);

      expect(handshakeService.refreshSession).toHaveBeenCalledWith('sess-1');
      expect(result).toHaveProperty('encryptedBody');
    });

    it('refreshSession 返回 null 应抛 SESSION_EXPIRED', async () => {
      handshakeService.refreshSession.mockResolvedValue(null);
      const req = buildSdkRequest();
      await expect(controller.heartbeat(req)).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('time', () => {
    it('应返回 timestamp + iso', async () => {
      const before = Math.floor(Date.now() / 1000);
      const result = await controller.time();
      const after = Math.floor(Date.now() / 1000);

      expect(result.timestamp).toBeGreaterThanOrEqual(before);
      expect(result.timestamp).toBeLessThanOrEqual(after);
      expect(result.iso).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    });
  });

  describe('integrity', () => {
    it('APP 存在应返回 signHashAllowList + sdkRsaPublicKeyHash', async () => {
      const result = await controller.integrity('app-1');
      expect(result).toEqual({
        signHashAllowList: ['sha256:abc123'],
        sdkRsaPublicKeyHash: 'sha256:def456',
      });
      expect(prismaService.application.findUnique).toHaveBeenCalledWith({
        where: { id: 'app-1' },
        select: { signHashAllowList: true, sdkRsaPublicKeyHash: true },
      });
    });

    it('APP 不存在应抛 NotFoundException', async () => {
      prismaService.application.findUnique.mockResolvedValueOnce(null);
      await expect(controller.integrity('not-exist')).rejects.toThrow(NotFoundException);
    });
  });

  describe('publicKey', () => {
    it('应返回 crypto.getPublicKeyPem 的结果', async () => {
      const result = await controller.publicKey();
      expect(cryptoService.getPublicKeyPem).toHaveBeenCalled();
      expect(result.publicKeyPem).toContain('-----BEGIN PUBLIC KEY-----');
      expect(result.publicKeyPem).toContain('MOCK_PUBLIC_KEY');
      expect(result.publicKeyPem).toContain('-----END PUBLIC KEY-----');
    });

    it('无需鉴权(公钥本就公开)', async () => {
      // publicKey 不应依赖 prisma 查询(无需 appId)
      const result = await controller.publicKey();
      expect(prismaService.application.findUnique).not.toHaveBeenCalled();
      expect(result).toBeDefined();
    });
  });

  describe('encryptResponse(私有方法,间接测)', () => {
    it('加密响应应为 Base64 编码的 iv|ciphertext|tag', async () => {
      const req = buildSdkRequest();
      const result = await controller.activate(req, req.body, '127.0.0.1');

      // Base64 解码后长度 = 12 (iv) + 明文长度 (ciphertext) + 16 (tag) > 28
      const decoded = Buffer.from(result.encryptedBody, 'base64');
      expect(decoded.length).toBeGreaterThan(12 + 16);
    });
  });
});
