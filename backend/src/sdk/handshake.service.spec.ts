import { Test } from '@nestjs/testing';
import { NotFoundException, BadRequestException } from '@nestjs/common';
import * as crypto from 'crypto';
import { HandshakeService } from './handshake.service';
import { RedisService } from '../redis/redis.service';
import { CryptoService } from '../crypto/crypto.service';
import { PrismaService } from '../prisma/prisma.service';

/**
 * HandshakeService 单元测试
 *
 * 覆盖 ADR 0020 (通信加密) 的握手流程:
 *  - APP_NOT_FOUND( appId 不存在)
 *  - RSA 解密失败(RSA_DECRYPT_FAILED)
 *  - AES 密钥长度非 32(INVALID_AES_KEY_LENGTH)
 *  - 成功握手(sessionId 返回 + Redis 存储)
 *  - getSession(存在 / 不存在)
 *  - revokeSession
 *  - refreshSession(续期 / 密钥轮换 / 会话不存在)
 */
describe('HandshakeService', () => {
  let service: HandshakeService;
  let redisService: { set: jest.Mock; get: jest.Mock; del: jest.Mock; client: { expire: jest.Mock } };
  let cryptoService: {
    rsaDecrypt: jest.Mock;
    generateSessionId: jest.Mock;
    generateAesKey: jest.Mock;
    sessionTtl: number;
  };
  let prismaService: {
    $transaction: jest.Mock;
  };

  const aesKey = crypto.randomBytes(32);
  const appId = 'app-1';
  const developerId = 'dev-1';

  beforeEach(async () => {
    redisService = {
      set: jest.fn().mockResolvedValue(undefined),
      get: jest.fn().mockResolvedValue(null),
      del: jest.fn().mockResolvedValue(1),
      client: { expire: jest.fn().mockResolvedValue(true) },
    };
    cryptoService = {
      rsaDecrypt: jest.fn(() => aesKey),
      generateSessionId: jest.fn().mockReturnValue('a'.repeat(64)),
      generateAesKey: jest.fn().mockReturnValue(crypto.randomBytes(32)),
      sessionTtl: 3600,
    };
    prismaService = {
      $transaction: jest.fn().mockImplementation(async (fn) => {
        const tx = {
          $executeRaw: jest.fn().mockResolvedValue(undefined),
          application: {
            findUnique: jest.fn().mockResolvedValue({ id: appId, developerId }),
          },
        };
        return fn(tx);
      }),
    };

    const moduleRef = await Test.createTestingModule({
      providers: [
        HandshakeService,
        { provide: RedisService, useValue: redisService },
        { provide: CryptoService, useValue: cryptoService },
        { provide: PrismaService, useValue: prismaService },
      ],
    }).compile();
    service = moduleRef.get(HandshakeService);
  });

  describe('handshake', () => {
    it('APP 不存在应拒绝(APP_NOT_FOUND)', async () => {
      prismaService.$transaction.mockImplementation(async (fn) => {
        const tx = {
          $executeRaw: jest.fn().mockResolvedValue(undefined),
          application: {
            findUnique: jest.fn().mockResolvedValue(null),
          },
        };
        return fn(tx);
      });

      await expect(
        service.handshake('encrypted-base64', appId),
      ).rejects.toThrow(NotFoundException);
    });

    it('RSA 解密失败应拒绝(RSA_DECRYPT_FAILED)', async () => {
      cryptoService.rsaDecrypt.mockImplementation(() => {
        throw new Error('rsa decrypt failed');
      });
      await expect(service.handshake('bad-encrypted', appId)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('AES 密钥长度非 32 应拒绝(INVALID_AES_KEY_LENGTH)', async () => {
      cryptoService.rsaDecrypt.mockReturnValue(crypto.randomBytes(16)); // 16 字节,非 32
      await expect(service.handshake('encrypted', appId)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('成功握手应返回 sessionId 并存 Redis', async () => {
      const result = await service.handshake('encrypted', appId);
      expect(result).toEqual({ sessionId: 'a'.repeat(64) });
      expect(redisService.set).toHaveBeenCalledWith(
        `sdk_session:${'a'.repeat(64)}`,
        expect.any(String),
        3600,
      );
      // 存入 Redis 的数据应包含 aesKey(hex)+ appId + developerId
      const stored = redisService.set.mock.calls[0][1];
      const parsed = JSON.parse(stored);
      expect(parsed.aesKey).toBe(aesKey.toString('hex'));
      expect(parsed.appId).toBe(appId);
      expect(parsed.developerId).toBe(developerId);
      expect(parsed.createdAt).toBeDefined();
    });
  });

  describe('getSession', () => {
    it('会话不存在应返回 null', async () => {
      redisService.get.mockResolvedValue(null);
      const result = await service.getSession('sess-1');
      expect(result).toBeNull();
    });

    it('Redis 数据损坏应返回 null(不抛错)', async () => {
      redisService.get.mockResolvedValue('not-json');
      const result = await service.getSession('sess-1');
      expect(result).toBeNull();
    });

    it('有效会话应返回 { aesKey, appId, developerId }', async () => {
      const sessionData = {
        aesKey: aesKey.toString('hex'),
        appId,
        developerId,
        createdAt: Date.now(),
      };
      redisService.get.mockResolvedValue(JSON.stringify(sessionData));
      const result = await service.getSession('sess-1');
      expect(result).toEqual({
        aesKey,
        appId,
        developerId,
      });
    });
  });

  describe('revokeSession', () => {
    it('应调用 redis.del 删除会话', async () => {
      await service.revokeSession('sess-1');
      expect(redisService.del).toHaveBeenCalledWith('sdk_session:sess-1');
    });
  });

  describe('refreshSession', () => {
    const sessionId = 'sess-1';
    const sessionData = {
      aesKey: aesKey.toString('hex'),
      appId,
      developerId,
      createdAt: Date.now(),
    };

    it('会话不存在应返回 null', async () => {
      redisService.get.mockResolvedValue(null);
      const result = await service.refreshSession(sessionId);
      expect(result).toBeNull();
    });

    it('Redis 数据损坏应返回 null', async () => {
      redisService.get.mockResolvedValue('not-json');
      const result = await service.refreshSession(sessionId);
      expect(result).toBeNull();
    });

    it('未到轮换时间应只续期 TTL,不轮换密钥', async () => {
      redisService.get.mockResolvedValue(
        JSON.stringify({ ...sessionData, rotatedAt: Date.now() }),
      );
      const result = await service.refreshSession(sessionId);
      expect(result).toBeDefined();
      expect(result?.expiresAt).toBeInstanceOf(Date);
      expect(result?.newAesKey).toBeUndefined();
      expect(redisService.client.expire).toHaveBeenCalledWith(
        `sdk_session:${sessionId}`,
        3600,
      );
      expect(cryptoService.generateAesKey).not.toHaveBeenCalled();
    });

    it('超过 20 分钟应轮换密钥 + 写回 Redis', async () => {
      redisService.get.mockResolvedValue(
        JSON.stringify({
          ...sessionData,
          rotatedAt: Date.now() - 25 * 60 * 1000, // 25 分钟前
        }),
      );
      const newKey = crypto.randomBytes(32);
      cryptoService.generateAesKey.mockReturnValue(newKey);

      const result = await service.refreshSession(sessionId);
      expect(result?.newAesKey).toBe(newKey.toString('base64'));
      expect(cryptoService.generateAesKey).toHaveBeenCalled();
      expect(redisService.set).toHaveBeenCalledWith(
        `sdk_session:${sessionId}`,
        expect.any(String),
        3600,
      );
      // 写回的 Redis 数据应包含新 aesKey
      const stored = redisService.set.mock.calls[0][1];
      const parsed = JSON.parse(stored);
      expect(parsed.aesKey).toBe(newKey.toString('hex'));
      expect(parsed.rotatedAt).toBeDefined();
    });

    it('无 rotatedAt 用 createdAt 计算(向后兼容)', async () => {
      redisService.get.mockResolvedValue(
        JSON.stringify({
          ...sessionData,
          createdAt: Date.now() - 25 * 60 * 1000, // createdAt 25 分钟前
          // 无 rotatedAt
        }),
      );
      const newKey = crypto.randomBytes(32);
      cryptoService.generateAesKey.mockReturnValue(newKey);

      const result = await service.refreshSession(sessionId);
      expect(result?.newAesKey).toBe(newKey.toString('base64'));
    });
  });
});
