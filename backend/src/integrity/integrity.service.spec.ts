import { IntegrityService } from './integrity.service';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import * as crypto from 'crypto';

describe('IntegrityService', () => {
  let service: IntegrityService;
  let prisma: { application: { findFirst: jest.Mock } };
  const configMap: Record<string, string | undefined> = {
    integrityTokenSecret: 'test-integrity-secret-32-chars-long!!',
  };

  function buildService() {
    const configService = {
      get: jest.fn((key: string) => configMap[key]),
    } as unknown as ConfigService;
    return new IntegrityService(prisma as unknown as PrismaService, configService);
  }

  beforeEach(() => {
    jest.clearAllMocks();
    prisma = { application: { findFirst: jest.fn() } };
    delete configMap.integrityRsaPrivateKey;
    delete configMap.integrityRsaPrivateKeyFile;
    service = buildService();
  });

  const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');

  describe('verifyAndIssueToken', () => {
    it('时间戳超窗口应 FAIL TIMESTAMP_EXPIRED', async () => {
      const r = await service.verifyAndIssueToken({
        appId: 'com.test',
        encryptedHash: b64('abc'),
        nonce: 'n',
        timestamp: Date.now() - 10 * 60 * 1000,
      });
      expect(r.verdict).toBe('FAIL');
      expect(r.reason).toBe('TIMESTAMP_EXPIRED');
    });

    it('应用未注册应 FAIL APP_NOT_REGISTERED', async () => {
      prisma.application.findFirst.mockResolvedValue(null);
      const r = await service.verifyAndIssueToken({
        appId: 'com.unknown',
        encryptedHash: b64('hash1'),
        nonce: 'n',
        timestamp: Date.now(),
      });
      expect(r.verdict).toBe('FAIL');
      expect(r.reason).toBe('APP_NOT_REGISTERED');
    });

    it('签名哈希不匹配应 FAIL SIGNATURE_MISMATCH', async () => {
      prisma.application.findFirst.mockResolvedValue({
        id: 'app-1',
        name: 'Test',
        signHashAllowList: ['allowed-hash'],
      });
      const r = await service.verifyAndIssueToken({
        appId: 'com.test',
        encryptedHash: b64('wrong-hash'),
        nonce: 'n',
        timestamp: Date.now(),
      });
      expect(r.verdict).toBe('FAIL');
      expect(r.reason).toBe('SIGNATURE_MISMATCH');
    });

    it('匹配应 PASS 并颁发可验证的 token', async () => {
      prisma.application.findFirst.mockResolvedValue({
        id: 'app-1',
        name: 'Test',
        signHashAllowList: ['HASH-ABC'],
      });
      const r = await service.verifyAndIssueToken({
        appId: 'com.test',
        encryptedHash: b64('hash-abc'),
        nonce: 'n',
        timestamp: Date.now(),
        deviceFingerprint: 'fp-1',
      });
      expect(r.verdict).toBe('PASS');
      expect(r.token).toBeTruthy();
      expect(r.expireAt).toBeTruthy();
      expect(r.nextCheckDelay).toBeGreaterThanOrEqual(300);
      // 颁发的 token 应可通过 verifyToken
      const v = service.verifyToken(r.token!);
      expect(v.valid).toBe(true);
      expect(v.appId).toBe('com.test');
    });
  });

  describe('verifyToken', () => {
    it('格式错误应 valid=false', () => {
      expect(service.verifyToken('not-a-jwt')).toEqual({ valid: false });
    });

    it('篡改签名应 valid=false', async () => {
      prisma.application.findFirst.mockResolvedValue({
        id: 'app-1',
        name: 'T',
        signHashAllowList: ['h'],
      });
      const r = await service.verifyAndIssueToken({
        appId: 'com.test',
        encryptedHash: b64('h'),
        nonce: 'n',
        timestamp: Date.now(),
      });
      const tampered = r.token!.slice(0, -2) + 'xx';
      expect(service.verifyToken(tampered).valid).toBe(false);
    });

    it('过期 token 应 expired=true', () => {
      // 手工构造一个已过期的 token(用同一 secret)
      const secret = configMap.integrityTokenSecret!;
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString(
        'base64url',
      );
      const payload = Buffer.from(
        JSON.stringify({ appId: 'com.test', exp: Date.now() - 1000 }),
      ).toString('base64url');
      const sig = crypto
        .createHmac('sha256', secret)
        .update(header + '.' + payload)
        .digest('base64url');
      const v = service.verifyToken(`${header}.${payload}.${sig}`);
      expect(v.valid).toBe(false);
      expect(v.expired).toBe(true);
    });
  });

  describe('decryptHash(经 verifyAndIssueToken 触发)', () => {
    it('配置 RSA 私钥时应走 RSA 解密分支', async () => {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      configMap.integrityRsaPrivateKey = privateKey.export({
        type: 'pkcs8',
        format: 'pem',
      }) as string;
      service = buildService();

      const hash = 'rsa-hash-123';
      const encrypted = crypto
        .publicEncrypt(
          { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
          Buffer.from(hash, 'utf8'),
        )
        .toString('base64');

      prisma.application.findFirst.mockResolvedValue({
        id: 'app-1',
        name: 'T',
        signHashAllowList: [hash],
      });
      const r = await service.verifyAndIssueToken({
        appId: 'com.test',
        encryptedHash: encrypted,
        nonce: 'n',
        timestamp: Date.now(),
      });
      expect(r.verdict).toBe('PASS');
    });

    it('RSA 解密失败应回退 base64(仍能匹配)', async () => {
      // 配置一个合法私钥,但传入的不是 RSA 密文(是普通 base64)→ RSA 失败回退 base64
      const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      configMap.integrityRsaPrivateKey = privateKey.export({
        type: 'pkcs8',
        format: 'pem',
      }) as string;
      service = buildService();

      prisma.application.findFirst.mockResolvedValue({
        id: 'app-1',
        name: 'T',
        signHashAllowList: ['plain-hash'],
      });
      const r = await service.verifyAndIssueToken({
        appId: 'com.test',
        encryptedHash: b64('plain-hash'),
        nonce: 'n',
        timestamp: Date.now(),
      });
      expect(r.verdict).toBe('PASS');
    });
  });
});
