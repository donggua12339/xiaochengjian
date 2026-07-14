import { Test } from '@nestjs/testing';
import { ConfigModule } from '@nestjs/config';
import { authenticator } from 'otplib';
import { TotpService } from './totp.service';

describe('TotpService', () => {
  let service: TotpService;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          load: [
            () => ({
              totpIssuer: 'Xiaochengjian',
              totpAlgorithm: 'sha1',
              totpDigits: 6,
              totpStep: 30,
            }),
          ],
        }),
      ],
      providers: [TotpService],
    }).compile();
    service = moduleRef.get(TotpService);
  });

  describe('generateSecret', () => {
    it('应返回非空 base32 字符串', () => {
      const secret = service.generateSecret();
      expect(secret).toBeTruthy();
      expect(secret.length).toBeGreaterThan(10);
    });

    it('每次应不同', () => {
      const secrets = new Set<string>();
      for (let i = 0; i < 50; i++) {
        secrets.add(service.generateSecret());
      }
      expect(secrets.size).toBe(50);
    });
  });

  describe('generateOtpAuthUrl', () => {
    it('应包含 issuer / email / secret', () => {
      const secret = 'JBSWY3DPEHPK3PXP';
      const url = service.generateOtpAuthUrl('user@xcj.dev', secret);
      expect(url).toContain('otpauth://totp/');
      expect(url).toContain('Xiaochengjian');
      expect(url).toContain('user%40xcj.dev');
      expect(url).toContain(`secret=${secret}`);
    });
  });

  describe('verify', () => {
    it('正确 TOTP 码应验证通过', () => {
      const secret = service.generateSecret();
      const token = authenticator.generate(secret);
      expect(service.verify(token, secret)).toBe(true);
    });

    it('错误 TOTP 码应验证失败', () => {
      const secret = service.generateSecret();
      expect(service.verify('000000', secret)).toBe(false);
    });

    it('无效输入应返回 false 而非抛异常', () => {
      expect(service.verify('', '')).toBe(false);
      expect(service.verify('abc', 'invalid_secret')).toBe(false);
    });
  });

  describe('generateBackupCodes', () => {
    it('应生成 10 个备份码', () => {
      const codes = service.generateBackupCodes();
      expect(codes).toHaveLength(10);
    });

    it('每个备份码应为 8 字符字母数字', () => {
      const codes = service.generateBackupCodes();
      for (const code of codes) {
        expect(code).toMatch(/^[A-Z0-9]{8}$/);
      }
    });

    it('备份码应几乎不重复', () => {
      const codes = service.generateBackupCodes();
      const unique = new Set(codes);
      expect(unique.size).toBeGreaterThanOrEqual(9);
    });
  });

  describe('hashBackupCode', () => {
    it('应返回 64 字符十六进制 SHA-256', () => {
      expect(service.hashBackupCode('ABCD1234')).toMatch(/^[0-9a-f]{64}$/);
    });

    it('相同输入应相同输出(确定性)', () => {
      expect(service.hashBackupCode('ABCD1234')).toBe(service.hashBackupCode('ABCD1234'));
    });

    it('大小写不敏感(自动转大写)', () => {
      expect(service.hashBackupCode('abcd1234')).toBe(service.hashBackupCode('ABCD1234'));
    });
  });

  describe('verifyBackupCode', () => {
    it('匹配的备份码应返回 true + 剩余列表', () => {
      const codes = ['ABCD1234', 'EFGH5678'];
      const hashed = codes.map((c) => service.hashBackupCode(c));
      const [matched, remaining] = service.verifyBackupCode('ABCD1234', hashed);
      expect(matched).toBe(true);
      expect(remaining).toHaveLength(1);
      expect(remaining[0]).toBe(hashed[1]);
    });

    it('不匹配的备份码应返回 false + 原列表', () => {
      const hashed = ['ABCD1234', 'EFGH5678'].map((c) => service.hashBackupCode(c));
      const [matched, remaining] = service.verifyBackupCode('ZZZZ0000', hashed);
      expect(matched).toBe(false);
      expect(remaining).toHaveLength(2);
    });

    it('小写输入应能匹配(大小写不敏感)', () => {
      const hashed = [service.hashBackupCode('ABCD1234')];
      const [matched] = service.verifyBackupCode('abcd1234', hashed);
      expect(matched).toBe(true);
    });

    it('使用后应从列表移除(一次性)', () => {
      const hashed = ['ABCD1234', 'EFGH5678'].map((c) => service.hashBackupCode(c));
      const [matched1, remaining1] = service.verifyBackupCode('ABCD1234', hashed);
      expect(matched1).toBe(true);
      // 再次使用同一个备份码应失败
      const [matched2] = service.verifyBackupCode('ABCD1234', remaining1);
      expect(matched2).toBe(false);
    });

    it('空列表应返回 false', () => {
      const [matched, remaining] = service.verifyBackupCode('ABCD1234', []);
      expect(matched).toBe(false);
      expect(remaining).toEqual([]);
    });
  });
});
