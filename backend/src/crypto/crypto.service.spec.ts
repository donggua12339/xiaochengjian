import { Test } from '@nestjs/testing';
import { ConfigModule } from '@nestjs/config';
import { CryptoService } from './crypto.service';

describe('CryptoService', () => {
  let service: CryptoService;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          load: [
            () => ({
              rsaPrivateKeyPath: './keys/private.pem',
              rsaPublicKeyPath: './keys/public.pem',
              sdkSessionTtl: 3600,
            }),
          ],
        }),
      ],
      providers: [CryptoService],
    }).compile();
    service = moduleRef.get(CryptoService);
  });

  describe('RSA', () => {
    it('应能解密用公钥加密的数据', () => {
      const plaintext = Buffer.from('hello xiaochengjian', 'utf-8');
      // 用 Node crypto 公钥加密(模拟客户端)
      const crypto = require('node:crypto');
      const fs = require('node:fs');
      const pubPem = fs.readFileSync('./keys/public.pem', 'utf-8');
      const encrypted = crypto.publicEncrypt(
        { key: pubPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
        plaintext,
      );
      const decrypted = service.rsaDecrypt(encrypted);
      expect(decrypted.toString('utf-8')).toBe('hello xiaochengjian');
    });

    it('不同明文应不同密文', () => {
      const crypto = require('node:crypto');
      const fs = require('node:fs');
      const pubPem = fs.readFileSync('./keys/public.pem', 'utf-8');
      const e1 = crypto.publicEncrypt(
        { key: pubPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
        Buffer.from('a'),
      );
      const e2 = crypto.publicEncrypt(
        { key: pubPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
        Buffer.from('b'),
      );
      expect(e1.equals(e2)).toBe(false);
    });
  });

  describe('AES-256-GCM', () => {
    it('加解密应还原原文', () => {
      const key = Buffer.alloc(32, 0xab);
      const plaintext = Buffer.from('{"cardKey":"ABCD-EFGH-IJKL-MNOP"}', 'utf-8');
      const { iv, ciphertext, tag } = service.aesEncrypt(key, plaintext);
      const decrypted = service.aesDecrypt(key, iv, ciphertext, tag);
      expect(decrypted.toString('utf-8')).toBe(plaintext.toString('utf-8'));
    });

    it('iv 应为 12 字节', () => {
      const key = Buffer.alloc(32, 0xab);
      const { iv } = service.aesEncrypt(key, Buffer.from('test'));
      expect(iv.length).toBe(12);
    });

    it('tag 应为 16 字节', () => {
      const key = Buffer.alloc(32, 0xab);
      const { tag } = service.aesEncrypt(key, Buffer.from('test'));
      expect(tag.length).toBe(16);
    });

    it('篡改密文应解密失败', () => {
      const key = Buffer.alloc(32, 0xab);
      const { iv, ciphertext, tag } = service.aesEncrypt(key, Buffer.from('test'));
      const tampered = Buffer.from(ciphertext);
      tampered[0] ^= 0xff;
      expect(() => service.aesDecrypt(key, iv, tampered, tag)).toThrow();
    });
  });

  describe('HMAC-SHA256', () => {
    it('相同输入应相同输出', () => {
      const key = Buffer.alloc(32, 0xcd);
      const sig1 = service.hmacSign(key, 'message');
      const sig2 = service.hmacSign(key, 'message');
      expect(sig1).toBe(sig2);
    });

    it('hmacVerify 应正确验证', () => {
      const key = Buffer.alloc(32, 0xcd);
      const sig = service.hmacSign(key, 'message');
      expect(service.hmacVerify(key, 'message', sig)).toBe(true);
      expect(service.hmacVerify(key, 'tampered', sig)).toBe(false);
    });

    it('签名应为 64 字符十六进制', () => {
      const sig = service.hmacSign(Buffer.alloc(32), 'test');
      expect(sig).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe('SHA-256', () => {
    it('应返回 64 字符十六进制', () => {
      expect(service.sha256('test')).toMatch(/^[0-9a-f]{64}$/);
    });

    it('已知值验证', () => {
      // SHA-256("test") = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
      expect(service.sha256('test')).toBe(
        '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      );
    });
  });

  describe('generateSessionId', () => {
    it('应返回 64 字符十六进制', () => {
      const id = service.generateSessionId();
      expect(id).toMatch(/^[0-9a-f]{64}$/);
    });

    it('每次应不同', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 100; i++) {
        ids.add(service.generateSessionId());
      }
      expect(ids.size).toBe(100);
    });
  });
});
