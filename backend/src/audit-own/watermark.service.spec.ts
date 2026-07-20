import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { BadRequestException } from '@nestjs/common';
import { CryptoService } from '../crypto/crypto.service';
import { WatermarkService } from './watermark.service';
import * as crypto from 'crypto';

/**
 * WatermarkService 单元测试(ADR 0030 §c)
 *
 * 覆盖:
 *  - generateEncryptedWatermark: 正常生成 / 密钥未配置拒绝 / watermarkId 非法
 *  - decryptWatermark: 加密-解密往返一致性
 */
describe('WatermarkService', () => {
  let service: WatermarkService;
  const validKey = crypto.randomBytes(32).toString('hex'); // 64 char hex

  beforeEach(async () => {
    const moduleRef = await Test.createTestingModule({
      providers: [
        WatermarkService,
        {
          provide: CryptoService,
          useValue: {
            aesEncrypt: (key: Buffer, plaintext: Buffer) => {
              const iv = crypto.randomBytes(12);
              const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
              const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
              const tag = cipher.getAuthTag();
              return { iv, ciphertext, tag };
            },
            aesDecrypt: (key: Buffer, iv: Buffer, ciphertext: Buffer, tag: Buffer) => {
              const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
              decipher.setAuthTag(tag);
              return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
            },
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: (key: string) => (key === 'watermarkAesKey' ? validKey : undefined),
          },
        },
      ],
    }).compile();
    service = moduleRef.get(WatermarkService);
  });

  describe('generateEncryptedWatermark', () => {
    it('正常应生成 Base64 密文(可解密回原文)', () => {
      const result = service.generateEncryptedWatermark('dev-123', '0.2.0');
      expect(result.algorithm).toBe('AES-256-GCM');
      expect(result.version).toBe('0.2.0');
      expect(result.watermarkBase64).toBeTruthy();

      // 解密验证
      const decrypted = service.decryptWatermark(result.watermarkBase64);
      expect(decrypted.watermarkId).toBe('dev-123');
      expect(decrypted.version).toBe('0.2.0');
      expect(decrypted.timestamp).toBeGreaterThan(0);
      expect(decrypted.nonce).toMatch(/^[0-9a-f]{32}$/); // 16 bytes hex
    });

    it('每次生成 nonce 不同(防重放)', () => {
      const r1 = service.generateEncryptedWatermark('dev-1');
      const r2 = service.generateEncryptedWatermark('dev-1');
      expect(r1.watermarkBase64).not.toBe(r2.watermarkBase64);
      const d1 = service.decryptWatermark(r1.watermarkBase64);
      const d2 = service.decryptWatermark(r2.watermarkBase64);
      expect(d1.nonce).not.toBe(d2.nonce);
    });

    it('watermarkId 为空应抛 BadRequestException', () => {
      expect(() => service.generateEncryptedWatermark('')).toThrow(BadRequestException);
    });

    it('watermarkId 超过 128 字符应抛 BadRequestException', () => {
      const long = 'a'.repeat(129);
      expect(() => service.generateEncryptedWatermark(long)).toThrow(BadRequestException);
    });
  });

  describe('密钥未配置', () => {
    it('WATERMARK_AES_KEY 缺失时 generateEncryptedWatermark 应抛 BadRequestException', async () => {
      const moduleRef = await Test.createTestingModule({
        providers: [
          WatermarkService,
          { provide: CryptoService, useValue: {} },
          {
            provide: ConfigService,
            useValue: { get: () => '' },
          },
        ],
      }).compile();
      const svc = moduleRef.get(WatermarkService);
      expect(() => svc.generateEncryptedWatermark('dev-1')).toThrow(BadRequestException);
    });

    it('WATERMARK_AES_KEY 长度非 64 应抛 BadRequestException', async () => {
      const moduleRef = await Test.createTestingModule({
        providers: [
          WatermarkService,
          { provide: CryptoService, useValue: {} },
          {
            provide: ConfigService,
            useValue: { get: () => 'shortkey' },
          },
        ],
      }).compile();
      const svc = moduleRef.get(WatermarkService);
      expect(() => svc.generateEncryptedWatermark('dev-1')).toThrow(BadRequestException);
    });
  });

  describe('decryptWatermark', () => {
    it('篡改密文应解密失败(认证标签校验)', () => {
      const result = service.generateEncryptedWatermark('dev-1');
      // 篡改 base64(改最后一个字符)
      const tampered = result.watermarkBase64.slice(0, -1) + 'A';
      expect(() => service.decryptWatermark(tampered)).toThrow();
    });
  });

  describe('extractAndDecryptFromApk', () => {
    it('APK 无水印文件应返回 { found: false }', async () => {
      const yazl = await import('yazl');
      const zipBuf = await new Promise<Buffer>((resolve) => {
        const zipfile = new yazl.ZipFile();
        zipfile.addBuffer(Buffer.from('hello'), 'META-INF/other.txt');
        zipfile.end();
        const chunks: Buffer[] = [];
        zipfile.outputStream.on('data', (c) => chunks.push(c));
        zipfile.outputStream.on('end', () => resolve(Buffer.concat(chunks)));
      });
      const result = await service.extractAndDecryptFromApk(zipBuf);
      expect(result.found).toBe(false);
    });

    it('APK 含水印文件应提取并解密成功', async () => {
      const yazl = await import('yazl');
      // 先生成加密水印
      const watermark = service.generateEncryptedWatermark('dev-trace-test', '0.2.0');
      // 构造含水印的 zip
      const zipBuf = await new Promise<Buffer>((resolve) => {
        const zipfile = new yazl.ZipFile();
        zipfile.addBuffer(Buffer.from('app content'), 'classes.dex');
        zipfile.addBuffer(
          Buffer.from(watermark.watermarkBase64),
          'META-INF/xcj-watermark.enc.txt',
        );
        zipfile.end();
        const chunks: Buffer[] = [];
        zipfile.outputStream.on('data', (c) => chunks.push(c));
        zipfile.outputStream.on('end', () => resolve(Buffer.concat(chunks)));
      });
      const result = await service.extractAndDecryptFromApk(zipBuf);
      expect(result.found).toBe(true);
      expect(result.watermark?.watermarkId).toBe('dev-trace-test');
      expect(result.watermark?.version).toBe('0.2.0');
      expect(result.watermark?.timestamp).toBeGreaterThan(0);
      expect(result.watermark?.nonce).toMatch(/^[0-9a-f]{32}$/);
    });
  });
});
