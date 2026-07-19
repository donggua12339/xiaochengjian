import {
  Injectable,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import { CryptoService } from '../crypto/crypto.service';
import type { AppConfig } from '../config/configuration';

/**
 * 水印服务(ADR 0030 §c 防滥用机制)
 *
 * 生成 AES-256-GCM 加密的水印,供 injector sign 子命令嵌入 APK。
 * 密钥服务端持有(WATERMARK_AES_KEY),攻击者拿到 APK 只能看到密文,
 * 服务端可解密追溯(开发者 ID + 时间戳 + nonce)。
 *
 * 水印明文字段:
 *  - version: 注入工具版本(InjectorConstants.VERSION)
 *  - watermarkId: 开发者标识(通常为 developerId)
 *  - timestamp: 注入时间(Unix ms)
 *  - nonce: 16 字节随机数(防重放/防碰撞)
 *
 * 密文格式(Base64 编码的 JSON):
 *  { iv: base64, ciphertext: base64, tag: base64 }
 */
@Injectable()
export class WatermarkService {
  private readonly logger = new Logger(WatermarkService.name);
  private readonly watermarkKey: Buffer | null;

  constructor(
    private readonly cryptoService: CryptoService,
    private readonly configService: ConfigService<AppConfig, true>,
  ) {
    const hex = this.configService.get('watermarkAesKey', { infer: true });
    if (hex && hex.length === 64 && /^[0-9a-fA-F]+$/.test(hex)) {
      this.watermarkKey = Buffer.from(hex, 'hex');
      this.logger.log('水印 AES-256 密钥已加载');
    } else {
      this.watermarkKey = null;
      this.logger.warn(
        'WATERMARK_AES_KEY 未配置或格式错误(需 32 字节 hex),水印生成端点将拒绝',
      );
    }
  }

  /**
   * 生成加密水印
   * @param watermarkId 开发者标识(通常为 developerId 或应用 ID)
   * @param version 注入工具版本(默认 '0.2.0')
   * @returns Base64 编码的密文 JSON,可直接写入 APK META-INF/xcj-watermark.enc.txt
   */
  generateEncryptedWatermark(
    watermarkId: string,
    version = '0.2.0',
  ): {
    watermarkBase64: string;
    version: string;
    algorithm: string;
  } {
    if (!this.watermarkKey) {
      throw new BadRequestException('WATERMARK_KEY_NOT_CONFIGURED', {
        cause: 'server must configure WATERMARK_AES_KEY (32-byte hex) to enable watermark',
      });
    }
    if (!watermarkId || watermarkId.length > 128) {
      throw new BadRequestException('INVALID_WATERMARK_ID', {
        cause: 'watermarkId must be 1-128 chars',
      });
    }

    // 明文 JSON
    const plaintext = JSON.stringify({
      version,
      watermarkId,
      timestamp: Date.now(),
      nonce: crypto.randomBytes(16).toString('hex'),
    });

    // AES-256-GCM 加密
    const { iv, ciphertext, tag } = this.cryptoService.aesEncrypt(
      this.watermarkKey,
      Buffer.from(plaintext, 'utf8'),
    );

    // 密文 JSON(Base64 编码各字段)
    const encryptedEnvelope = JSON.stringify({
      iv: iv.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      tag: tag.toString('base64'),
    });

    this.logger.log(
      `水印已生成: watermarkId=${watermarkId} version=${version} ctLen=${ciphertext.length}`,
    );

    return {
      watermarkBase64: Buffer.from(encryptedEnvelope, 'utf8').toString('base64'),
      version,
      algorithm: 'AES-256-GCM',
    };
  }

  /**
   * 解密水印(用于服务端追溯,本 service 不暴露 HTTP 端点,仅供内部审计用)
   */
  decryptWatermark(watermarkBase64: string): {
    version: string;
    watermarkId: string;
    timestamp: number;
    nonce: string;
  } {
    if (!this.watermarkKey) {
      throw new BadRequestException('WATERMARK_KEY_NOT_CONFIGURED');
    }
    const envelope = JSON.parse(
      Buffer.from(watermarkBase64, 'base64').toString('utf8'),
    ) as { iv: string; ciphertext: string; tag: string };
    const plaintext = this.cryptoService.aesDecrypt(
      this.watermarkKey,
      Buffer.from(envelope.iv, 'base64'),
      Buffer.from(envelope.ciphertext, 'base64'),
      Buffer.from(envelope.tag, 'base64'),
    );
    return JSON.parse(plaintext.toString('utf8'));
  }
}
