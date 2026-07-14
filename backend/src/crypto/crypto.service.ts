import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import * as fs from 'fs';
import type { AppConfig } from '../config/configuration';

/**
 * 加密服务
 * 详见 ADR 0020 (通信加密) 与 ADR 0021 (请求签名)
 *
 * RSA:用于 handshake 阶段加密临时 AES 密钥
 * AES-256-GCM:用于后续请求体加解密
 * HMAC-SHA256:用于请求签名(防篡改 + 防重放)
 */
@Injectable()
export class CryptoService {
  private readonly logger = new Logger(CryptoService.name);
  private readonly privateKey: crypto.KeyObject;
  private readonly sdkSessionTtl: number;

  constructor(private readonly configService: ConfigService<AppConfig, true>) {
    const privatePath = this.configService.get('rsaPrivateKeyPath', { infer: true });

    let privateKeyPem: string;
    try {
      privateKeyPem = fs.readFileSync(privatePath, 'utf-8');
    } catch (e) {
      // 私钥缺失会导致 SDK 握手全部失败,需要给运维明确的修复指引
      throw new Error(
        `RSA 私钥加载失败(path=${privatePath}): ${(e as Error).message}。` +
          `请执行 openssl genrsa -out keys/private.pem 2048 生成密钥对(详见 README.md)。`,
      );
    }

    try {
      this.privateKey = crypto.createPrivateKey({ key: privateKeyPem, format: 'pem' });
    } catch (e) {
      throw new Error(
        `RSA 私钥格式无效(path=${privatePath}): ${(e as Error).message}。` +
          `请确认文件为 PEM 格式且为有效私钥。`,
      );
    }
    this.sdkSessionTtl = this.configService.get('sdkSessionTtl', { infer: true });

    this.logger.log('RSA 私钥已加载');
  }

  /**
   * RSA 解密(用于 handshake 解密客户端发来的 AES 密钥)
   * 客户端用 RSA 公钥加密 AES 密钥,服务端用私钥解密
   */
  rsaDecrypt(encrypted: Buffer): Buffer {
    return crypto.privateDecrypt(
      {
        key: this.privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      encrypted,
    );
  }

  /**
   * 生成 sessionId(用于 handshake 返回)
   */
  generateSessionId(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * 生成 AES-256 密钥(用于密钥轮换,ADR 0060)
   */
  generateAesKey(): Buffer {
    return crypto.randomBytes(32);
  }

  /**
   * AES-256-GCM 加密
   * @param key AES 密钥(32 字节)
   * @param plaintext 明文
   * @returns { iv, ciphertext, tag }(均为 Buffer)
   */
  aesEncrypt(
    key: Buffer,
    plaintext: Buffer,
  ): {
    iv: Buffer;
    ciphertext: Buffer;
    tag: Buffer;
  } {
    const iv = crypto.randomBytes(12); // GCM 推荐 12 字节 IV
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return { iv, ciphertext, tag };
  }

  /**
   * AES-256-GCM 解密
   * @param key AES 密钥(32 字节)
   * @param iv 12 字节 IV
   * @param ciphertext 密文
   * @param tag 16 字节认证标签
   */
  aesDecrypt(key: Buffer, iv: Buffer, ciphertext: Buffer, tag: Buffer): Buffer {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }

  /**
   * HMAC-SHA256 签名
   * @param key 签名密钥
   * @param message 待签名内容
   */
  hmacSign(key: Buffer, message: string): string {
    return crypto.createHmac('sha256', key).update(message).digest('hex');
  }

  /**
   * 验证 HMAC 签名(常量时间比较,防时序攻击)
   */
  hmacVerify(key: Buffer, message: string, signature: string): boolean {
    const expected = this.hmacSign(key, message);
    const a = Buffer.from(expected, 'hex');
    const b = Buffer.from(signature, 'hex');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  }

  /**
   * SHA-256 哈希(用于 bodyHash)
   */
  sha256(data: string | Buffer): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  get sessionTtl(): number {
    return this.sdkSessionTtl;
  }
}
