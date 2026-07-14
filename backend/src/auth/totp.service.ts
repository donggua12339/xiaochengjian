import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { authenticator, totp } from 'otplib';
import * as crypto from 'crypto';
import type { AppConfig } from '../config/configuration';

/**
 * TOTP 服务(2FA)
 * 详见 ADR 0027 (2FA 强制)
 *
 * 使用 otplib 实现 TOTP(Time-based One-Time Password)
 * 兼容 Google Authenticator / Microsoft Authenticator
 */
@Injectable()
export class TotpService {
  constructor(private readonly configService: ConfigService<AppConfig, true>) {
    const digits = configService.get('totpDigits', { infer: true });
    const step = configService.get('totpStep', { infer: true });

    authenticator.options = { digits, step };
    totp.options = { digits, step };
  }

  /**
   * 生成新的 TOTP secret(base32 编码,32 字符)
   */
  generateSecret(): string {
    return authenticator.generateSecret();
  }

  /**
   * 生成 otpauth URL(用于二维码)
   * 格式:otpauth://totp/{issuer}:{email}?secret={secret}&issuer={issuer}
   */
  generateOtpAuthUrl(email: string, secret: string): string {
    const issuer = this.configService.get('totpIssuer', { infer: true });
    return authenticator.keyuri(email, issuer, secret);
  }

  /**
   * 验证 TOTP 码
   * @param token 6 位数字
   * @param secret base32 secret
   * @returns 是否有效
   */
  verify(token: string, secret: string): boolean {
    try {
      return authenticator.verify({ token, secret });
    } catch {
      return false;
    }
  }

  /**
   * 生成 10 个一次性备份码(8 字符,字母数字)
   * 返回明文(仅此一次),服务端存 SHA-256 hash
   */
  generateBackupCodes(): string[] {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const codes: string[] = [];
    for (let i = 0; i < 10; i++) {
      const bytes = crypto.randomBytes(8);
      let code = '';
      for (let j = 0; j < 8; j++) {
        code += charset[bytes[j] % charset.length];
      }
      codes.push(code);
    }
    return codes;
  }

  /**
   * 哈希备份码(存数据库前哈希,防数据库泄露后备份码可用)
   */
  hashBackupCode(code: string): string {
    return crypto.createHash('sha256').update(code.toUpperCase()).digest('hex');
  }

  /**
   * 验证备份码
   * 比对哈希,匹配后从列表移除(一次性使用)
   * @param code 用户输入的备份码
   * @param hashedCodes 数据库存储的哈希列表
   * @returns [是否匹配, 剩余哈希列表]
   */
  verifyBackupCode(code: string, hashedCodes: string[]): [boolean, string[]] {
    const hash = this.hashBackupCode(code);
    const index = hashedCodes.indexOf(hash);
    if (index === -1) {
      return [false, hashedCodes];
    }
    const remaining = [...hashedCodes];
    remaining.splice(index, 1);
    return [true, remaining];
  }
}
