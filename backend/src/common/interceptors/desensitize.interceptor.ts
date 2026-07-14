import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { Observable, map } from 'rxjs';

/**
 * 响应脱敏拦截器(ADR 0027 安全基线)
 * 对响应体中敏感字段统一替换为 ***
 *
 * 敏感字段(脱敏):
 *  - cardKey(卡密明文,永不返回)
 *  - password / passwordHash
 *  - appSecret / totpSecret / jwtSecret / apiSecret(具体 secret 字段)
 *  - privateKey
 *  - tokenHash / refreshTokenHash(token 的哈希,不返回)
 *
 * 允许返回(不脱敏):
 *  - secret(TOTP setup 返回的 TOTP secret,客户端需要生成二维码)
 *  - accessToken / refreshToken(登录响应需要)
 *  - cardKeyHash / cardKeyPrefix(哈希/前缀,设计上返回)
 *  - signHashAllowList(签名白名单)
 *
 * 注意:此拦截器仅作为兜底,业务层不应返回敏感字段
 */
@Injectable()
export class DesensitizeInterceptor implements NestInterceptor {
  private readonly SENSITIVE_PATTERNS = [
    /^cardKey$/i,
    /password/i,
    /^totpSecret$/i,
    /^jwtSecret$/i,
    /^apiSecret$/i,
    /privateKey/i,
    /tokenHash/i,
  ];

  private readonly ALLOW_PATTERNS = [/cardKeyPrefix/i, /hash$/i, /signHashAllowList/i];

  intercept(_context: ExecutionContext, next: CallHandler): Observable<unknown> {
    return next.handle().pipe(
      map((data) => {
        if (data === null || data === undefined) {
          return data;
        }
        return this.desensitize(data);
      }),
    );
  }

  private desensitize(value: unknown): unknown {
    if (typeof value !== 'object' || value === null) {
      return value;
    }

    if (Array.isArray(value)) {
      return value.map((item) => this.desensitize(item));
    }

    const result: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      if (this.isSensitive(key) && !this.isAllowed(key)) {
        result[key] = '***';
      } else if (typeof val === 'object' && val !== null) {
        result[key] = this.desensitize(val);
      } else {
        result[key] = val;
      }
    }
    return result;
  }

  private isSensitive(key: string): boolean {
    return this.SENSITIVE_PATTERNS.some((pattern) => pattern.test(key));
  }

  private isAllowed(key: string): boolean {
    return this.ALLOW_PATTERNS.some((pattern) => pattern.test(key));
  }
}
