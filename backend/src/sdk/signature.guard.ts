import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import type { Request } from 'express';
import { RedisService } from '../redis/redis.service';
import { CryptoService } from '../crypto/crypto.service';
import { HandshakeService } from './handshake.service';

/**
 * SDK 签名守卫
 * 详见 ADR 0021 (请求签名与防重放)
 *
 * 校验流程:
 *  1. 从 header 取 sessionId / timestamp / nonce / signature
 *  2. 从 Redis 取会话(aesKey + appId + developerId)
 *  3. 校验 timestamp 偏差 < 60s
 *  4. 校验 nonce 未用过(Redis SETNX,5 分钟 TTL)
 *  5. 重新计算 HMAC-SHA256(method + path + timestamp + nonce + bodyHash)
 *  6. 常量时间比较签名
 *  7. 解密请求体,挂到 request.body
 *
 * 解密后的明文挂到 request.body,_session 挂到 request 对象供 controller 使用
 */
@Injectable()
export class SdkSignatureGuard implements CanActivate {
  private readonly NONCE_PREFIX = 'sdk_nonce:';
  private readonly NONCE_TTL = 5 * 60; // 5 分钟
  private readonly MAX_TIMESTAMP_SKEW = 60; // 60 秒

  constructor(
    private readonly handshakeService: HandshakeService,
    private readonly redis: RedisService,
    private readonly crypto: CryptoService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();

    const sessionId = request.headers['x-session-id'] as string | undefined;
    const timestamp = request.headers['x-timestamp'] as string | undefined;
    const nonce = request.headers['x-nonce'] as string | undefined;
    const signature = request.headers['x-signature'] as string | undefined;
    const encryptedBody = (request.body as { encryptedBody?: string } | undefined)?.encryptedBody;

    if (!sessionId || !timestamp || !nonce || !signature || !encryptedBody) {
      throw new UnauthorizedException('MISSING_SDK_HEADERS');
    }

    // 1. 获取会话
    const session = await this.handshakeService.getSession(sessionId);
    if (!session) {
      throw new UnauthorizedException('SESSION_EXPIRED_OR_INVALID');
    }

    // 2. 校验 timestamp
    const ts = parseInt(timestamp, 10);
    if (isNaN(ts)) {
      throw new UnauthorizedException('INVALID_TIMESTAMP');
    }
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - ts) > this.MAX_TIMESTAMP_SKEW) {
      throw new UnauthorizedException(`TIMESTAMP_SKEW_EXCEEDED(${Math.abs(now - ts)}s)`);
    }

    // 3. 校验 nonce(防重放)
    const nonceKey = `${this.NONCE_PREFIX}${nonce}`;
    const nonceSet = await this.redis.client.set(nonceKey, '1', 'EX', this.NONCE_TTL, 'NX');
    if (nonceSet !== 'OK') {
      throw new UnauthorizedException('NONCE_ALREADY_USED');
    }

    // 4. 验证签名
    // 签名内容:method + path + timestamp + nonce + sha256(encryptedBody)
    const bodyHash = this.crypto.sha256(encryptedBody);
    const signMessage = `${request.method}${request.path}${timestamp}${nonce}${bodyHash}`;
    const signKey = session.aesKey; // 用 AES 密钥作为 HMAC 密钥(简化,实际可用单独密钥)

    if (!this.crypto.hmacVerify(signKey, signMessage, signature)) {
      throw new UnauthorizedException('INVALID_SIGNATURE');
    }

    // 5. 解密请求体
    let plaintext: Buffer;
    try {
      const raw = Buffer.from(encryptedBody, 'base64');
      // 格式:iv(12B) | ciphertext | tag(16B)
      const iv = raw.subarray(0, 12);
      const tag = raw.subarray(raw.length - 16);
      const ciphertext = raw.subarray(12, raw.length - 16);
      plaintext = this.crypto.aesDecrypt(session.aesKey, iv, ciphertext, tag);
    } catch (e) {
      throw new UnauthorizedException(`DECRYPT_FAILED: ${(e as Error).message}`);
    }

    // 6. 挂载解密后的明文 + 会话信息到 request
    const parsedBody = JSON.parse(plaintext.toString('utf-8'));
    (request as unknown as { body: unknown }).body = parsedBody;
    (request as unknown as { _sdkSession: typeof session })._sdkSession = session;

    return true;
  }
}
