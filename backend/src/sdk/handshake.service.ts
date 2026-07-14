import { Injectable, NotFoundException, BadRequestException, Logger } from '@nestjs/common';
import { RedisService } from '../redis/redis.service';
import { CryptoService } from '../crypto/crypto.service';
import { PrismaService } from '../prisma/prisma.service';

/**
 * Handshake 服务
 * 详见 ADR 0020 (通信加密)
 *
 * 流程:
 *  1. 客户端生成临时 AES-256 密钥
 *  2. 用 RSA 公钥加密 AES 密钥
 *  3. 发送加密的 AES 密钥 + appId
 *  4. 服务端用 RSA 私钥解密,获得 AES 密钥
 *  5. 生成 sessionId,存 Redis(key=sessionId, value={aesKey, appId, developerId}, TTL=1h)
 *  6. 返回 sessionId
 *
 * 后续请求用 sessionId + AES 密钥 + HMAC 签名
 */
@Injectable()
export class HandshakeService {
  private readonly logger = new Logger(HandshakeService.name);
  private readonly SESSION_PREFIX = 'sdk_session:';
  private readonly SESSION_TTL: number;

  constructor(
    private readonly redis: RedisService,
    private readonly crypto: CryptoService,
    private readonly prisma: PrismaService,
  ) {
    this.SESSION_TTL = this.crypto.sessionTtl;
  }

  /**
   * 处理 handshake 请求
   * @param encryptedKeyBase64 RSA 加密的 AES 密钥(Base64)
   * @param appId 应用 ID
   * @returns sessionId
   */
  async handshake(encryptedKeyBase64: string, appId: string): Promise<{ sessionId: string }> {
    // SDK 入口:无 JWT,无 tenant_id,临时 SET ROLE xcj_admin(BYPASSRLS)查 application
    // 安全性靠 appId + RSA 加密(只有合法 SDK 客户端能构造正确请求)
    // SET LOCAL ROLE 只在当前事务内有效,事务结束后自动 RESET
    const app = await this.prisma.$transaction(async (tx) => {
      await tx.$executeRaw`SET LOCAL ROLE xcj_admin`;
      return tx.application.findUnique({
        where: { id: appId },
        select: { id: true, developerId: true },
      });
    });
    if (!app) {
      throw new NotFoundException('APP_NOT_FOUND');
    }

    // RSA 解密 AES 密钥
    let aesKey: Buffer;
    try {
      const encrypted = Buffer.from(encryptedKeyBase64, 'base64');
      aesKey = this.crypto.rsaDecrypt(encrypted);
    } catch (e) {
      throw new BadRequestException(`RSA_DECRYPT_FAILED: ${(e as Error).message}`);
    }

    if (aesKey.length !== 32) {
      throw new BadRequestException(`INVALID_AES_KEY_LENGTH(${aesKey.length}, expected 32)`);
    }

    // 生成 sessionId,存 Redis
    const sessionId = this.crypto.generateSessionId();
    const sessionData = JSON.stringify({
      aesKey: aesKey.toString('hex'),
      appId: app.id,
      developerId: app.developerId,
      createdAt: Date.now(),
    });

    await this.redis.set(`${this.SESSION_PREFIX}${sessionId}`, sessionData, this.SESSION_TTL);

    this.logger.log(`Handshake 成功: appId=${appId}, sessionId=${sessionId.substring(0, 8)}...`);

    return { sessionId };
  }

  /**
   * 获取会话信息(供 SignatureGuard 使用)
   * @returns { aesKey, appId, developerId } 或 null(会话不存在/过期)
   */
  async getSession(sessionId: string): Promise<{
    aesKey: Buffer;
    appId: string;
    developerId: string;
  } | null> {
    const raw = await this.redis.get(`${this.SESSION_PREFIX}${sessionId}`);
    if (!raw) {
      return null;
    }

    try {
      const data = JSON.parse(raw) as { aesKey: string; appId: string; developerId: string };
      return {
        aesKey: Buffer.from(data.aesKey, 'hex'),
        appId: data.appId,
        developerId: data.developerId,
      };
    } catch {
      return null;
    }
  }

  /**
   * 撤销会话
   */
  async revokeSession(sessionId: string): Promise<void> {
    await this.redis.del(`${this.SESSION_PREFIX}${sessionId}`);
  }

  /**
   * 续期会话(heartbeat 调用)+ 密钥轮换(ADR 0060)
   *
   * 每 20 分钟轮换 AES 密钥:
   *  - 检查会话创建时间
   *  - 超过 20 分钟则生成新 AES 密钥,更新 Redis
   *  - 返回新密钥(Base64)供客户端使用
   *
   * @returns { expiresAt, newAesKey? } 续期后的过期时间;newAesKey 仅在轮换时返回
   */
  async refreshSession(sessionId: string): Promise<{
    expiresAt: Date;
    newAesKey?: string;
  } | null> {
    const key = `${this.SESSION_PREFIX}${sessionId}`;
    const raw = await this.redis.get(key);
    if (!raw) {
      return null;
    }

    let sessionData: { aesKey: string; appId: string; developerId: string; createdAt?: number; rotatedAt?: number };
    try {
      sessionData = JSON.parse(raw);
    } catch {
      return null;
    }

    // 续期 TTL
    await this.redis.client.expire(key, this.SESSION_TTL);

    const now = Date.now();
    const rotatedAt = sessionData.rotatedAt ?? sessionData.createdAt ?? now;
    const elapsed = now - rotatedAt;
    const ROTATION_INTERVAL = 20 * 60 * 1000; // 20 分钟(ADR 0060)

    // 超过 20 分钟,轮换密钥
    if (elapsed >= ROTATION_INTERVAL) {
      const newAesKey = this.crypto.generateAesKey();
      sessionData.aesKey = newAesKey.toString('hex');
      sessionData.rotatedAt = now;
      await this.redis.set(key, JSON.stringify(sessionData), this.SESSION_TTL);
      this.logger.log(
        `密钥轮换: sessionId=${sessionId.substring(0, 8)}..., appId=${sessionData.appId}`,
      );
      return {
        expiresAt: new Date(now + this.SESSION_TTL * 1000),
        newAesKey: newAesKey.toString('base64'),
      };
    }

    return { expiresAt: new Date(now + this.SESSION_TTL * 1000) };
  }
}
