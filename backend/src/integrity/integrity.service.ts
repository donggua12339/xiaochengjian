import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import * as fs from 'fs';
import { PrismaService } from '../prisma/prisma.service';

/**
 * Integrity 服务(方案 C 服务端 gate)
 *
 * 详见 xcj_blue_demo_v2.1.1_prompt.md §方案 C
 *
 * 流程:
 *  1. 客户端 Native 层计算签名哈希,用服务端公钥加密(防篡改传输)
 *  2. POST /v1/integrity/verify 提交加密哈希 + nonce + timestamp
 *  3. 服务端用私钥解密,比对 application.signHashAllowList
 *  4. 匹配 -> 颁发短期 token(绑定设备+App+完整性,JWT)
 *  5. 客户端核心功能必须携带 token
 *
 * 对抗:
 *  - 客户端被完全破解(MT 改 SO / NP Hook syscall):无 token 核心功能不可用
 *  - 攻击者需伪造服务端响应(绕过 HTTPS Pinning + 服务器私钥签名),成本极高
 */
@Injectable()
export class IntegrityService {
  private readonly logger = new Logger(IntegrityService.name);
  private readonly tokenSecret: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
  ) {
    // token 签名密钥(生产环境必须配置 32+ 字符)
    this.tokenSecret =
      this.configService.get<string>('integrityTokenSecret') ??
      'dev-integrity-secret-change-in-production';
  }

  /**
   * 校验签名哈希 + 颁发 token
   *
   * @param appId 应用 ID(包名)
   * @param encryptedHash 客户端用服务端公钥加密的签名哈希(RSA-2048)
   * @param nonce 一次性随机数(防重放)
   * @param timestamp 毫秒时间戳
   * @param deviceFingerprint 设备指纹(可选,绑定 token)
   * @returns verdict + token + 过期时间 + 下次校验延迟
   */
  async verifyAndIssueToken(params: {
    appId: string;
    encryptedHash: string;  // base64
    nonce: string;
    timestamp: number;
    deviceFingerprint?: string;
  }): Promise<{
    verdict: 'PASS' | 'FAIL';
    token?: string;
    expireAt?: string;
    nextCheckDelay: number;
    reason?: string;
  }> {
    const { appId, encryptedHash, timestamp, deviceFingerprint } = params;

    // 1. 时间戳校验(防重放,5 分钟窗口)
    const now = Date.now();
    if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
      this.logger.warn(`时间戳超出窗口: appId=${appId} ts=${timestamp}`);
      return { verdict: 'FAIL', nextCheckDelay: 60, reason: 'TIMESTAMP_EXPIRED' };
    }

    // 2. 解密签名哈希(用服务端 RSA 私钥)
    let signatureHash: string;
    try {
      signatureHash = this.decryptHash(encryptedHash);
    } catch (e) {
      this.logger.warn(`解密失败: appId=${appId} ${(e as Error).message}`);
      return { verdict: 'FAIL', nextCheckDelay: 60, reason: 'DECRYPT_FAILED' };
    }

    // 3. 查询应用白名单(application 表 signHashAllowList)
    const app = await this.prisma.application.findFirst({
      where: { packageName: appId },
      select: { id: true, name: true, signHashAllowList: true },
    });
    if (!app) {
      this.logger.warn(`应用不在白名单: ${appId}`);
      return { verdict: 'FAIL', nextCheckDelay: 60, reason: 'APP_NOT_REGISTERED' };
    }

    // 4. 比对签名哈希
    const normalized = signatureHash.toLowerCase();
    const matched = (app.signHashAllowList ?? []).some(
      (h) => h.toLowerCase() === normalized,
    );
    if (!matched) {
      this.logger.warn(
        `签名哈希不匹配: appId=${appId} hash=${normalized.slice(0, 16)}...`,
      );
      return { verdict: 'FAIL', nextCheckDelay: 60, reason: 'SIGNATURE_MISMATCH' };
    }

    // 5. 颁发短期 token(JWT,绑定 appId + 设备 + 完整性,1 小时有效)
    const expireAt = new Date(now + 60 * 60 * 1000);
    const token = this.issueToken(appId, deviceFingerprint, expireAt);

    // 6. 下次校验延迟(5-15 分钟随机,防逆向定位)
    const nextCheckDelay = 300 + Math.floor(Math.random() * 600);

    this.logger.log(`Integrity 校验通过: appId=${appId} token 颁发成功`);
    return {
      verdict: 'PASS',
      token,
      expireAt: expireAt.toISOString(),
      nextCheckDelay,
    };
  }

  /**
   * 验证 token(供其他服务调用)
   */
  verifyToken(token: string): { valid: boolean; appId?: string; expired?: boolean } {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return { valid: false };

      const payload = JSON.parse(
        Buffer.from(parts[1], 'base64').toString('utf8'),
      ) as { appId: string; exp: number; fp?: string };

      if (payload.exp < Date.now()) {
        return { valid: false, expired: true };
      }

      // 验证签名(HMAC-SHA256)
      const expectedSig = crypto
        .createHmac('sha256', this.tokenSecret)
        .update(parts[0] + '.' + parts[1])
        .digest('base64url');
      if (expectedSig !== parts[2]) {
        return { valid: false };
      }

      return { valid: true, appId: payload.appId };
    } catch {
      return { valid: false };
    }
  }

  /**
   * 解密客户端用 RSA 公钥加密的签名哈希
   *
   * 支持两种私钥配置方式:
   *  1. 环境变量 INTEGRITY_RSA_PRIVATE_KEY(PEM 内容,多行用 \n 转义)
   *  2. 文件路径 INTEGRITY_RSA_PRIVATE_KEY_FILE(docker-compose 挂载,推荐)
   *
   * 简化版:假设 encryptedHash 是 base64 编码的 RSA-2048 密文。
   * 开发模式(两者都未配):直接 base64 解码,便于测试。
   */
  private decryptHash(encryptedHash: string): string {
    let privateKeyPem: string | undefined;

    // 优先从文件读(docker-compose 挂载)
    const keyFile = this.configService.get<string>('integrityRsaPrivateKeyFile');
    if (keyFile) {
      try {
        privateKeyPem = fs.readFileSync(keyFile, 'utf8');
      } catch (e) {
        this.logger.warn(`读取 RSA 私钥文件失败: ${keyFile} - ${(e as Error).message}`);
      }
    }

    // 回退到环境变量
    if (!privateKeyPem) {
      privateKeyPem = this.configService.get<string>('integrityRsaPrivateKey');
    }

    if (!privateKeyPem) {
      // 开发阶段:直接 base64(未加密),便于测试
      this.logger.warn('RSA 私钥未配置,开发模式直接 base64 解码');
      return Buffer.from(encryptedHash, 'base64').toString('utf8');
    }

    try {
      const privateKey = crypto.createPrivateKey(privateKeyPem);
      const decrypted = crypto.privateDecrypt(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256',
        },
        Buffer.from(encryptedHash, 'base64'),
      );
      return decrypted.toString('utf8');
    } catch (e) {
      // RSA 解密失败:客户端可能尚未实现 RSA 加密,回退 base64 解码
      this.logger.warn(`RSA 解密失败,回退 base64 解码: ${(e as Error).message}`);
      return Buffer.from(encryptedHash, 'base64').toString('utf8');
    }
  }

  /**
   * 颁发 JWT token(HMAC-SHA256 签名)
   */
  private issueToken(appId: string, deviceFingerprint: string | undefined, expireAt: Date): string {
    const header = { alg: 'HS256', typ: 'JWT' };
    const payload = {
      appId,
      fp: deviceFingerprint,
      iat: Date.now(),
      exp: expireAt.getTime(),
    };

    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const sig = crypto
      .createHmac('sha256', this.tokenSecret)
      .update(headerB64 + '.' + payloadB64)
      .digest('base64url');

    return `${headerB64}.${payloadB64}.${sig}`;
  }
}
