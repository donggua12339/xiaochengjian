import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as argon2 from 'argon2';
import * as crypto from 'crypto';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { TotpService } from './totp.service';
import type { AppConfig } from '../config/configuration';
import type { JwtPayload } from '../common/decorators/current-developer.decorator';

/**
 * 认证服务
 * 详见 ADR 0027 (2FA / JWT / 密码)
 *
 * JWT 策略:
 *  - access token: 15 分钟,签名 secret=jwtAccessSecret,payload={sub,email,role}
 *  - refresh token: 7 天,随机字符串,存 Redis(可撤销)
 *  - pendingTotpToken: 5 分钟,随机字符串,存 Redis(2FA 流程中间态)
 */
@Injectable()
export class AuthService {
  private readonly REFRESH_TTL = 7 * 24 * 60 * 60; // 7 天
  private readonly PENDING_TOTP_TTL = 5 * 60; // 5 分钟

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly redis: RedisService,
    private readonly totp: TotpService,
    private readonly configService: ConfigService<AppConfig, true>,
  ) {}

  /**
   * 注册
   * 邮箱+密码创建开发者账号
   * 注册成功后不自动登录(需调 login)
   */
  async register(email: string, password: string): Promise<{ developerId: string; email: string }> {
    const normalizedEmail = email.toLowerCase().trim();

    const existing = await this.prisma.developer.findUnique({
      where: { email: normalizedEmail },
      select: { id: true },
    });
    if (existing) {
      throw new ConflictException('EMAIL_ALREADY_REGISTERED');
    }

    const passwordHash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 19456,
      timeCost: 2,
      parallelism: 1,
    });

    const developer = await this.prisma.developer.create({
      data: {
        email: normalizedEmail,
        passwordHash,
      },
      select: { id: true, email: true },
    });

    return { developerId: developer.id, email: developer.email };
  }

  /**
   * 登录
   * 验证邮箱+密码
   *  - 未启用 2FA: 返回 access + refresh
   *  - 已启用 2FA: 返回 pendingTotpToken(客户端需再调 2FA 验证)
   */
  async login(
    email: string,
    password: string,
    meta: { ip?: string; userAgent?: string } = {},
  ): Promise<LoginResult> {
    const normalizedEmail = email.toLowerCase().trim();

    const developer = await this.prisma.developer.findUnique({
      where: { email: normalizedEmail },
    });
    if (!developer) {
      throw new UnauthorizedException('INVALID_CREDENTIALS');
    }

    const passwordValid = await argon2.verify(developer.passwordHash, password);
    if (!passwordValid) {
      throw new UnauthorizedException('INVALID_CREDENTIALS');
    }

    // 更新最后登录信息
    await this.prisma.developer.update({
      where: { id: developer.id },
      data: { lastLoginAt: new Date(), lastLoginIp: meta.ip },
    });

    // 已启用 2FA: 返回 pendingTotpToken
    if (developer.totpEnabled && developer.totpSecret) {
      const pendingTotpToken = this.generateToken();
      await this.redis.set(`totp_pending:${pendingTotpToken}`, developer.id, this.PENDING_TOTP_TTL);
      return {
        requiresTotp: true,
        pendingTotpToken,
        developerId: developer.id,
      };
    }

    // 未启用 2FA: 直接返回 access + refresh
    const tokens = await this.issueTokens(developer.id, developer.email, developer.role, meta);
    return {
      requiresTotp: false,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
  }

  /**
   * 刷新 access token
   * 验证 refresh token 在 Redis 中存在,签发新 access + refresh
   */
  async refresh(
    refreshToken: string,
    meta: { ip?: string; userAgent?: string } = {},
  ): Promise<TokenPair> {
    const refreshHash = this.hashToken(refreshToken);
    const key = `refresh:${refreshHash}`;

    const raw = await this.redis.get(key);
    if (!raw) {
      throw new UnauthorizedException('INVALID_REFRESH_TOKEN');
    }

    let developerId: string;
    try {
      const parsed = JSON.parse(raw) as { developerId: string };
      developerId = parsed.developerId;
    } catch {
      // 兼容旧格式(纯 developerId)
      developerId = raw;
    }

    const developer = await this.prisma.developer.findUnique({
      where: { id: developerId },
      select: { id: true, email: true, role: true },
    });
    if (!developer) {
      await this.redis.del(key);
      throw new UnauthorizedException('DEVELOPER_NOT_FOUND');
    }

    // 撤销旧 refresh token(rotation,防重放)
    await this.redis.del(key);

    return this.issueTokens(developer.id, developer.email, developer.role, meta);
  }

  /**
   * 登出
   * 撤销 refresh token
   */
  async logout(refreshToken: string): Promise<void> {
    const refreshHash = this.hashToken(refreshToken);
    await this.redis.del(`refresh:${refreshHash}`);
  }

  /**
   * 设置 2FA(生成 TOTP secret + QR URL)
   * 需要开发者已登录
   * 返回 secret + otpauthUrl(客户端生成二维码)
   * 此时不保存 secret 到数据库,等 verifyTotp 确认后才保存
   */
  async setupTotp(developerId: string): Promise<{
    secret: string;
    otpauthUrl: string;
  }> {
    const developer = await this.prisma.developer.findUnique({
      where: { id: developerId },
      select: { id: true, email: true, totpEnabled: true },
    });
    if (!developer) {
      throw new NotFoundException('DEVELOPER_NOT_FOUND');
    }
    if (developer.totpEnabled) {
      throw new BadRequestException('2FA_ALREADY_ENABLED');
    }

    const secret = this.totp.generateSecret();
    const otpauthUrl = this.totp.generateOtpAuthUrl(developer.email, secret);

    // 暂存 secret 到 Redis(10 分钟),等 verifyTotp 确认
    await this.redis.set(`totp_setup:${developerId}`, secret, 10 * 60);

    return { secret, otpauthUrl };
  }

  /**
   * 验证 TOTP 码,启用 2FA
   * 从 Redis 读取待确认的 secret,验证 TOTP 码
   * 验证通过后保存 secret 到数据库,返回备份码(仅此一次)
   */
  async verifyTotp(
    developerId: string,
    code: string,
  ): Promise<{
    backupCodes: string[];
  }> {
    const developer = await this.prisma.developer.findUnique({
      where: { id: developerId },
      select: { id: true, totpEnabled: true },
    });
    if (!developer) {
      throw new NotFoundException('DEVELOPER_NOT_FOUND');
    }
    if (developer.totpEnabled) {
      throw new BadRequestException('2FA_ALREADY_ENABLED');
    }

    const secret = await this.redis.get(`totp_setup:${developerId}`);
    if (!secret) {
      throw new BadRequestException('TOTP_SETUP_EXPIRED');
    }

    const valid = this.totp.verify(code, secret);
    if (!valid) {
      throw new UnauthorizedException('INVALID_TOTP_CODE');
    }

    // 生成 10 个备份码(明文返回,哈希存库)
    const backupCodesPlain = this.totp.generateBackupCodes();
    const backupCodesHashed = backupCodesPlain.map((c) => this.totp.hashBackupCode(c));

    await this.prisma.developer.update({
      where: { id: developerId },
      data: {
        totpSecret: secret,
        totpEnabled: true,
        backupCodes: backupCodesHashed,
      },
    });

    await this.redis.del(`totp_setup:${developerId}`);

    return { backupCodes: backupCodesPlain };
  }

  /**
   * 用备份码完成 2FA 登录
   * 验证 pendingTotpToken + 备份码
   * 返回 access + refresh(备份码一次性,消耗一个)
   */
  async verifyBackup(
    pendingTotpToken: string,
    backupCode: string,
    meta: { ip?: string; userAgent?: string } = {},
  ): Promise<TokenPair> {
    const developerId = await this.redis.get(`totp_pending:${pendingTotpToken}`);
    if (!developerId) {
      throw new UnauthorizedException('PENDING_TOTP_TOKEN_EXPIRED');
    }

    const developer = await this.prisma.developer.findUnique({
      where: { id: developerId },
    });
    if (!developer || !developer.totpEnabled) {
      throw new UnauthorizedException('DEVELOPER_NOT_FOUND');
    }

    const [matched, remaining] = this.totp.verifyBackupCode(backupCode, developer.backupCodes);
    if (!matched) {
      throw new UnauthorizedException('INVALID_BACKUP_CODE');
    }

    await this.prisma.developer.update({
      where: { id: developerId },
      data: { backupCodes: remaining },
    });

    await this.redis.del(`totp_pending:${pendingTotpToken}`);

    return this.issueTokens(developer.id, developer.email, developer.role, meta);
  }

  /**
   * 用 TOTP 码完成 2FA 登录
   */
  async verifyTotpLogin(
    pendingTotpToken: string,
    code: string,
    meta: { ip?: string; userAgent?: string } = {},
  ): Promise<TokenPair> {
    const developerId = await this.redis.get(`totp_pending:${pendingTotpToken}`);
    if (!developerId) {
      throw new UnauthorizedException('PENDING_TOTP_TOKEN_EXPIRED');
    }

    const developer = await this.prisma.developer.findUnique({
      where: { id: developerId },
      select: { id: true, email: true, role: true, totpSecret: true, totpEnabled: true },
    });
    if (!developer || !developer.totpEnabled || !developer.totpSecret) {
      throw new UnauthorizedException('DEVELOPER_NOT_FOUND');
    }

    const valid = this.totp.verify(code, developer.totpSecret);
    if (!valid) {
      throw new UnauthorizedException('INVALID_TOTP_CODE');
    }

    await this.redis.del(`totp_pending:${pendingTotpToken}`);

    return this.issueTokens(developer.id, developer.email, developer.role, meta);
  }

  /**
   * 修改密码
   * 校验当前密码 -> argon2 哈希新密码 -> 更新 developer.passwordHash
   * 不撤销已签发的 refresh token(用户可继续使用现有会话,但下次登录用新密码)
   */
  async changePassword(
    developerId: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<{ success: true }> {
    const developer = await this.prisma.developer.findUnique({
      where: { id: developerId },
      select: { id: true, passwordHash: true },
    });
    if (!developer) {
      throw new NotFoundException('DEVELOPER_NOT_FOUND');
    }

    const passwordValid = await argon2.verify(developer.passwordHash, currentPassword);
    if (!passwordValid) {
      throw new UnauthorizedException('CURRENT_PASSWORD_INCORRECT');
    }

    if (currentPassword === newPassword) {
      throw new BadRequestException('NEW_PASSWORD_MUST_DIFFER');
    }

    const newHash = await argon2.hash(newPassword, {
      type: argon2.argon2id,
      memoryCost: 19456,
      timeCost: 2,
      parallelism: 1,
    });

    await this.prisma.developer.update({
      where: { id: developerId },
      data: { passwordHash: newHash },
    });

    return { success: true };
  }

  /**
   * 获取开发者资料(个人信息页用)
   * 返回 email / role / createdAt / maxApps / 2FA 状态
   */
  async getProfile(developerId: string): Promise<{
    id: string;
    email: string;
    role: string;
    createdAt: Date;
    maxApps: number;
    totpEnabled: boolean;
  }> {
    const developer = await this.prisma.developer.findUnique({
      where: { id: developerId },
      select: {
        id: true,
        email: true,
        role: true,
        createdAt: true,
        maxApps: true,
        totpEnabled: true,
      },
    });
    if (!developer) {
      throw new NotFoundException('DEVELOPER_NOT_FOUND');
    }
    return developer;
  }

  /**
   * 签发 access + refresh token 对
   * meta 信息(IP/userAgent)随 refresh token 一起存 Redis,便于审计
   */
  private async issueTokens(
    developerId: string,
    email: string,
    role: string,
    meta: { ip?: string; userAgent?: string },
  ): Promise<TokenPair> {
    const payload: JwtPayload = { sub: developerId, email, role };

    const expiresIn = this.configService.get('jwtAccessExpiresIn', { infer: true });
    const accessToken = await this.jwtService.signAsync(payload, { expiresIn });

    const refreshToken = this.generateToken();
    const refreshHash = this.hashToken(refreshToken);
    // value 格式:developerId|ip|userAgent(便于审计追溯)
    const value = JSON.stringify({ developerId, ...meta });
    await this.redis.set(`refresh:${refreshHash}`, value, this.REFRESH_TTL);

    return { accessToken, refreshToken };
  }

  private generateToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  private hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export interface LoginResult {
  requiresTotp: boolean;
  pendingTotpToken?: string;
  developerId?: string;
  accessToken?: string;
  refreshToken?: string;
}
