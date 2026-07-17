import { Test } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as argon2 from 'argon2';
import {
  ConflictException,
  UnauthorizedException,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { TotpService } from './totp.service';

/**
 * AuthService 单元测试
 *
 * 覆盖:
 *  - register: 正常 / EMAIL_ALREADY_REGISTERED / 邮箱规范化
 *  - login: 正常(无 2FA)/ 正常(有 2FA,返回 pendingTotpToken)/ INVALID_CREDENTIALS(用户不存在/密码错)
 *  - refresh: 正常 / INVALID_REFRESH_TOKEN / DEVELOPER_NOT_FOUND / 旧 token 撤销
 *  - logout: 撤销 refresh token
 *  - setupTotp: 正常 / DEVELOPER_NOT_FOUND / 2FA_ALREADY_ENABLED
 *  - verifyTotp: 正常 / DEVELOPER_NOT_FOUND / 2FA_ALREADY_ENABLED / TOTP_SETUP_EXPIRED / INVALID_TOTP_CODE
 *  - verifyBackup: 正常 / PENDING_TOTP_TOKEN_EXPIRED / DEVELOPER_NOT_FOUND / INVALID_BACKUP_CODE
 *  - verifyTotpLogin: 正常 / PENDING_TOTP_TOKEN_EXPIRED / INVALID_TOTP_CODE
 *  - changePassword: 正常 / DEVELOPER_NOT_FOUND / CURRENT_PASSWORD_INCORRECT / NEW_PASSWORD_MUST_DIFFER
 *  - getProfile: 正常 / DEVELOPER_NOT_FOUND
 */
describe('AuthService', () => {
  let service: AuthService;
  let prisma: {
    developer: {
      findUnique: jest.Mock;
      create: jest.Mock;
      update: jest.Mock;
    };
  };
  let redis: {
    get: jest.Mock;
    set: jest.Mock;
    del: jest.Mock;
  };
  let totp: {
    generateSecret: jest.Mock;
    generateOtpAuthUrl: jest.Mock;
    verify: jest.Mock;
    generateBackupCodes: jest.Mock;
    hashBackupCode: jest.Mock;
    verifyBackupCode: jest.Mock;
  };
  let jwtService: { signAsync: jest.Mock };
  let configService: { get: jest.Mock };

  const developerId = 'dev-1';
  const email = 'test@xcj.test';
  const password = 'Password123';
  // 用 beforeAll 生成真实 argon2 hash,避免 top-level await + 避免每次测试重算
  let realHash: string;

  beforeAll(async () => {
    realHash = await argon2.hash(password, { type: argon2.argon2id });
  });

  beforeEach(async () => {
    prisma = {
      developer: {
        findUnique: jest.fn(),
        create: jest.fn(),
        update: jest.fn(),
      },
    };
    redis = {
      get: jest.fn(),
      set: jest.fn().mockResolvedValue(undefined),
      del: jest.fn().mockResolvedValue(1),
    };
    totp = {
      generateSecret: jest.fn().mockReturnValue('SECRET-BASE32'),
      generateOtpAuthUrl: jest.fn().mockReturnValue('otpauth://totp/test'),
      verify: jest.fn(),
      generateBackupCodes: jest.fn().mockReturnValue(['CODE1', 'CODE2']),
      hashBackupCode: jest.fn((c: string) => `hash(${c})`),
      verifyBackupCode: jest.fn(),
    };
    jwtService = {
      signAsync: jest.fn().mockResolvedValue('access-token'),
    };
    configService = {
      get: jest.fn((key: string) => {
        if (key === 'jwtAccessExpiresIn') return '15m';
        return undefined;
      }),
    };

    const moduleRef = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: PrismaService, useValue: prisma },
        { provide: RedisService, useValue: redis },
        { provide: TotpService, useValue: totp },
        { provide: JwtService, useValue: jwtService },
        { provide: ConfigService, useValue: configService },
      ],
    }).compile();
    service = moduleRef.get(AuthService);
  });

  describe('register', () => {
    it('邮箱已注册应拒绝(EMAIL_ALREADY_REGISTERED)', async () => {
      prisma.developer.findUnique.mockResolvedValue({ id: developerId });
      await expect(service.register(email, password)).rejects.toThrow(ConflictException);
    });

    it('正常注册应返回 developerId + email', async () => {
      prisma.developer.findUnique.mockResolvedValue(null);
      prisma.developer.create.mockResolvedValue({ id: developerId, email });
      const result = await service.register(email, password);
      expect(result).toEqual({ developerId, email });
    });

    it('邮箱应转小写 + 去空格', async () => {
      prisma.developer.findUnique.mockResolvedValue(null);
      prisma.developer.create.mockResolvedValue({ id: developerId, email });
      await service.register('  Test@XCJ.TEST  ', password);
      expect(prisma.developer.findUnique).toHaveBeenCalledWith({
        where: { email: 'test@xcj.test' },
        select: { id: true },
      });
    });
  });

  describe('login', () => {
    it('用户不存在应拒绝(INVALID_CREDENTIALS)', async () => {
      prisma.developer.findUnique.mockResolvedValue(null);
      await expect(service.login(email, password)).rejects.toThrow(UnauthorizedException);
    });

    it('密码错误应拒绝(INVALID_CREDENTIALS)', async () => {
      prisma.developer.findUnique.mockResolvedValue({
        id: developerId,
        email,
        passwordHash: realHash,
        role: 'DEVELOPER',
        totpEnabled: false,
        totpSecret: null,
      });
      await expect(service.login(email, 'wrong-password')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('未启用 2FA 应直接返回 access + refresh', async () => {
      prisma.developer.findUnique.mockResolvedValue({
        id: developerId,
        email,
        passwordHash: realHash,
        role: 'DEVELOPER',
        totpEnabled: false,
        totpSecret: null,
      });
      const result = await service.login(email, password, { ip: '1.1.1.1' });
      expect(result.requiresTotp).toBe(false);
      expect(result.accessToken).toBe('access-token');
      expect(result.refreshToken).toBeDefined();
      // 应更新 lastLoginAt
      expect(prisma.developer.update).toHaveBeenCalledWith({
        where: { id: developerId },
        data: expect.objectContaining({ lastLoginAt: expect.any(Date), lastLoginIp: '1.1.1.1' }),
      });
    });

    it('已启用 2FA 应返回 pendingTotpToken', async () => {
      prisma.developer.findUnique.mockResolvedValue({
        id: developerId,
        email,
        passwordHash: realHash,
        role: 'DEVELOPER',
        totpEnabled: true,
        totpSecret: 'secret',
      });
      const result = await service.login(email, password);
      expect(result.requiresTotp).toBe(true);
      expect(result.pendingTotpToken).toBeDefined();
      expect(result.developerId).toBe(developerId);
      // 应存 Redis
      expect(redis.set).toHaveBeenCalledWith(
        `totp_pending:${result.pendingTotpToken}`,
        developerId,
        5 * 60,
      );
    });
  });

  describe('refresh', () => {
    it('refresh token 不存在应拒绝(INVALID_REFRESH_TOKEN)', async () => {
      redis.get.mockResolvedValue(null);
      await expect(service.refresh('old-token')).rejects.toThrow(UnauthorizedException);
    });

    it('developer 不存在应拒绝 + 清理 Redis(DEVELOPER_NOT_FOUND)', async () => {
      redis.get.mockResolvedValue(JSON.stringify({ developerId }));
      prisma.developer.findUnique.mockResolvedValue(null);
      await expect(service.refresh('old-token')).rejects.toThrow(UnauthorizedException);
      expect(redis.del).toHaveBeenCalled();
    });

    it('正常刷新应撤销旧 token + 签发新 token(rotation)', async () => {
      redis.get.mockResolvedValue(JSON.stringify({ developerId }));
      prisma.developer.findUnique.mockResolvedValue({
        id: developerId,
        email,
        role: 'DEVELOPER',
      });
      const result = await service.refresh('old-token');
      expect(result.accessToken).toBe('access-token');
      expect(result.refreshToken).toBeDefined();
      // 应撤销旧 token
      expect(redis.del).toHaveBeenCalled();
    });

    it('Redis 存旧格式(纯 developerId)应兼容', async () => {
      redis.get.mockResolvedValue(developerId); // 纯字符串,非 JSON
      prisma.developer.findUnique.mockResolvedValue({
        id: developerId,
        email,
        role: 'DEVELOPER',
      });
      const result = await service.refresh('old-token');
      expect(result.accessToken).toBe('access-token');
    });
  });

  describe('logout', () => {
    it('应撤销 refresh token', async () => {
      await service.logout('some-token');
      expect(redis.del).toHaveBeenCalledWith(expect.stringContaining('refresh:'));
    });
  });

  describe('setupTotp', () => {
    it('developer 不存在应拒绝(DEVELOPER_NOT_FOUND)', async () => {
      prisma.developer.findUnique.mockResolvedValue(null);
      await expect(service.setupTotp(developerId)).rejects.toThrow(NotFoundException);
    });

    it('已启用 2FA 应拒绝(2FA_ALREADY_ENABLED)', async () => {
      prisma.developer.findUnique.mockResolvedValue({
        id: developerId,
        email,
        totpEnabled: true,
      });
      await expect(service.setupTotp(developerId)).rejects.toThrow(BadRequestException);
    });

    it('正常应返回 secret + otpauthUrl,并存 Redis 等待 verify', async () => {
      prisma.developer.findUnique.mockResolvedValue({
        id: developerId,
        email,
        totpEnabled: false,
      });
      const result = await service.setupTotp(developerId);
      expect(result.secret).toBe('SECRET-BASE32');
      expect(result.otpauthUrl).toBe('otpauth://totp/test');
      expect(redis.set).toHaveBeenCalledWith(`totp_setup:${developerId}`, 'SECRET-BASE32', 10 * 60);
    });
  });

  describe('verifyTotp(启用 2FA)', () => {
    it('developer 不存在应拒绝', async () => {
      prisma.developer.findUnique.mockResolvedValue(null);
      await expect(service.verifyTotp(developerId, '123456')).rejects.toThrow(NotFoundException);
    });

    it('已启用 2FA 应拒绝', async () => {
      prisma.developer.findUnique.mockResolvedValue({
        id: developerId,
        totpEnabled: true,
      });
      await expect(service.verifyTotp(developerId, '123456')).rejects.toThrow(BadRequestException);
    });

    it('setup 过期应拒绝(TOTP_SETUP_EXPIRED)', async () => {
      prisma.developer.findUnique.mockResolvedValue({
        id: developerId,
        totpEnabled: false,
      });
      redis.get.mockResolvedValue(null);
      await expect(service.verifyTotp(developerId, '123456')).rejects.toThrow(BadRequestException);
    });

    it('TOTP 码错误应拒绝(INVALID_TOTP_CODE)', async () => {
      prisma.developer.findUnique.mockResolvedValue({
        id: developerId,
        totpEnabled: false,
      });
      redis.get.mockResolvedValue('SECRET-BASE32');
      totp.verify.mockReturnValue(false);
      await expect(service.verifyTotp(developerId, '000000')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('正常应保存 secret + 返回备份码(明文)', async () => {
      prisma.developer.findUnique.mockResolvedValue({
        id: developerId,
        totpEnabled: false,
      });
      redis.get.mockResolvedValue('SECRET-BASE32');
      totp.verify.mockReturnValue(true);
      const result = await service.verifyTotp(developerId, '123456');
      expect(result.backupCodes).toEqual(['CODE1', 'CODE2']);
      // 应保存 secret + hashed 备份码到 DB
      expect(prisma.developer.update).toHaveBeenCalledWith({
        where: { id: developerId },
        data: expect.objectContaining({
          totpSecret: 'SECRET-BASE32',
          totpEnabled: true,
          backupCodes: ['hash(CODE1)', 'hash(CODE2)'],
        }),
      });
      // 应清理 Redis 中的 setup secret
      expect(redis.del).toHaveBeenCalledWith(`totp_setup:${developerId}`);
    });
  });

  describe('verifyBackup(备份码登录)', () => {
    it('pendingTotpToken 过期应拒绝', async () => {
      redis.get.mockResolvedValue(null);
      await expect(service.verifyBackup('token', 'CODE1')).rejects.toThrow(UnauthorizedException);
    });

    it('developer 不存在应拒绝', async () => {
      redis.get.mockResolvedValue(developerId);
      prisma.developer.findUnique.mockResolvedValue(null);
      await expect(service.verifyBackup('token', 'CODE1')).rejects.toThrow(UnauthorizedException);
    });

    it('未启用 2FA 应拒绝', async () => {
      redis.get.mockResolvedValue(developerId);
      prisma.developer.findUnique.mockResolvedValue({
        id: developerId,
        email,
        role: 'DEVELOPER',
        totpEnabled: false,
        backupCodes: [],
      });
      await expect(service.verifyBackup('token', 'CODE1')).rejects.toThrow(UnauthorizedException);
    });

    it('备份码错误应拒绝(INVALID_BACKUP_CODE)', async () => {
      redis.get.mockResolvedValue(developerId);
      prisma.developer.findUnique.mockResolvedValue({
        id: developerId,
        email,
        role: 'DEVELOPER',
        totpEnabled: true,
        backupCodes: ['hash(CODE1)'],
      });
      totp.verifyBackupCode.mockReturnValue([false, ['hash(CODE1)']]);
      await expect(service.verifyBackup('token', 'WRONG')).rejects.toThrow(UnauthorizedException);
    });

    it('正常应消耗备份码 + 返回新 token', async () => {
      redis.get.mockResolvedValue(developerId);
      prisma.developer.findUnique.mockResolvedValue({
        id: developerId,
        email,
        role: 'DEVELOPER',
        totpEnabled: true,
        backupCodes: ['hash(CODE1)', 'hash(CODE2)'],
      });
      totp.verifyBackupCode.mockReturnValue([true, ['hash(CODE2)']]);
      const result = await service.verifyBackup('token', 'CODE1');
      expect(result.accessToken).toBe('access-token');
      // 应更新 backupCodes(消耗一个)
      expect(prisma.developer.update).toHaveBeenCalledWith({
        where: { id: developerId },
        data: { backupCodes: ['hash(CODE2)'] },
      });
      // 应清理 pendingTotpToken
      expect(redis.del).toHaveBeenCalledWith('totp_pending:token');
    });
  });

  describe('verifyTotpLogin(TOTP 码登录)', () => {
    it('pendingTotpToken 过期应拒绝', async () => {
      redis.get.mockResolvedValue(null);
      await expect(service.verifyTotpLogin('token', '123456')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('developer 不存在应拒绝', async () => {
      redis.get.mockResolvedValue(developerId);
      prisma.developer.findUnique.mockResolvedValue(null);
      await expect(service.verifyTotpLogin('token', '123456')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('未启用 2FA 应拒绝', async () => {
      redis.get.mockResolvedValue(developerId);
      prisma.developer.findUnique.mockResolvedValue({
        id: developerId,
        email,
        role: 'DEVELOPER',
        totpEnabled: false,
        totpSecret: null,
      });
      await expect(service.verifyTotpLogin('token', '123456')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('TOTP 码错误应拒绝', async () => {
      redis.get.mockResolvedValue(developerId);
      prisma.developer.findUnique.mockResolvedValue({
        id: developerId,
        email,
        role: 'DEVELOPER',
        totpEnabled: true,
        totpSecret: 'secret',
      });
      totp.verify.mockReturnValue(false);
      await expect(service.verifyTotpLogin('token', '000000')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('正常应返回新 token + 清理 pendingTotpToken', async () => {
      redis.get.mockResolvedValue(developerId);
      prisma.developer.findUnique.mockResolvedValue({
        id: developerId,
        email,
        role: 'DEVELOPER',
        totpEnabled: true,
        totpSecret: 'secret',
      });
      totp.verify.mockReturnValue(true);
      const result = await service.verifyTotpLogin('token', '123456');
      expect(result.accessToken).toBe('access-token');
      expect(redis.del).toHaveBeenCalledWith('totp_pending:token');
    });
  });

  describe('changePassword', () => {
    it('developer 不存在应拒绝', async () => {
      prisma.developer.findUnique.mockResolvedValue(null);
      await expect(
        service.changePassword(developerId, password, 'NewPassword456'),
      ).rejects.toThrow(NotFoundException);
    });

    it('当前密码错误应拒绝(CURRENT_PASSWORD_INCORRECT)', async () => {
      prisma.developer.findUnique.mockResolvedValue({ id: developerId, passwordHash: realHash });
      await expect(
        service.changePassword(developerId, 'wrong-current', 'NewPassword456'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('新密码与当前相同应拒绝(NEW_PASSWORD_MUST_DIFFER)', async () => {
      prisma.developer.findUnique.mockResolvedValue({ id: developerId, passwordHash: realHash });
      await expect(
        service.changePassword(developerId, password, password),
      ).rejects.toThrow(BadRequestException);
    });

    it('正常应更新密码 hash', async () => {
      prisma.developer.findUnique.mockResolvedValue({ id: developerId, passwordHash: realHash });
      const result = await service.changePassword(developerId, password, 'NewPassword456');
      expect(result).toEqual({ success: true });
      expect(prisma.developer.update).toHaveBeenCalledWith({
        where: { id: developerId },
        data: { passwordHash: expect.any(String) },
      });
    });
  });

  describe('getProfile', () => {
    it('developer 不存在应拒绝', async () => {
      prisma.developer.findUnique.mockResolvedValue(null);
      await expect(service.getProfile(developerId)).rejects.toThrow(NotFoundException);
    });

    it('正常应返回 profile', async () => {
      const profile = {
        id: developerId,
        email,
        role: 'DEVELOPER',
        createdAt: new Date(),
        maxApps: 10,
        totpEnabled: false,
      };
      prisma.developer.findUnique.mockResolvedValue(profile);
      const result = await service.getProfile(developerId);
      expect(result).toEqual(profile);
    });
  });
});
