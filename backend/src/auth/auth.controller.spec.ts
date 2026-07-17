import { Test } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { AuditInterceptor } from '../audit/audit.interceptor';

/**
 * AuthController 单元测试
 *
 * 覆盖 9 个端点:
 *  - POST /auth/register
 *  - POST /auth/login
 *  - POST /auth/refresh
 *  - POST /auth/logout
 *  - POST /auth/2fa/setup(需 JWT)
 *  - POST /auth/2fa/verify(需 JWT)
 *  - POST /auth/2fa/login
 *  - POST /auth/2fa/backup
 *  - POST /auth/change-password(需 JWT)
 *  - GET /auth/profile(需 JWT)
 */
describe('AuthController', () => {
  let controller: AuthController;
  let authService: {
    register: jest.Mock;
    login: jest.Mock;
    refresh: jest.Mock;
    logout: jest.Mock;
    setupTotp: jest.Mock;
    verifyTotp: jest.Mock;
    verifyTotpLogin: jest.Mock;
    verifyBackup: jest.Mock;
    changePassword: jest.Mock;
    getProfile: jest.Mock;
  };

  beforeEach(async () => {
    authService = {
      register: jest.fn().mockResolvedValue({ developerId: 'dev-1', email: 'test@xcj.test' }),
      login: jest.fn().mockResolvedValue({
        requiresTotp: false,
        accessToken: 'access',
        refreshToken: 'refresh',
      }),
      refresh: jest.fn().mockResolvedValue({ accessToken: 'new-access', refreshToken: 'new-refresh' }),
      logout: jest.fn().mockResolvedValue(undefined),
      setupTotp: jest.fn().mockResolvedValue({ secret: 'S', otpauthUrl: 'otpauth://x' }),
      verifyTotp: jest.fn().mockResolvedValue({ backupCodes: ['C1', 'C2'] }),
      verifyTotpLogin: jest.fn().mockResolvedValue({ accessToken: 'a', refreshToken: 'r' }),
      verifyBackup: jest.fn().mockResolvedValue({ accessToken: 'a', refreshToken: 'r' }),
      changePassword: jest.fn().mockResolvedValue({ success: true }),
      getProfile: jest.fn().mockResolvedValue({ id: 'dev-1', email: 'test@xcj.test' }),
    };

    const moduleRef = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [{ provide: AuthService, useValue: authService }],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .overrideInterceptor(AuditInterceptor)
      .useValue({ intercept: (_ctx: any, next: any) => next.handle() })
      .compile();
    controller = moduleRef.get(AuthController);
  });

  describe('register', () => {
    it('应转调 authService.register', async () => {
      const result = await controller.register({ email: 'test@xcj.test', password: 'Pass123' });
      expect(authService.register).toHaveBeenCalledWith('test@xcj.test', 'Pass123');
      expect(result).toEqual({ developerId: 'dev-1', email: 'test@xcj.test' });
    });
  });

  describe('login', () => {
    it('应转调 authService.login,透传 ip + userAgent', async () => {
      const result = await controller.login(
        { email: 'test@xcj.test', password: 'Pass123' },
        '1.2.3.4',
        'Mozilla/5.0',
      );
      expect(authService.login).toHaveBeenCalledWith('test@xcj.test', 'Pass123', {
        ip: '1.2.3.4',
        userAgent: 'Mozilla/5.0',
      });
      expect(result).toEqual({
        requiresTotp: false,
        accessToken: 'access',
        refreshToken: 'refresh',
      });
    });

    it('userAgent 可选', async () => {
      await controller.login({ email: 't@x.test', password: 'p' }, '1.2.3.4', undefined);
      expect(authService.login).toHaveBeenCalledWith('t@x.test', 'p', {
        ip: '1.2.3.4',
        userAgent: undefined,
      });
    });
  });

  describe('refresh', () => {
    it('应转调 authService.refresh', async () => {
      const result = await controller.refresh(
        { refreshToken: 'old-refresh' },
        '1.2.3.4',
        'UA',
      );
      expect(authService.refresh).toHaveBeenCalledWith('old-refresh', { ip: '1.2.3.4', userAgent: 'UA' });
      expect(result).toEqual({ accessToken: 'new-access', refreshToken: 'new-refresh' });
    });
  });

  describe('logout', () => {
    it('应转调 authService.logout + 返回 success', async () => {
      const result = await controller.logout({ refreshToken: 'r' });
      expect(authService.logout).toHaveBeenCalledWith('r');
      expect(result).toEqual({ success: true });
    });
  });

  describe('2fa/setup', () => {
    it('应转调 authService.setupTotp(需 JWT)', async () => {
      const result = await controller.setupTotp('dev-1');
      expect(authService.setupTotp).toHaveBeenCalledWith('dev-1');
      expect(result).toEqual({ secret: 'S', otpauthUrl: 'otpauth://x' });
    });
  });

  describe('2fa/verify', () => {
    it('应转调 authService.verifyTotp', async () => {
      const result = await controller.verifyTotp('dev-1', { code: '123456' });
      expect(authService.verifyTotp).toHaveBeenCalledWith('dev-1', '123456');
      expect(result).toEqual({ backupCodes: ['C1', 'C2'] });
    });
  });

  describe('2fa/login', () => {
    it('应转调 authService.verifyTotpLogin', async () => {
      await controller.totpLogin(
        { pendingTotpToken: 'p', code: '123456' },
        '1.2.3.4',
        'UA',
      );
      expect(authService.verifyTotpLogin).toHaveBeenCalledWith('p', '123456', {
        ip: '1.2.3.4',
        userAgent: 'UA',
      });
    });
  });

  describe('2fa/backup', () => {
    it('应转调 authService.verifyBackup', async () => {
      await controller.backupLogin(
        { pendingTotpToken: 'p', code: '123456', backupCode: 'C1' } as any,
        '1.2.3.4',
        'UA',
      );
      expect(authService.verifyBackup).toHaveBeenCalledWith('p', 'C1', {
        ip: '1.2.3.4',
        userAgent: 'UA',
      });
    });
  });

  describe('change-password', () => {
    it('应转调 authService.changePassword(需 JWT)', async () => {
      const result = await controller.changePassword('dev-1', {
        currentPassword: 'old',
        newPassword: 'new12345',
      });
      expect(authService.changePassword).toHaveBeenCalledWith('dev-1', 'old', 'new12345');
      expect(result).toEqual({ success: true });
    });
  });

  describe('profile', () => {
    it('应转调 authService.getProfile(需 JWT)', async () => {
      const result = await controller.getProfile('dev-1');
      expect(authService.getProfile).toHaveBeenCalledWith('dev-1');
      expect(result).toEqual({ id: 'dev-1', email: 'test@xcj.test' });
    });
  });
});
