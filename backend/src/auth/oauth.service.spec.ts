import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import { OAuthService } from './oauth.service';
import { PrismaService } from '../prisma/prisma.service';
import { AuthService } from './auth.service';

describe('OAuthService', () => {
  let service: OAuthService;
  let prisma: {
    developer: {
      findFirst: jest.Mock;
      findUnique: jest.Mock;
      update: jest.Mock;
      create: jest.Mock;
    };
  };
  let authService: { issueTokensForOAuth: jest.Mock };
  const configMap: Record<string, string | undefined> = {
    githubClientId: 'gh-client-id',
    qqAppId: 'qq-app-id',
  };

  beforeEach(async () => {
    prisma = {
      developer: {
        findFirst: jest.fn().mockResolvedValue(null),
        findUnique: jest.fn().mockResolvedValue(null),
        update: jest.fn().mockResolvedValue({}),
        create: jest.fn().mockResolvedValue({ id: 'dev-new', email: 'a@b.c', role: 'developer' }),
      },
    };
    authService = { issueTokensForOAuth: jest.fn() };

    const module = await Test.createTestingModule({
      providers: [
        OAuthService,
        { provide: PrismaService, useValue: prisma },
        { provide: AuthService, useValue: authService },
        { provide: ConfigService, useValue: { get: jest.fn((k: string) => configMap[k]) } },
      ],
    }).compile();
    service = module.get(OAuthService);
  });

  type Priv = Record<string, (...a: unknown[]) => unknown>;

  describe('buildAuthorizeUrl', () => {
    it('github 已配置应返回授权 URL + state', async () => {
      const r = await service.buildAuthorizeUrl('github');
      expect(r.redirectUrl).toContain('github.com/login/oauth/authorize');
      expect(r.redirectUrl).toContain('client_id=gh-client-id');
      expect(r.state).toMatch(/^[0-9a-f]{32}$/);
    });

    it('github 未配置应抛 GITHUB_OAUTH_NOT_CONFIGURED', async () => {
      configMap.githubClientId = undefined;
      await expect(service.buildAuthorizeUrl('github')).rejects.toThrow(BadRequestException);
      configMap.githubClientId = 'gh-client-id';
    });

    it('qq 已配置应返回授权 URL', async () => {
      const r = await service.buildAuthorizeUrl('qq');
      expect(r.redirectUrl).toContain('graph.qq.com/oauth2.0/authorize');
      expect(r.redirectUrl).toContain('client_id=qq-app-id');
    });

    it('qq 未配置应抛 QQ_OAUTH_NOT_CONFIGURED', async () => {
      configMap.qqAppId = undefined;
      await expect(service.buildAuthorizeUrl('qq')).rejects.toThrow(BadRequestException);
      configMap.qqAppId = 'qq-app-id';
    });
  });

  describe('handleCallback / 未实现方法', () => {
    it('handleCallback 应因 token 交换未实现而抛错', async () => {
      await expect(service.handleCallback('github', 'code')).rejects.toThrow(/not implemented/);
    });

    it('exchangeCodeForToken 私有方法应抛 not implemented', async () => {
      const fn = (service as unknown as Priv).exchangeCodeForToken.bind(service);
      await expect(fn('github', 'code')).rejects.toThrow(/not implemented/);
    });

    it('fetchUserInfo 私有方法应抛 not implemented', async () => {
      const fn = (service as unknown as Priv).fetchUserInfo.bind(service);
      await expect(fn('github', 'token')).rejects.toThrow(/not implemented/);
    });
  });

  describe('findOrCreateDeveloper', () => {
    const call = (provider: string, userInfo: object) =>
      (
        (service as unknown as Priv).findOrCreateDeveloper as (
          p: string,
          u: object,
        ) => Promise<unknown>
      ).call(service, provider, userInfo);

    it('缺 providerId 应抛 OAUTH_USER_INFO_MISSING_ID', async () => {
      await expect(call('github', { email: 'a@b.c' })).rejects.toThrow(UnauthorizedException);
    });

    it('providerId 已存在应返回现有 developer', async () => {
      prisma.developer.findFirst.mockResolvedValue({
        id: 'dev-1',
        email: 'a@b.c',
        role: 'developer',
      });
      const r = await call('github', { githubId: 'gh-1' });
      expect(r).toEqual({ id: 'dev-1', email: 'a@b.c', role: 'developer' });
      expect(prisma.developer.create).not.toHaveBeenCalled();
    });

    it('email 已注册应绑定 providerId', async () => {
      prisma.developer.findFirst.mockResolvedValue(null);
      prisma.developer.findUnique.mockResolvedValue({
        id: 'dev-2',
        email: 'a@b.c',
        role: 'developer',
      });
      const r = await call('github', { githubId: 'gh-1', email: 'a@b.c' });
      expect(prisma.developer.update).toHaveBeenCalled();
      expect(r).toMatchObject({ id: 'dev-2' });
    });

    it('全新用户应创建 developer', async () => {
      prisma.developer.findFirst.mockResolvedValue(null);
      prisma.developer.findUnique.mockResolvedValue(null);
      const r = await call('qq', { qqOpenId: 'qq-1' });
      expect(prisma.developer.create).toHaveBeenCalled();
      expect(r).toMatchObject({ id: 'dev-new' });
    });
  });

  describe('getCallbackUrl', () => {
    it('localhost 应回退到 http://localhost:3000', () => {
      const fn = (service as unknown as Priv).getCallbackUrl.bind(service);
      expect(fn('github')).toContain('/v1/auth/oauth/github/callback');
    });
  });
});
