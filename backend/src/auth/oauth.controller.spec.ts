import { BadRequestException } from '@nestjs/common';
import { OAuthController } from './oauth.controller';
import { OAuthService } from './oauth.service';

describe('OAuthController', () => {
  let controller: OAuthController;
  let oauthService: { buildAuthorizeUrl: jest.Mock; handleCallback: jest.Mock };

  function makeRes(cookies: Record<string, string> = {}) {
    return {
      cookie: jest.fn(),
      clearCookie: jest.fn(),
      redirect: jest.fn(),
      req: { cookies },
    } as unknown as import('express').Response & {
      cookie: jest.Mock;
      clearCookie: jest.Mock;
      redirect: jest.Mock;
    };
  }

  beforeEach(() => {
    oauthService = {
      buildAuthorizeUrl: jest
        .fn()
        .mockResolvedValue({ redirectUrl: 'https://gh/auth', state: 'st-1' }),
      handleCallback: jest.fn().mockResolvedValue({
        accessToken: 'at',
        refreshToken: 'rt',
        developerId: 'dev-1',
      }),
    };
    controller = new OAuthController(oauthService as unknown as OAuthService);
  });

  describe('authorize', () => {
    it('不支持的 provider 应抛 UNSUPPORTED_PROVIDER', async () => {
      await expect(controller.authorize('weibo', makeRes())).rejects.toThrow(BadRequestException);
    });

    it('github 应构造 URL + 设 cookie + 302 重定向', async () => {
      const res = makeRes();
      await controller.authorize('github', res);
      expect(oauthService.buildAuthorizeUrl).toHaveBeenCalledWith('github');
      expect(res.cookie).toHaveBeenCalledWith('oauth_state_github', 'st-1', expect.any(Object));
      expect(res.redirect).toHaveBeenCalledWith(302, 'https://gh/auth');
    });
  });

  describe('callback', () => {
    it('不支持的 provider 应抛错', async () => {
      await expect(controller.callback('weibo', 'code', 'st', makeRes())).rejects.toThrow(
        BadRequestException,
      );
    });

    it('缺 code 应抛 MISSING_CODE', async () => {
      await expect(controller.callback('github', '', 'st', makeRes())).rejects.toThrow(
        BadRequestException,
      );
    });

    it('state 不匹配应抛 OAUTH_STATE_MISMATCH', async () => {
      const res = makeRes({ oauth_state_github: 'other' });
      await expect(controller.callback('github', 'code', 'st-1', res)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('合法回调应登录 + 重定向带 token', async () => {
      const res = makeRes({ oauth_state_github: 'st-1' });
      await controller.callback('github', 'code', 'st-1', res);
      expect(oauthService.handleCallback).toHaveBeenCalledWith('github', 'code');
      expect(res.clearCookie).toHaveBeenCalledWith('oauth_state_github');
      expect(res.redirect).toHaveBeenCalledWith(302, expect.stringContaining('access_token=at'));
    });
  });
});
