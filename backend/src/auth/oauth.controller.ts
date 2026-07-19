import { Controller, Get, Param, Query, Res, BadRequestException, Logger } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Response } from 'express';
import { OAuthService } from './oauth.service';

/**
 * OAuth 控制器(GitHub + QQ)
 *
 * 详见 ADR 0074(第三方 OAuth 集成)
 *
 * 路由:
 *  - GET /auth/oauth/:provider          - 重定向到 OAuth provider 授权页
 *  - GET /auth/oauth/:provider/callback - 处理 OAuth 回调,登录或创建 developer
 *
 * 前置条件(详见 ADR 0074):
 *  - GitHub OAuth App 注册 + .env 配 GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET
 *  - QQ 互联应用注册 + .env 配 QQ_APP_ID / QQ_APP_KEY
 *  - Prisma migration 加 githubId / qqOpenId 字段
 *
 * 当前状态:代码框架已就绪,待 OAuth app 配置后启用(proposed)
 */
@ApiTags('认证-OAuth')
@Controller('auth/oauth')
export class OAuthController {
  private readonly logger = new Logger(OAuthController.name);

  constructor(private readonly oauthService: OAuthService) {}

  /**
   * 重定向到 OAuth provider 授权页
   *
   * @param provider 'github' | 'qq'
   * @param res Express Response(用于 302 重定向)
   */
  @Get(':provider')
  @ApiOperation({ summary: '重定向到 OAuth provider(GitHub/QQ)授权页' })
  async authorize(@Param('provider') provider: string, @Res() res: Response) {
    if (provider !== 'github' && provider !== 'qq') {
      throw new BadRequestException('UNSUPPORTED_PROVIDER');
    }

    const { redirectUrl, state } = await this.oauthService.buildAuthorizeUrl(provider);
    // state 存 cookie(HttpOnly,5 分钟),回调时校验防 CSRF
    res.cookie(`oauth_state_${provider}`, state, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 5 * 60 * 1000,
    });
    return res.redirect(302, redirectUrl);
  }

  /**
   * 处理 OAuth provider 回调
   *
   * @param provider 'github' | 'qq'
   * @param code OAuth 授权码
   * @param state CSRF 防护 state(与 cookie 中比对)
   * @param res Express Response
   */
  @Get(':provider/callback')
  @ApiOperation({ summary: 'OAuth 回调(登录或创建 developer,重定向到前端带 token)' })
  async callback(
    @Param('provider') provider: string,
    @Query('code') code: string,
    @Query('state') state: string,
    @Res() res: Response,
  ) {
    if (provider !== 'github' && provider !== 'qq') {
      throw new BadRequestException('UNSUPPORTED_PROVIDER');
    }

    if (!code) {
      throw new BadRequestException('MISSING_CODE');
    }

    // 校验 state(CSRF 防护)
    const cookieState = res.req.cookies?.[`oauth_state_${provider}`];
    if (!state || !cookieState || state !== cookieState) {
      throw new BadRequestException('OAUTH_STATE_MISMATCH');
    }
    res.clearCookie(`oauth_state_${provider}`);

    const result = await this.oauthService.handleCallback(provider, code);

    // 重定向到前端,带 token(前端拿到后存 localStorage,跳转 dashboard)
    const frontendUrl = process.env.ADMIN_WEB_URL ?? 'http://localhost:5173';
    const redirect = `${frontendUrl}/oauth/callback?access_token=${encodeURIComponent(
      result.accessToken,
    )}&refresh_token=${encodeURIComponent(result.refreshToken)}`;

    this.logger.log(`OAuth ${provider} 登录成功: developerId=${result.developerId}`);
    return res.redirect(302, redirect);
  }
}
