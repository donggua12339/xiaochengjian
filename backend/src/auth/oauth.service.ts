import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import { PrismaService } from '../prisma/prisma.service';
import { AuthService } from './auth.service';
import type { AppConfig } from '../config/configuration';

/**
 * OAuth 服务(GitHub + QQ)
 *
 * 详见 ADR 0074(第三方 OAuth 集成)
 *
 * 流程:
 *  1. buildAuthorizeUrl(provider) - 构造授权 URL + state
 *  2. handleCallback(provider, code) - 用 code 换 access_token,拉用户信息,查找/创建 developer
 *
 * 前置条件:
 *  - GitHub OAuth App 注册 + .env 配 GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET
 *  - QQ 互联应用注册 + .env 配 QQ_APP_ID / QQ_APP_KEY
 *  - Prisma migration 加 githubId / qqOpenId 字段
 *
 * 当前状态:代码框架已就绪,待 OAuth app 配置后启用(proposed)
 */
@Injectable()
export class OAuthService {
  private readonly logger = new Logger(OAuthService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly authService: AuthService,
    private readonly configService: ConfigService<AppConfig, true>,
  ) {}

  /**
   * 构造 OAuth 授权 URL + state
   *
   * @param provider 'github' | 'qq'
   * @returns { redirectUrl, state }
   */
  async buildAuthorizeUrl(provider: 'github' | 'qq'): Promise<{
    redirectUrl: string;
    state: string;
  }> {
    const state = crypto.randomBytes(16).toString('hex');
    const callbackUrl = this.getCallbackUrl(provider);

    if (provider === 'github') {
      const clientId = this.configService.get('githubClientId', { infer: true }) as
        | string
        | undefined;
      if (!clientId) {
        throw new BadRequestException('GITHUB_OAUTH_NOT_CONFIGURED');
      }
      const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: callbackUrl,
        scope: 'read:user user:email',
        state,
      });
      return {
        redirectUrl: `https://github.com/login/oauth/authorize?${params}`,
        state,
      };
    }

    // QQ
    const appId = this.configService.get('qqAppId', { infer: true }) as string | undefined;
    if (!appId) {
      throw new BadRequestException('QQ_OAUTH_NOT_CONFIGURED');
    }
    const params = new URLSearchParams({
      client_id: appId,
      redirect_uri: callbackUrl,
      response_type: 'code',
      scope: 'get_user_info',
      state,
    });
    return {
      redirectUrl: `https://graph.qq.com/oauth2.0/authorize?${params}`,
      state,
    };
  }

  /**
   * 处理 OAuth 回调
   *
   * @param provider 'github' | 'qq'
   * @param code OAuth 授权码
   * @returns { accessToken, refreshToken, developerId }
   */
  async handleCallback(
    provider: 'github' | 'qq',
    code: string,
  ): Promise<{
    accessToken: string;
    refreshToken: string;
    developerId: string;
  }> {
    // 1. 用 code 换 access_token
    const oauthAccessToken = await this.exchangeCodeForToken(provider, code);

    // 2. 拉用户信息
    const userInfo = await this.fetchUserInfo(provider, oauthAccessToken);

    // 3. 查找/创建 developer
    const developer = await this.findOrCreateDeveloper(provider, userInfo);

    // 4. 签发 JWT(复用 AuthService 的 issueTokens 逻辑)
    // 注:issueTokens 是 private,需通过 AuthService 暴露一个内部方法,或复制逻辑
    // 这里走 AuthService 的"OAuth 登录"入口(待 AuthService 加方法)
    // TODO: AuthService 加 loginOAuth(developerId, email, role) -> TokenPair
    const tokens = await this.authService.issueTokensForOAuth(
      developer.id,
      developer.email,
      developer.role,
    );

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      developerId: developer.id,
    };
  }

  /**
   * 用 code 换 OAuth access_token
   */
  private async exchangeCodeForToken(
    provider: 'github' | 'qq',
    code: string,
  ): Promise<string> {
    // TODO: 实现实际 HTTP 请求(待 OAuth app 配置后)
    // GitHub: POST https://github.com/login/oauth/access_token
    //   body: { client_id, client_secret, code, redirect_uri }
    //   返回: { access_token, token_type, scope }
    // QQ: POST https://graph.qq.com/oauth2.0/token
    //   body: { grant_type=authorization_code, client_id, client_secret, code, redirect_uri }
    //   返回: access_token=xxx&expires_in=xxx

    throw new Error(
      `OAuth ${provider} token exchange not implemented yet (ADR 0074 proposed, ` +
        `待 OAuth app 配置 + AuthService.issueTokensForOAuth 方法实现)`,
    );
  }

  /**
   * 拉用户信息
   */
  private async fetchUserInfo(
    provider: 'github' | 'qq',
    oauthAccessToken: string,
  ): Promise<OAuthUserInfo> {
    // TODO: 实现实际 HTTP 请求(待 OAuth app 配置后)
    // GitHub: GET https://api.github.com/user + GET https://api.github.com/user/emails
    // QQ: GET https://graph.qq.com/oauth2.0/me(拿 openid) + GET https://graph.qq.com/user/get_user_info

    throw new Error(
      `OAuth ${provider} fetch user info not implemented yet (ADR 0074 proposed)`,
    );
  }

  /**
   * 查找/创建 developer
   *
   * 逻辑:
   *  - providerId 已存在 -> 返回现有 developer(登录)
   *  - providerId 不存在 + email 已注册 -> 绑定(关联 providerId)
   *  - providerId 不存在 + email 未注册 -> 创建新 developer(无密码)
   */
  private async findOrCreateDeveloper(
    provider: 'github' | 'qq',
    userInfo: OAuthUserInfo,
  ): Promise<{ id: string; email: string; role: string }> {
    const providerIdField = provider === 'github' ? 'githubId' : 'qqOpenId';
    const providerId = provider === 'github' ? userInfo.githubId : userInfo.qqOpenId;

    if (!providerId) {
      throw new UnauthorizedException('OAUTH_USER_INFO_MISSING_ID');
    }

    // 1. 按 providerId 查找
    const existing = await this.prisma.developer.findFirst({
      where: { [providerIdField]: providerId },
      select: { id: true, email: true, role: true },
    });
    if (existing) {
      return existing;
    }

    // 2. 按 email 查找(绑定流程)
    if (userInfo.email) {
      const byEmail = await this.prisma.developer.findUnique({
        where: { email: userInfo.email.toLowerCase() },
        select: { id: true, email: true, role: true },
      });
      if (byEmail) {
        // 绑定:更新 developer 的 providerId 字段
        await this.prisma.developer.update({
          where: { id: byEmail.id },
          data: { [providerIdField]: providerId },
        });
        return byEmail;
      }
    }

    // 3. 创建新 developer(无密码,只能 OAuth 登录)
    const email = userInfo.email ?? `${provider}-${providerId}@oauth.local`;
    const newDeveloper = await this.prisma.developer.create({
      data: {
        email: email.toLowerCase(),
        passwordHash: null, // OAuth 用户无密码
        [providerIdField]: providerId,
      },
      select: { id: true, email: true, role: true },
    });

    this.logger.log(`OAuth ${provider} 创建新 developer: ${newDeveloper.id}`);
    return newDeveloper;
  }

  /**
   * 获取回调 URL(从 ADMIN_WEB_URL 派生)
   */
  private getCallbackUrl(provider: 'github' | 'qq'): string {
    const baseUrl = process.env.ADMIN_WEB_URL ?? 'http://localhost:5173';
    // 后端 API 在 /v1 前缀下
    const apiBase = baseUrl.includes('localhost')
      ? 'http://localhost:3000'
      : baseUrl.replace(/\/$/, '');
    return `${apiBase}/v1/auth/oauth/${provider}/callback`;
  }
}

interface OAuthUserInfo {
  githubId?: string;
  qqOpenId?: string;
  email?: string;
  name?: string;
  avatarUrl?: string;
}
