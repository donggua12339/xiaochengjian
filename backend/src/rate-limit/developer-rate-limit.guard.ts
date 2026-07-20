import {
  CanActivate,
  ExecutionContext,
  Injectable,
  HttpException,
  HttpStatus,
  SetMetadata,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import { RateLimitService } from './rate-limit.service';

/**
 * 开发者级限流装饰器
 * 用法:
 *   @DeveloperRateLimit({ limit: 100, window: 60 })
 *   @UseGuards(DeveloperRateLimitGuard)
 */
export const DEVELOPER_RATE_LIMIT_KEY = 'developerRateLimit';
export const DeveloperRateLimit = (options: { limit?: number; window?: number }) =>
  SetMetadata(DEVELOPER_RATE_LIMIT_KEY, options);

/**
 * 开发者级限流守卫(ADR 0022 扩展)
 * 基于 JWT payload 的 developerId 限流
 */
@Injectable()
export class DeveloperRateLimitGuard implements CanActivate {
  constructor(
    private readonly rateLimitService: RateLimitService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const options = this.reflector.get<{ limit?: number; window?: number }>(
      DEVELOPER_RATE_LIMIT_KEY,
      context.getHandler(),
    );
    if (!options) {
      return true; // 未配置限流,放行
    }

    const request = context.switchToHttp().getRequest<Request>();
    // 从 JWT payload 提取 developerId(需先经过 JwtAuthGuard)
    const developerId = (request as any).user?.sub;
    if (!developerId) {
      // 未认证,放行(由 JwtAuthGuard 处理)
      return true;
    }

    const limit = options.limit ?? 100;
    const window = options.window ?? 60;

    const { allowed, remaining, retryAfter } =
      await this.rateLimitService.checkDeveloperRateLimit(developerId, limit, window);

    if (!allowed) {
      throw new HttpException(
        {
          code: 'TOO_MANY_REQUESTS',
          message: `DEVELOPER_RATE_LIMIT_EXCEEDED(retryAfter=${retryAfter}s)`,
          retryAfter,
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    // 挂载剩余次数到 response header
    const response = context.switchToHttp().getResponse();
    response.setHeader('X-RateLimit-Limit', limit);
    response.setHeader('X-RateLimit-Remaining', remaining);

    return true;
  }
}
