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
 * 限流配置装饰器
 * 用法:
 *   @RateLimit({ ip: 60, window: 60 })
 *   @UseGuards(RateLimitGuard)
 */
export const RATE_LIMIT_KEY = 'rateLimit';
export const RateLimit = (options: { ip?: number; window?: number }) =>
  SetMetadata(RATE_LIMIT_KEY, options);

/**
 * 限流守卫
 * 基于 IP 限流(业务层可自行调 checkDeviceRateLimit 做设备限流)
 */
@Injectable()
export class RateLimitGuard implements CanActivate {
  constructor(
    private readonly rateLimitService: RateLimitService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const options = this.reflector.get<{ ip?: number; window?: number }>(
      RATE_LIMIT_KEY,
      context.getHandler(),
    );
    if (!options) {
      return true; // 未配置限流,放行
    }

    const request = context.switchToHttp().getRequest<Request>();
    const ip =
      (request.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      request.socket.remoteAddress ||
      'unknown';

    const limit = options.ip ?? 60;
    const window = options.window ?? 60;

    const { allowed, remaining, retryAfter } = await this.rateLimitService.checkIpRateLimit(
      ip,
      limit,
      window,
    );

    if (!allowed) {
      throw new HttpException(
        {
          code: 'TOO_MANY_REQUESTS',
          message: `RATE_LIMIT_EXCEEDED(retryAfter=${retryAfter}s)`,
          retryAfter,
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    // 挂载剩余次数到 response header(供客户端参考)
    const response = context.switchToHttp().getResponse();
    response.setHeader('X-RateLimit-Limit', limit);
    response.setHeader('X-RateLimit-Remaining', remaining);

    return true;
  }
}
