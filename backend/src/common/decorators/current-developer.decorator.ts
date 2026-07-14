import { ExecutionContext, createParamDecorator } from '@nestjs/common';
import type { Request } from 'express';

/**
 * JWT Payload 类型
 */
export interface JwtPayload {
  sub: string; // developerId
  email: string;
  role: string;
  iat?: number;
  exp?: number;
}

/**
 * 扩展 Request 类型,附带已认证的开发者
 */
export interface AuthenticatedRequest extends Request {
  user?: JwtPayload;
}

/**
 * 从请求中提取当前已认证开发者 ID
 *
 * 用法:
 *   @Get('profile')
 *   @UseGuards(JwtAuthGuard)
 *   getProfile(@CurrentDeveloper() developerId: string) { ... }
 */
export const CurrentDeveloper = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): string | undefined => {
    const request = ctx.switchToHttp().getRequest<AuthenticatedRequest>();
    return request.user?.sub;
  },
);
