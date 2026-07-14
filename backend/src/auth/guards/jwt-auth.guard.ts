import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * JWT 认证守卫
 * 验证 Authorization: Bearer <access_token>
 * 失败返回 401 Unauthorized
 *
 * 用法:
 *   @UseGuards(JwtAuthGuard)
 *   @Get('profile')
 *   getProfile(@CurrentDeveloper() developerId: string) { ... }
 */
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
