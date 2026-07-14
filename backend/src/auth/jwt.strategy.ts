import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import type { AppConfig } from '../config/configuration';
import type { JwtPayload } from '../common/decorators/current-developer.decorator';

/**
 * JWT 策略
 * 从 Authorization: Bearer <token> 提取 access token
 * 验证签名,返回 payload
 *
 * 详见 ADR 0027 (JWT access 15min + refresh 7day)
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(configService: ConfigService<AppConfig, true>) {
    const secret = configService.get('jwtAccessSecret', { infer: true });

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: secret,
    });
  }

  async validate(payload: JwtPayload): Promise<JwtPayload> {
    if (!payload.sub || !payload.email) {
      throw new UnauthorizedException('INVALID_TOKEN');
    }
    return payload;
  }
}
