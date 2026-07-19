import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { OAuthController } from './oauth.controller';
import { OAuthService } from './oauth.service';
import { TotpService } from './totp.service';
import { JwtStrategy } from './jwt.strategy';
import { PrismaModule } from '../prisma/prisma.module';
import { RedisModule } from '../redis/redis.module';
import type { AppConfig } from '../config/configuration';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService<AppConfig, true>],
      useFactory: (config: ConfigService<AppConfig, true>) => ({
        secret: config.get('jwtAccessSecret', { infer: true }),
        signOptions: {
          expiresIn: config.get('jwtAccessExpiresIn', { infer: true }),
        },
      }),
    }),
    PrismaModule,
    RedisModule,
  ],
  controllers: [AuthController, OAuthController],
  providers: [AuthService, OAuthService, TotpService, JwtStrategy],
  exports: [AuthService, JwtModule],
})
export class AuthModule {}
