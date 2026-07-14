import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { PrismaModule } from './prisma/prisma.module';
import { RedisModule } from './redis/redis.module';
import { TenantModule } from './tenant/tenant.module';
import { TenantInterceptor } from './tenant/tenant.interceptor';
import { SecurityModule } from './security/security.module';
import { HealthModule } from './health/health.module';
import { AuthModule } from './auth/auth.module';
import { ApplicationModule } from './application/application.module';
import { CardKeyModule } from './card-key/card-key.module';
import { DeviceModule } from './device/device.module';
import { StatsModule } from './stats/stats.module';
import { CryptoModule } from './crypto/crypto.module';
import { SdkModule } from './sdk/sdk.module';
import { RateLimitModule } from './rate-limit/rate-limit.module';
import { AuditModule } from './audit/audit.module';
import { AuditInterceptor } from './audit/audit.interceptor';
import { MembershipModule } from './membership/membership.module';
import { InjectModule } from './inject/inject.module';
import { LoggingInterceptor } from './common/interceptors/logging.interceptor';
import { appConfig, validate } from './config/configuration';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [appConfig],
      validate,
    }),
    PrismaModule,
    RedisModule,
    TenantModule,
    SecurityModule,
    HealthModule,
    AuthModule,
    ApplicationModule,
    CardKeyModule,
    DeviceModule,
    StatsModule,
    CryptoModule,
    SdkModule,
    RateLimitModule,
    AuditModule,
    MembershipModule,
    InjectModule,
  ],
  providers: [
    {
      provide: APP_INTERCEPTOR,
      useClass: LoggingInterceptor,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: TenantInterceptor,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: AuditInterceptor,
    },
  ],
})
export class AppModule {}
