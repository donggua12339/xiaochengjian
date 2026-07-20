import { Global, Module } from '@nestjs/common';
import { RateLimitService } from './rate-limit.service';
import { RateLimitGuard } from './rate-limit.guard';
import { DeveloperRateLimitGuard } from './developer-rate-limit.guard';

@Global()
@Module({
  providers: [RateLimitService, RateLimitGuard, DeveloperRateLimitGuard],
  exports: [RateLimitService, RateLimitGuard, DeveloperRateLimitGuard],
})
export class RateLimitModule {}
