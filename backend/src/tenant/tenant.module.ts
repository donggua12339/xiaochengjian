import { Global, Module } from '@nestjs/common';
import { TenantPrismaService } from './tenant-prisma.service';
import { TenantInterceptor } from './tenant.interceptor';

@Global()
@Module({
  providers: [TenantPrismaService, TenantInterceptor],
  exports: [TenantPrismaService, TenantInterceptor],
})
export class TenantModule {}
