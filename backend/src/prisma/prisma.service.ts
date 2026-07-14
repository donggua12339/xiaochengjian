import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

/**
 * Prisma 服务
 * 详见 ADR 0006 (PostgreSQL) 与 ADR 0018 (多租户)
 *
 * 多租户隔离通过 PostgreSQL RLS 实现,M1.3 通过 SQL migration 配置。
 * NestJS 侧通过 TenantMiddleware 设置 `SET LOCAL app.tenant_id`。
 *
 * 注意:不在 onModuleInit 调用 $connect(),Prisma 客户端是惰性连接的,
 * 首次查询时自动连接。这样 NestJS 启动不依赖 DB 可用,
 * 健康检查 controller 调 $queryRaw 时才真正连 DB。
 */
@Injectable()
export class PrismaService extends PrismaClient implements OnModuleDestroy {
  private readonly logger = new Logger(PrismaService.name);

  async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
    this.logger.log('数据库连接已关闭');
  }
}
