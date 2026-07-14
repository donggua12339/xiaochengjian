import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import type { PrismaClient } from '@prisma/client';

/**
 * 多租户 Prisma 服务
 * 详见 ADR 0018 (多租户隔离)
 *
 * 用法:
 *   const results = await this.tenantPrisma.tx(developerId, async (tx) => {
 *     return tx.application.findMany();
 *     // RLS 自动过滤,只返回 developerId = 当前租户 的行
 *   });
 *
 * 原理:
 *  - 在 Prisma 交互式事务内执行 SET LOCAL app.tenant_id = 'xxx'
 *  - SET LOCAL 只在事务内有效,事务结束后自动清除
 *  - PostgreSQL RLS 策略自动过滤:developer_id = current_setting('app.tenant_id')
 *  - 事务隔离:每个请求的 tenant_id 不会污染其他请求
 */
@Injectable()
export class TenantPrismaService {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * 在指定租户上下文中执行事务
   * @param tenantId 开发者 ID(租户 ID)
   * @param fn 业务函数,接收绑定了租户的 Prisma 事务 client
   */
  async tx<T>(
    tenantId: string,
    fn: (
      tx: Omit<
        PrismaClient,
        '$connect' | '$disconnect' | '$on' | '$transaction' | '$use' | '$extends'
      >,
    ) => Promise<T>,
  ): Promise<T> {
    return this.prisma.$transaction(async (tx) => {
      // 用 set_config 函数代替 SET LOCAL
      // set_config(name, value, is_local):is_local=true 等同 SET LOCAL(只当前事务有效)
      // 用函数是因为 SET 命令不支持参数化,set_config 支持
      await tx.$executeRaw`SELECT set_config('app.tenant_id', ${tenantId}, true)`;
      return fn(tx);
    });
  }

  /**
   * 系统级查询(不绑定租户,用于健康检查、migrate 等)
   */
  get raw(): PrismaService {
    return this.prisma;
  }
}
