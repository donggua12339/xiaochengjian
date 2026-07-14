import { Injectable, NotFoundException } from '@nestjs/common';
import { TenantPrismaService } from '../tenant/tenant-prisma.service';

/**
 * 统计服务
 * 详见 docs/architecture.md (统计模块)
 *
 * 聚合查询用 Prisma groupBy + 原生 SQL(日期截断)
 * 验证日志分区表 validation_log 按天聚合
 */
@Injectable()
export class StatsService {
  constructor(private readonly tenantPrisma: TenantPrismaService) {}

  /**
   * 应用概览
   * 卡密总数(按状态分组)、激活数、活跃设备数、今日验证数
   */
  async appOverview(developerId: string, appId: string) {
    const app = await this.tenantPrisma.tx(developerId, async (tx) => {
      return tx.application.findUnique({ where: { id: appId }, select: { id: true } });
    });
    if (!app) {
      throw new NotFoundException('APP_NOT_FOUND');
    }

    return this.tenantPrisma.tx(developerId, async (tx) => {
      // 卡密按状态分组
      const cardsByStatus = await tx.cardKey.groupBy({
        by: ['status'],
        where: { appId },
        _count: { id: true },
      });

      // 卡密按类型分组
      const cardsByType = await tx.cardKey.groupBy({
        by: ['type'],
        where: { appId },
        _count: { id: true },
      });

      // 已激活卡密数(activatedAt 非空)
      const activatedCount = await tx.cardKey.count({
        where: { appId, activatedAt: { not: null } },
      });

      // 活跃设备数(lastSeenAt 在 30 天内)
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const activeDeviceCount = await tx.device.count({
        where: { appId, lastSeenAt: { gte: thirtyDaysAgo } },
      });

      // 总设备数
      const totalDevices = await tx.device.count({ where: { appId } });

      // 今日验证数
      const todayStart = new Date();
      todayStart.setHours(0, 0, 0, 0);
      const todayValidations = await tx.validationLog.count({
        where: { appId, createdAt: { gte: todayStart } },
      });

      // 今日验证成功数
      const todaySuccessValidations = await tx.validationLog.count({
        where: { appId, createdAt: { gte: todayStart }, success: true },
      });

      return {
        cards: {
          total: cardsByStatus.reduce((s, g) => s + g._count.id, 0),
          byStatus: Object.fromEntries(cardsByStatus.map((g) => [g.status, g._count.id])),
          byType: Object.fromEntries(cardsByType.map((g) => [g.type, g._count.id])),
          activated: activatedCount,
        },
        devices: {
          total: totalDevices,
          active30d: activeDeviceCount,
        },
        validations: {
          today: todayValidations,
          todaySuccess: todaySuccessValidations,
          todayFailRate:
            todayValidations > 0
              ? Number(
                  (((todayValidations - todaySuccessValidations) / todayValidations) * 100).toFixed(
                    2,
                  ),
                )
              : 0,
        },
      };
    });
  }

  /**
   * 验证趋势(按天聚合,最近 N 天)
   * 用原生 SQL 做日期截断 + 聚合
   */
  async validationTrend(developerId: string, appId: string, days: number) {
    const app = await this.tenantPrisma.tx(developerId, async (tx) => {
      return tx.application.findUnique({ where: { id: appId }, select: { id: true } });
    });
    if (!app) {
      throw new NotFoundException('APP_NOT_FOUND');
    }

    return this.tenantPrisma.tx(developerId, async (tx) => {
      const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

      // 原生 SQL:按天聚合验证日志
      const rows = await tx.$queryRaw<
        Array<{ date: string; total: bigint; success: bigint; fail: bigint }>
      >`
        SELECT
          DATE("createdAt") AS date,
          COUNT(*)::bigint AS total,
          COUNT(*) FILTER (WHERE success = true)::bigint AS success,
          COUNT(*) FILTER (WHERE success = false)::bigint AS fail
        FROM "validation_log"
        WHERE "appId" = ${appId}
          AND "createdAt" >= ${startDate}
        GROUP BY DATE("createdAt")
        ORDER BY date
      `;

      return rows.map((r) => ({
        date: r.date,
        total: Number(r.total),
        success: Number(r.success),
        fail: Number(r.fail),
      }));
    });
  }

  /**
   * 激活趋势(按天聚合卡密激活数)
   */
  async activationTrend(developerId: string, appId: string, days: number) {
    const app = await this.tenantPrisma.tx(developerId, async (tx) => {
      return tx.application.findUnique({ where: { id: appId }, select: { id: true } });
    });
    if (!app) {
      throw new NotFoundException('APP_NOT_FOUND');
    }

    return this.tenantPrisma.tx(developerId, async (tx) => {
      const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

      const rows = await tx.$queryRaw<Array<{ date: string; count: bigint }>>`
        SELECT
          DATE("activatedAt") AS date,
          COUNT(*)::bigint AS count
        FROM "card_key"
        WHERE "appId" = ${appId}
          AND "activatedAt" IS NOT NULL
          AND "activatedAt" >= ${startDate}
        GROUP BY DATE("activatedAt")
        ORDER BY date
      `;

      return rows.map((r) => ({
        date: r.date,
        count: Number(r.count),
      }));
    });
  }

  /**
   * 开发者全局概览
   * 应用数、卡密数、设备数、最近 7 天验证数
   */
  async developerOverview(developerId: string) {
    return this.tenantPrisma.tx(developerId, async (tx) => {
      const [apps, cards, devices, templates] = await Promise.all([
        tx.application.count(),
        tx.cardKey.count(),
        tx.device.count(),
        tx.cardTemplate.count(),
      ]);

      // 最近 7 天验证数
      const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
      const recentValidations = await tx.validationLog.count({
        where: { createdAt: { gte: sevenDaysAgo } },
      });

      // 最近 7 天激活数
      const recentActivations = await tx.cardKey.count({
        where: { activatedAt: { gte: sevenDaysAgo } },
      });

      // 各应用的卡密数(前 10)
      const appsWithCounts = await tx.application.findMany({
        select: {
          id: true,
          name: true,
          packageName: true,
          _count: { select: { cardKeys: true, devices: true } },
        },
        orderBy: { createdAt: 'desc' },
        take: 10,
      });

      return {
        totals: {
          apps,
          cards,
          devices,
          templates,
        },
        recent7d: {
          validations: recentValidations,
          activations: recentActivations,
        },
        topApps: appsWithCounts.map((a) => ({
          id: a.id,
          name: a.name,
          packageName: a.packageName,
          cardsCount: a._count.cardKeys,
          devicesCount: a._count.devices,
        })),
      };
    });
  }
}
