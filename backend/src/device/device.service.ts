import { Injectable, NotFoundException } from '@nestjs/common';
import { TenantPrismaService } from '../tenant/tenant-prisma.service';

/**
 * 设备服务
 * 详见 ADR 0015 (设备绑定) 与 ADR 0016 (机器码)
 *
 * 设备记录由 SDK 激活时创建(M1.8),M1.6 只做查询和解绑
 * 一台物理设备在不同应用算不同记录(@@unique([appId, machineId]))
 *
 * 解绑设备 = 删除该设备的所有 deviceBinding 记录
 * 解绑后,卡密可在新设备重新激活
 */
@Injectable()
export class DeviceService {
  constructor(private readonly tenantPrisma: TenantPrismaService) {}

  /**
   * 列出设备(分页)
   */
  async list(developerId: string, appId: string, params: { page: number; pageSize: number }) {
    const { page, pageSize } = params;
    const skip = (page - 1) * pageSize;

    return this.tenantPrisma.tx(developerId, async (tx) => {
      const where = { appId };
      const [items, total] = await Promise.all([
        tx.device.findMany({
          where,
          skip,
          take: pageSize,
          orderBy: { lastSeenAt: 'desc' },
          include: {
            deviceBindings: {
              select: {
                id: true,
                cardKeyId: true,
                boundAt: true,
              },
            },
          },
        }),
        tx.device.count({ where }),
      ]);

      return {
        items: items.map((d) => ({
          ...d,
          boundCardsCount: d.deviceBindings.length,
        })),
        total,
        page,
        pageSize,
        totalPages: Math.ceil(total / pageSize) || 1,
      };
    });
  }

  /**
   * 获取设备详情(含绑定的卡密)
   */
  async getById(developerId: string, appId: string, deviceId: string) {
    const device = await this.tenantPrisma.tx(developerId, async (tx) => {
      return tx.device.findFirst({
        where: { id: deviceId, appId },
        include: {
          deviceBindings: {
            include: {
              cardKey: {
                select: {
                  id: true,
                  type: true,
                  status: true,
                  cardKeyPrefix: true,
                  bindingStrategy: true,
                  maxDevices: true,
                },
              },
            },
            orderBy: { boundAt: 'desc' },
          },
        },
      });
    });

    if (!device) {
      throw new NotFoundException('DEVICE_NOT_FOUND');
    }

    return device;
  }

  /**
   * 解绑设备(删除该设备的所有卡密绑定)
   * 用于用户换机场景:开发者后台解绑后,卡密可在新设备重新激活
   */
  async unbindAll(developerId: string, appId: string, deviceId: string) {
    return this.tenantPrisma.tx(developerId, async (tx) => {
      const device = await tx.device.findFirst({
        where: { id: deviceId, appId },
      });
      if (!device) {
        throw new NotFoundException('DEVICE_NOT_FOUND');
      }

      const result = await tx.deviceBinding.deleteMany({
        where: { deviceId },
      });

      return {
        success: true,
        unboundCount: result.count,
      };
    });
  }
}
