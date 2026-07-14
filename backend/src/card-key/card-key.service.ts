import { Injectable, NotFoundException, BadRequestException, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { v4 as uuidv4 } from 'uuid';
import { TenantPrismaService } from '../tenant/tenant-prisma.service';
import {
  generateCardKey,
  generateCardSalt,
  hashCardKey,
  extractCardKeyPrefix,
} from './card-key-generator';
import type { AppConfig } from '../config/configuration';
import { CardKeyType } from '@prisma/client';
import type { GenerateCardsDto, CreateCardTemplateDto } from './dto/card-key.dto';

/**
 * 卡密服务
 * 详见 ADR 0013 (卡密类型) / 0014 (卡密格式) / 0015 (设备绑定) / 0017 (离线验证)
 *
 * 卡密类型:
 *  - DAY:激活后 1 天失效
 *  - WEEK:7 天
 *  - MONTH:30 天
 *  - PERMANENT:永久
 *  - TRIAL:试用卡,设备级判重(一台设备只能领一次)
 *
 * 绑定策略:
 *  - NONE:不绑定
 *  - FIRST_BIND:首次激活绑定(一卡一机)
 *  - N_DEVICES:最多 N 台设备
 *
 * 存储:
 *  - 只存 SHA-256(cardKey + salt),不存明文
 *  - 明文仅生成时返回(一次性)
 */
@Injectable()
export class CardKeyService {
  private readonly logger = new Logger(CardKeyService.name);

  constructor(
    private readonly tenantPrisma: TenantPrismaService,
    private readonly configService: ConfigService<AppConfig, true>,
  ) {}

  /**
   * 批量生成卡密
   * 返回明文列表(一次性,服务端不保留)
   */
  async generate(
    developerId: string,
    appId: string,
    dto: GenerateCardsDto,
  ): Promise<{ batchId: string; cardKeys: string[]; count: number }> {
    const batchMax = this.configService.get('cardKeyBatchMax', { infer: true });
    if (dto.count > batchMax) {
      throw new BadRequestException(`COUNT_EXCEEDS_MAX(max=${batchMax})`);
    }

    // 校验应用存在且属于当前租户(RLS 自动隔离)
    const app = await this.tenantPrisma.tx(developerId, async (tx) => {
      return tx.application.findUnique({ where: { id: appId } });
    });
    if (!app) {
      throw new NotFoundException('APP_NOT_FOUND');
    }

    // 试用卡校验:maxDevices 必须为 1(设备级判重)
    if (dto.type === CardKeyType.TRIAL && dto.maxDevices && dto.maxDevices > 1) {
      throw new BadRequestException('TRIAL_CARD_MUST_BE_SINGLE_DEVICE');
    }

    const batchId = uuidv4();
    const maxDevices = dto.maxDevices ?? 1;
    const cardKeys: string[] = [];

    // 生成卡密数据
    const now = new Date();
    const data = Array.from({ length: dto.count }, () => {
      const cardKey = generateCardKey();
      const salt = generateCardSalt();
      const cardKeyHash = hashCardKey(cardKey, salt);
      const cardKeyPrefix = extractCardKeyPrefix(cardKey);
      cardKeys.push(cardKey);

      return {
        developerId,
        appId,
        cardKeyHash,
        cardSalt: salt,
        type: dto.type,
        bindingStrategy: dto.bindingStrategy,
        maxDevices,
        status: 'ACTIVE' as const,
        cardKeyPrefix,
        remark: dto.remark ?? null,
        batchId,
        expiresAt: this.computeExpiry(dto.type, now),
      };
    });

    // 批量插入(分批,每批 500,避免单次 INSERT 过大)
    const BATCH_SIZE = 500;
    for (let i = 0; i < data.length; i += BATCH_SIZE) {
      const batch = data.slice(i, i + BATCH_SIZE);
      await this.tenantPrisma.tx(developerId, async (tx) => {
        await tx.cardKey.createMany({ data: batch });
      });
    }

    this.logger.log(
      `开发者 ${developerId} 生成 ${dto.count} 张卡密,批次 ${batchId},类型 ${dto.type}`,
    );

    return { batchId, cardKeys, count: dto.count };
  }

  /**
   * 列出卡密(分页/筛选)
   */
  async list(
    developerId: string,
    appId: string,
    params: {
      page: number;
      pageSize: number;
      type?: CardKeyType;
      status?: string;
      batchId?: string;
    },
  ) {
    const { page, pageSize, type, status, batchId } = params;
    const skip = (page - 1) * pageSize;

    return this.tenantPrisma.tx(developerId, async (tx) => {
      const where = {
        appId,
        ...(type && { type }),
        ...(status && { status: status as never }),
        ...(batchId && { batchId }),
      };

      const [items, total] = await Promise.all([
        tx.cardKey.findMany({
          where,
          skip,
          take: pageSize,
          orderBy: { createdAt: 'desc' },
          include: {
            deviceBindings: { select: { deviceId: true } },
          },
        }),
        tx.cardKey.count({ where }),
      ]);

      return {
        items: items.map((c) => ({
          ...c,
          boundDevicesCount: c.deviceBindings.length,
          deviceBindings: undefined,
        })),
        total,
        page,
        pageSize,
        totalPages: Math.ceil(total / pageSize) || 1,
      };
    });
  }

  /**
   * 获取卡密详情(含绑定设备列表)
   */
  async getById(developerId: string, appId: string, cardId: string) {
    const card = await this.tenantPrisma.tx(developerId, async (tx) => {
      return tx.cardKey.findUnique({
        where: { id: cardId },
        include: {
          deviceBindings: {
            include: {
              device: {
                select: { id: true, machineId: true, lastSeenAt: true },
              },
            },
          },
        },
      });
    });

    if (!card || card.appId !== appId) {
      throw new NotFoundException('CARD_NOT_FOUND');
    }

    return {
      ...card,
      boundDevicesCount: card.deviceBindings.length,
    };
  }

  /**
   * 禁用卡密
   */
  async disable(developerId: string, appId: string, cardId: string) {
    return this.tenantPrisma.tx(developerId, async (tx) => {
      const card = await tx.cardKey.findFirst({
        where: { id: cardId, appId },
      });
      if (!card) {
        throw new NotFoundException('CARD_NOT_FOUND');
      }
      return tx.cardKey.update({
        where: { id: cardId },
        data: { status: 'DISABLED' },
      });
    });
  }

  /**
   * 启用卡密(从 DISABLED 恢复为 ACTIVE)
   */
  async enable(developerId: string, appId: string, cardId: string) {
    return this.tenantPrisma.tx(developerId, async (tx) => {
      const card = await tx.cardKey.findFirst({
        where: { id: cardId, appId },
      });
      if (!card) {
        throw new NotFoundException('CARD_NOT_FOUND');
      }
      if (card.status !== 'DISABLED') {
        throw new BadRequestException('CARD_NOT_DISABLED');
      }
      return tx.cardKey.update({
        where: { id: cardId },
        data: { status: 'ACTIVE' },
      });
    });
  }

  /**
   * 解绑设备(开发者后台操作,用于用户换机)
   * 解绑后卡密可在新设备重新激活
   */
  async unbindDevice(developerId: string, appId: string, cardId: string, deviceId: string) {
    return this.tenantPrisma.tx(developerId, async (tx) => {
      const binding = await tx.deviceBinding.findFirst({
        where: { cardKeyId: cardId, deviceId, appId },
      });
      if (!binding) {
        throw new NotFoundException('DEVICE_BINDING_NOT_FOUND');
      }
      await tx.deviceBinding.delete({ where: { id: binding.id } });
      return { success: true };
    });
  }

  /**
   * 导出卡密元信息 CSV
   *
   * 注意:
   *  - 卡密明文不存(ADR 0014),无法导出明文
   *  - 仅导出元信息:prefix/status/batch/type/remark/activatedAt/expiresAt/boundDevicesCount/createdAt
   *  - 单次导出上限 10000 行(防止内存爆炸),超出则 truncated=true
   *  - 超出时建议开发者按 batchId 分批导出
   */
  async export(
    developerId: string,
    appId: string,
    params: { type?: CardKeyType; status?: string; batchId?: string },
  ): Promise<{ csv: string; count: number; truncated: boolean }> {
    const MAX_EXPORT = 10000;
    const { type, status, batchId } = params;

    const items = await this.tenantPrisma.tx(developerId, async (tx) => {
      return tx.cardKey.findMany({
        where: {
          appId,
          ...(type && { type }),
          ...(status && { status: status as never }),
          ...(batchId && { batchId }),
        },
        take: MAX_EXPORT + 1,
        orderBy: { createdAt: 'desc' },
        include: {
          _count: { select: { deviceBindings: true } },
        },
      });
    });

    const truncated = items.length > MAX_EXPORT;
    const list = truncated ? items.slice(0, MAX_EXPORT) : items;

    const header =
      'id,cardKeyPrefix,type,bindingStrategy,maxDevices,status,batchId,remark,activatedAt,expiresAt,boundDevicesCount,createdAt\n';
    const rows = list
      .map((c) =>
        [
          c.id,
          c.cardKeyPrefix,
          c.type,
          c.bindingStrategy,
          c.maxDevices.toString(),
          c.status,
          c.batchId,
          c.remark ?? '',
          c.activatedAt?.toISOString() ?? '',
          c.expiresAt?.toISOString() ?? '',
          c._count.deviceBindings.toString(),
          c.createdAt.toISOString(),
        ]
          .map(this.escapeCsv)
          .join(','),
      )
      .join('\n');

    return {
      csv: header + rows + (rows ? '\n' : ''),
      count: list.length,
      truncated,
    };
  }

  /**
   * CSV 字段转义(RFC 4180)
   * 包含逗号、引号、换行符的字段用双引号包裹,内部双引号转义为两个双引号
   */
  private escapeCsv(value: string): string {
    if (/[",\r\n]/.test(value)) {
      return `"${value.replace(/"/g, '""')}"`;
    }
    return value;
  }

  // ============= 卡密模板 =============

  async createTemplate(developerId: string, appId: string, dto: CreateCardTemplateDto) {
    // 校验应用存在
    const app = await this.tenantPrisma.tx(developerId, async (tx) => {
      return tx.application.findUnique({ where: { id: appId } });
    });
    if (!app) {
      throw new NotFoundException('APP_NOT_FOUND');
    }

    return this.tenantPrisma.tx(developerId, async (tx) => {
      return tx.cardTemplate.create({
        data: {
          developerId,
          appId,
          name: dto.name,
          type: dto.type,
          bindingStrategy: dto.bindingStrategy,
          maxDevices: dto.maxDevices ?? 1,
          count: dto.count ?? 100,
        },
      });
    });
  }

  async listTemplates(developerId: string, appId: string) {
    return this.tenantPrisma.tx(developerId, async (tx) => {
      return tx.cardTemplate.findMany({
        where: { appId },
        orderBy: { createdAt: 'desc' },
      });
    });
  }

  async deleteTemplate(developerId: string, appId: string, templateId: string) {
    return this.tenantPrisma.tx(developerId, async (tx) => {
      const template = await tx.cardTemplate.findFirst({
        where: { id: templateId, appId },
      });
      if (!template) {
        throw new NotFoundException('TEMPLATE_NOT_FOUND');
      }
      await tx.cardTemplate.delete({ where: { id: templateId } });
      return { success: true };
    });
  }

  // ============= 工具方法 =============

  /**
   * 根据卡密类型计算过期时间(未激活时也预计算,激活时覆盖)
   * PERMANENT 和 TRIAL 返回 null
   */
  private computeExpiry(type: CardKeyType, now: Date): Date | null {
    switch (type) {
      case 'DAY':
        return new Date(now.getTime() + 1 * 24 * 60 * 60 * 1000);
      case 'WEEK':
        return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
      case 'MONTH':
        return new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
      case 'PERMANENT':
      case 'TRIAL':
        return null;
      default:
        return null;
    }
  }
}
