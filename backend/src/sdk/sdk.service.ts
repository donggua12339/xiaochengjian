import {
  Injectable,
  NotFoundException,
  BadRequestException,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { TenantPrismaService } from '../tenant/tenant-prisma.service';
import { hashCardKey, validateCardKey } from '../card-key/card-key-generator';
import * as crypto from 'crypto';
import type { CardKey } from '@prisma/client';

/**
 * 租户事务客户端类型(由 TenantPrismaService.tx 传入)
 */
type TenantTx = Parameters<Parameters<TenantPrismaService['tx']>[1]>[0];

/**
 * SDK 服务
 * 详见 ADR 0013 (卡密类型) / 0015 (设备绑定) / 0017 (离线验证)
 *
 * 激活流程:
 *  1. 校验卡密格式(Luhn)
 *  2. 查找卡密(hash 匹配)
 *  3. 检查状态(ACTIVE)
 *  4. 试用卡:检查设备级判重
 *  5. 检查设备绑定(NONE/FIRST_BIND/N_DEVICES)
 *  6. 创建/更新 device 记录
 *  7. 创建 device_binding
 *  8. 更新卡密 activatedAt + expiresAt(首次激活时)
 *  9. 写入 validation_log(同事务,确保 RLS 上下文一致)
 *  10. 返回 cacheKey + 有效期
 *
 * 验证流程:
 *  1. 校验卡密格式
 *  2. 查找卡密
 *  3. 检查状态 + 过期 + 设备绑定(单次查询 device)
 *  4. 写入 validation_log
 *  5. 返回(刷新 cacheKey)
 */
@Injectable()
export class SdkService {
  private readonly logger = new Logger(SdkService.name);

  constructor(private readonly tenantPrisma: TenantPrismaService) {}

  /**
   * 激活卡密
   */
  async activate(params: {
    appId: string;
    developerId: string;
    cardKey: string;
    machineId: string;
    fingerprintHash: string;
    deviceInfo?: string;
    ip?: string;
    userAgent?: string;
  }): Promise<{
    success: true;
    cardType: string;
    expiresAt: Date | null;
    cacheKey: string;
    offlineCacheDays: number;
  }> {
    const { appId, developerId, cardKey, machineId, fingerprintHash, ip, userAgent } = params;

    // 1. 校验卡密格式(此时尚未进入事务,日志单独走一个事务)
    if (!validateCardKey(cardKey)) {
      await this.writeValidationLogStandalone(
        developerId,
        appId,
        cardKey,
        machineId,
        ip,
        userAgent,
        false,
        'INVALID_FORMAT',
      );
      throw new BadRequestException('INVALID_CARD_KEY_FORMAT');
    }

    // 2. 查找卡密(用 cardKeyPrefix 索引,逐一验证 hash)
    const prefix = cardKey.replace(/-/g, '').substring(0, 4).toUpperCase();

    return this.tenantPrisma.tx(developerId, async (tx) => {
      const candidates = await tx.cardKey.findMany({
        where: { appId, cardKeyPrefix: prefix },
      });

      let matchedCard: CardKey | null = null;
      for (const c of candidates) {
        const hash = hashCardKey(cardKey, c.cardSalt);
        if (hash === c.cardKeyHash) {
          matchedCard = c;
          break;
        }
      }

      if (!matchedCard) {
        await this.writeValidationLog(
          tx,
          appId,
          developerId,
          cardKey,
          machineId,
          ip,
          userAgent,
          false,
          'CARD_NOT_FOUND',
        );
        throw new NotFoundException('CARD_NOT_FOUND');
      }

      // 3. 检查状态
      if (matchedCard.status === 'DISABLED') {
        await this.writeValidationLog(
          tx,
          appId,
          developerId,
          cardKey,
          machineId,
          ip,
          userAgent,
          false,
          'CARD_DISABLED',
        );
        throw new UnauthorizedException('CARD_DISABLED');
      }

      // 4. 试用卡设备级判重
      if (matchedCard.type === 'TRIAL' && matchedCard.trialClaimedDeviceId) {
        if (matchedCard.trialClaimedDeviceId !== machineId) {
          await this.writeValidationLog(
            tx,
            appId,
            developerId,
            cardKey,
            machineId,
            ip,
            userAgent,
            false,
            'TRIAL_ALREADY_CLAIMED',
          );
          throw new BadRequestException('TRIAL_ALREADY_CLAIMED_BY_OTHER_DEVICE');
        }
      }

      // 5. 查找或创建设备(upsert 保证返回非 null)
      const device = await tx.device.upsert({
        where: { appId_machineId: { appId, machineId } },
        update: { lastSeenAt: new Date(), fingerprintHash },
        create: { developerId, appId, machineId, fingerprintHash },
      });

      // 6. 检查设备绑定
      const existingBindings = await tx.deviceBinding.findMany({
        where: { cardKeyId: matchedCard.id },
      });

      if (matchedCard.bindingStrategy !== 'NONE') {
        const isAlreadyBound = existingBindings.some((b) => b.deviceId === device.id);
        if (!isAlreadyBound) {
          if (matchedCard.bindingStrategy === 'FIRST_BIND') {
            if (existingBindings.length > 0) {
              await this.writeValidationLog(
                tx,
                appId,
                developerId,
                cardKey,
                machineId,
                ip,
                userAgent,
                false,
                'ALREADY_BOUND_OTHER_DEVICE',
              );
              throw new BadRequestException('CARD_ALREADY_BOUND_TO_OTHER_DEVICE');
            }
          } else if (matchedCard.bindingStrategy === 'N_DEVICES') {
            if (existingBindings.length >= matchedCard.maxDevices) {
              await this.writeValidationLog(
                tx,
                appId,
                developerId,
                cardKey,
                machineId,
                ip,
                userAgent,
                false,
                'MAX_DEVICES_REACHED',
              );
              throw new BadRequestException('MAX_DEVICES_REACHED');
            }
          }
        }
      }

      // 7. 创建绑定(如果尚未绑定)
      const isAlreadyBound = existingBindings.some((b) => b.deviceId === device.id);
      if (!isAlreadyBound) {
        await tx.deviceBinding.create({
          data: {
            developerId,
            cardKeyId: matchedCard.id,
            deviceId: device.id,
            appId,
          },
        });
      }

      // 8. 更新卡密(首次激活)
      let expiresAt = matchedCard.expiresAt;
      if (!matchedCard.activatedAt) {
        const now = new Date();
        expiresAt = this.computeExpiry(matchedCard.type, now);
        await tx.cardKey.update({
          where: { id: matchedCard.id },
          data: {
            activatedAt: now,
            expiresAt,
            ...(matchedCard.type === 'TRIAL' && { trialClaimedDeviceId: machineId }),
          },
        });
      }

      // 9. 写入验证日志(同事务,RLS 上下文一致)
      await this.writeValidationLog(
        tx,
        appId,
        developerId,
        cardKey,
        machineId,
        ip,
        userAgent,
        true,
        null,
      );

      // 10. 生成 cacheKey
      const cacheKey = crypto.randomBytes(32).toString('hex');

      this.logger.log(
        `卡密激活成功: appId=${appId}, cardPrefix=${prefix}, machineId=${machineId.substring(0, 8)}...`,
      );

      // 获取应用的离线缓存天数
      const app = await tx.application.findUnique({
        where: { id: appId },
        select: { offlineCacheDays: true },
      });

      return {
        success: true,
        cardType: matchedCard.type,
        expiresAt,
        cacheKey,
        offlineCacheDays: app?.offlineCacheDays ?? 7,
      };
    });
  }

  /**
   * 验证卡密(刷新 cacheKey)
   */
  async validate(params: {
    appId: string;
    developerId: string;
    cardKey: string;
    machineId: string;
    ip?: string;
    userAgent?: string;
  }): Promise<{
    success: true;
    valid: boolean;
    reason?: string;
    expiresAt: Date | null;
    cacheKey: string;
    offlineCacheDays: number;
  }> {
    const { appId, developerId, cardKey, machineId, ip, userAgent } = params;

    if (!validateCardKey(cardKey)) {
      await this.writeValidationLogStandalone(
        developerId,
        appId,
        cardKey,
        machineId,
        ip,
        userAgent,
        false,
        'INVALID_FORMAT',
      );
      throw new BadRequestException('INVALID_CARD_KEY_FORMAT');
    }

    const prefix = cardKey.replace(/-/g, '').substring(0, 4).toUpperCase();

    return this.tenantPrisma.tx(developerId, async (tx) => {
      const candidates = await tx.cardKey.findMany({
        where: { appId, cardKeyPrefix: prefix },
      });

      let matchedCard: CardKey | null = null;
      for (const c of candidates) {
        const hash = hashCardKey(cardKey, c.cardSalt);
        if (hash === c.cardKeyHash) {
          matchedCard = c;
          break;
        }
      }

      if (!matchedCard) {
        await this.writeValidationLog(
          tx,
          appId,
          developerId,
          cardKey,
          machineId,
          ip,
          userAgent,
          false,
          'CARD_NOT_FOUND',
        );
        throw new NotFoundException('CARD_NOT_FOUND');
      }

      // 检查状态 + 过期
      let valid = true;
      let reason: string | null = null;

      if (matchedCard.status === 'DISABLED') {
        valid = false;
        reason = 'CARD_DISABLED';
      } else if (matchedCard.expiresAt && matchedCard.expiresAt < new Date()) {
        valid = false;
        reason = 'CARD_EXPIRED';
      }

      // 设备绑定校验 + lastSeenAt 更新(单次查询 device,避免重复)
      // 仅在状态/过期检查通过时才进行设备校验,减少无谓查询
      let device: Awaited<ReturnType<typeof tx.device.findUnique>> = null;
      if (valid && matchedCard.bindingStrategy !== 'NONE') {
        device = await tx.device.findUnique({
          where: { appId_machineId: { appId, machineId } },
        });
        if (device) {
          const binding = await tx.deviceBinding.findUnique({
            where: {
              cardKeyId_deviceId: { cardKeyId: matchedCard.id, deviceId: device.id },
            },
          });
          if (!binding) {
            valid = false;
            reason = 'DEVICE_NOT_BOUND';
          }
        } else if (matchedCard.activatedAt) {
          // 设备未激活过,但卡密已激活过(说明在别的设备激活)
          valid = false;
          reason = 'DEVICE_NOT_BOUND';
        }
      }

      // 更新设备 lastSeenAt(复用上面的 device 查询结果,避免重复)
      if (valid) {
        if (device) {
          await tx.device.update({
            where: { id: device.id },
            data: { lastSeenAt: new Date() },
          });
        } else if (matchedCard.bindingStrategy === 'NONE') {
          // 无绑定策略且设备不存在:补建一条设备记录(保持 lastSeenAt 准确)
          await tx.device.upsert({
            where: { appId_machineId: { appId, machineId } },
            update: { lastSeenAt: new Date() },
            create: { developerId, appId, machineId, fingerprintHash: '' },
          });
        }
      }

      await this.writeValidationLog(
        tx,
        appId,
        developerId,
        cardKey,
        machineId,
        ip,
        userAgent,
        valid,
        reason,
      );

      const cacheKey = crypto.randomBytes(32).toString('hex');
      const app = await tx.application.findUnique({
        where: { id: appId },
        select: { offlineCacheDays: true },
      });

      return {
        success: true,
        valid,
        ...(reason ? { reason } : {}),
        expiresAt: matchedCard.expiresAt,
        cacheKey,
        offlineCacheDays: app?.offlineCacheDays ?? 7,
      };
    });
  }

  /**
   * 写入验证日志(在租户事务内调用,确保 RLS 上下文一致)
   * @param tx 租户事务客户端(由 tenantPrisma.tx 传入)
   */
  private async writeValidationLog(
    tx: TenantTx,
    appId: string,
    developerId: string,
    cardKey: string,
    machineId: string,
    ip: string | undefined,
    userAgent: string | undefined,
    success: boolean,
    failReason: string | null,
  ): Promise<void> {
    try {
      await tx.validationLog.create({
        data: {
          developerId,
          appId,
          // 日志哈希用固定 salt,便于按卡密聚合分析(不泄露明文卡密)
          cardKeyHash: hashCardKey(cardKey, 'log'),
          machineId,
          ip: ip ?? 'unknown',
          userAgent,
          success,
          failReason,
        },
      });
    } catch (e) {
      // 日志写入失败不影响主流程,但记录错误便于排查
      this.logger.error(`写入验证日志失败: ${(e as Error).message}`);
    }
  }

  /**
   * 写入验证日志(独立事务,用于 tx 外的早期错误,如卡密格式错误)
   * 单独开 tx 是为了保证 RLS 上下文一致(app.tenant_id 必须设置)
   */
  private async writeValidationLogStandalone(
    developerId: string,
    appId: string,
    cardKey: string,
    machineId: string,
    ip: string | undefined,
    userAgent: string | undefined,
    success: boolean,
    failReason: string | null,
  ): Promise<void> {
    try {
      await this.tenantPrisma.tx(developerId, async (tx) => {
        await tx.validationLog.create({
          data: {
            developerId,
            appId,
            cardKeyHash: hashCardKey(cardKey, 'log'),
            machineId,
            ip: ip ?? 'unknown',
            userAgent,
            success,
            failReason,
          },
        });
      });
    } catch (e) {
      this.logger.error(`写入验证日志(standalone)失败: ${(e as Error).message}`);
    }
  }

  /**
   * 根据卡密类型计算过期时间(激活时)
   */
  private computeExpiry(type: string, now: Date): Date | null {
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
