import {
  Injectable,
  ConflictException,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import * as argon2 from 'argon2';
import * as crypto from 'crypto';
import { PrismaService } from '../prisma/prisma.service';
import { TenantPrismaService } from '../tenant/tenant-prisma.service';
import { CreateAppDto, UpdateAppDto } from './dto/app.dto';

/**
 * 应用服务
 * 详见 ADR 0018 (多租户) 与 docs/architecture.md
 *
 * 所有查询通过 TenantPrismaService.tx(developerId, ...) 执行
 * RLS 自动隔离:开发者只能操作自己的应用
 *
 * appSecret:
 *  - 生成:32 字符随机字符串
 *  - 存储:argon2 哈希(不可逆)
 *  - 返回:仅创建/重置时返回明文(一次性)
 *  - 前缀:存前 4 位,便于后台识别
 */
@Injectable()
export class ApplicationService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly tenantPrisma: TenantPrismaService,
  ) {}

  /**
   * 创建应用
   * 检查 maxApps 限制 + 包名唯一性
   * 返回明文 appSecret(仅此一次)
   */
  async create(
    developerId: string,
    dto: CreateAppDto,
  ): Promise<{
    id: string;
    name: string;
    packageName: string;
    appSecret: string;
    appSecretPrefix: string;
    offlineCacheDays: number;
    createdAt: Date;
    updatedAt: Date;
  }> {
    // 检查 maxApps 限制(用原始 prisma,因为 developer 表无 RLS)
    const developer = await this.prisma.developer.findUnique({
      where: { id: developerId },
      select: { id: true, maxApps: true },
    });
    if (!developer) {
      throw new NotFoundException('DEVELOPER_NOT_FOUND');
    }

    const existingCount = await this.tenantPrisma.tx(developerId, async (tx) => {
      return tx.application.count();
    });

    if (existingCount >= developer.maxApps) {
      throw new ForbiddenException(`APP_LIMIT_REACHED(max=${developer.maxApps})`);
    }

    // 生成 appSecret
    const appSecret = this.generateAppSecret();
    const appSecretHash = await argon2.hash(appSecret, {
      type: argon2.argon2id,
      memoryCost: 19456,
      timeCost: 2,
      parallelism: 1,
    });
    const appSecretPrefix = appSecret.substring(0, 4);

    // 创建应用(RLS 自动绑定 developerId)
    const app = await this.tenantPrisma.tx(developerId, async (tx) => {
      // 先检查包名唯一性(RLS 范围内)
      const existing = await tx.application.findUnique({
        where: { developerId_packageName: { developerId, packageName: dto.packageName } },
        select: { id: true },
      });
      if (existing) {
        throw new ConflictException('PACKAGE_NAME_ALREADY_USED');
      }

      return tx.application.create({
        data: {
          developerId,
          name: dto.name,
          packageName: dto.packageName,
          appSecretHash,
        },
        select: {
          id: true,
          name: true,
          packageName: true,
          offlineCacheDays: true,
          createdAt: true,
          updatedAt: true,
        },
      });
    });

    return {
      ...app,
      appSecret,
      appSecretPrefix,
    };
  }

  /**
   * 列出当前开发者的所有应用
   */
  async list(developerId: string) {
    return this.tenantPrisma.tx(developerId, async (tx) => {
      const apps = await tx.application.findMany({
        orderBy: { createdAt: 'desc' },
      });
      return apps.map((app) => this.toResponse(app));
    });
  }

  /**
   * 获取应用详情
   */
  async getById(developerId: string, appId: string) {
    const app = await this.tenantPrisma.tx(developerId, async (tx) => {
      return tx.application.findUnique({ where: { id: appId } });
    });

    if (!app) {
      throw new NotFoundException('APP_NOT_FOUND');
    }

    return this.toResponse(app);
  }

  /**
   * 更新应用
   */
  async update(developerId: string, appId: string, dto: UpdateAppDto) {
    const app = await this.tenantPrisma.tx(developerId, async (tx) => {
      const existing = await tx.application.findUnique({ where: { id: appId } });
      if (!existing) {
        throw new NotFoundException('APP_NOT_FOUND');
      }

      return tx.application.update({
        where: { id: appId },
        data: {
          ...(dto.name !== undefined && { name: dto.name }),
          ...(dto.signHashAllowList !== undefined && {
            signHashAllowList: dto.signHashAllowList,
          }),
          ...(dto.rateLimitIpPerMinute !== undefined && {
            rateLimitIpPerMinute: dto.rateLimitIpPerMinute,
          }),
          ...(dto.rateLimitDevicePerMinute !== undefined && {
            rateLimitDevicePerMinute: dto.rateLimitDevicePerMinute,
          }),
          ...(dto.rateLimitFailLockThreshold !== undefined && {
            rateLimitFailLockThreshold: dto.rateLimitFailLockThreshold,
          }),
          ...(dto.rateLimitFailLockTtl !== undefined && {
            rateLimitFailLockTtl: dto.rateLimitFailLockTtl,
          }),
          ...(dto.offlineCacheDays !== undefined && {
            offlineCacheDays: dto.offlineCacheDays,
          }),
          ...(dto.sdkRsaPublicKeyHash !== undefined && {
            sdkRsaPublicKeyHash: dto.sdkRsaPublicKeyHash,
          }),
        },
      });
    });

    return this.toResponse(app);
  }

  /**
   * 删除应用(级联删除卡密/设备等)
   */
  async delete(developerId: string, appId: string): Promise<void> {
    await this.tenantPrisma.tx(developerId, async (tx) => {
      const existing = await tx.application.findUnique({ where: { id: appId } });
      if (!existing) {
        throw new NotFoundException('APP_NOT_FOUND');
      }
      await tx.application.delete({ where: { id: appId } });
    });
  }

  /**
   * 重置 appSecret
   * 返回新明文(仅此一次)
   */
  async rotateSecret(
    developerId: string,
    appId: string,
  ): Promise<{
    appSecret: string;
    appSecretPrefix: string;
  }> {
    const appSecret = this.generateAppSecret();
    const appSecretHash = await argon2.hash(appSecret, {
      type: argon2.argon2id,
      memoryCost: 19456,
      timeCost: 2,
      parallelism: 1,
    });
    const appSecretPrefix = appSecret.substring(0, 4);

    await this.tenantPrisma.tx(developerId, async (tx) => {
      const existing = await tx.application.findUnique({ where: { id: appId } });
      if (!existing) {
        throw new NotFoundException('APP_NOT_FOUND');
      }
      await tx.application.update({
        where: { id: appId },
        data: { appSecretHash },
      });
    });

    return { appSecret, appSecretPrefix };
  }

  /**
   * 生成 32 字符 appSecret(字母数字)
   */
  private generateAppSecret(): string {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const bytes = crypto.randomBytes(32);
    let secret = '';
    for (let i = 0; i < 32; i++) {
      secret += charset[bytes[i] % charset.length];
    }
    return secret;
  }

  /**
   * 转换为响应 DTO(不含 appSecretHash)
   */
  private toResponse(app: {
    id: string;
    name: string;
    packageName: string;
    appSecretHash: string;
    signHashAllowList: string[];
    rateLimitIpPerMinute: number | null;
    rateLimitDevicePerMinute: number | null;
    rateLimitFailLockThreshold: number | null;
    rateLimitFailLockTtl: number | null;
    offlineCacheDays: number;
    sdkRsaPublicKeyHash: string | null;
    createdAt: Date;
    updatedAt: Date;
  }) {
    // appSecretHash 不可逆,无法从 hash 得到前缀
    // 所以前缀在创建/重置时返回,这里不返回
    return {
      id: app.id,
      name: app.name,
      packageName: app.packageName,
      appSecretPrefix: '', // 前缀仅在创建/重置时返回,日常查询不返回
      hasSignHashAllowList: app.signHashAllowList.length > 0,
      rateLimitIpPerMinute: app.rateLimitIpPerMinute,
      rateLimitDevicePerMinute: app.rateLimitDevicePerMinute,
      rateLimitFailLockThreshold: app.rateLimitFailLockThreshold,
      rateLimitFailLockTtl: app.rateLimitFailLockTtl,
      offlineCacheDays: app.offlineCacheDays,
      sdkRsaPublicKeyHash: app.sdkRsaPublicKeyHash,
      createdAt: app.createdAt,
      updatedAt: app.updatedAt,
    };
  }
}
