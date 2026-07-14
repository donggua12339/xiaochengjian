import {
  Injectable,
  NotFoundException,
  ConflictException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';
import { PrismaService } from '../prisma/prisma.service';
import { TenantPrismaService } from '../tenant/tenant-prisma.service';
import { VipLevel } from '@prisma/client';
import type { GenerateMembershipCodesDto, RedeemMembershipCodeDto } from './dto/membership.dto';

/**
 * 会员激活码服务
 * 详见 ADR 0044(发卡网 + 会员激活码模式)
 *
 * 流程:
 *  1. 管理员批量生成激活码(明文返回一次,服务端只存 hash)
 *  2. 管理员在 WM 发卡网卖激活码
 *  3. 开发者购买后,在后台兑换 -> 升级会员
 */
@Injectable()
export class MembershipService {
  private readonly logger = new Logger(MembershipService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly tenantPrisma: TenantPrismaService,
  ) {}

  /**
   * 生成会员激活码(管理员)
   * 返回明文列表(一次性,服务端不保留)
   */
  async generate(adminId: string, dto: GenerateMembershipCodesDto) {
    const batchId = uuidv4();
    const codes: string[] = [];
    const records = [];

    for (let i = 0; i < dto.count; i++) {
      const plaintext = this.generateCode();
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = this.hashCode(plaintext, salt);
      const prefix = plaintext.substring(0, 4);

      codes.push(plaintext);
      records.push({
        codeHash: hash,
        codeSalt: salt,
        codePrefix: prefix,
        level: dto.level,
        durationDays: dto.durationDays,
        status: 'UNUSED',
        batchId,
        remark: dto.remark,
      });
    }

    // 批量写入
    await this.prisma.membershipCode.createMany({ data: records });

    this.logger.log(`管理员 ${adminId} 生成 ${dto.count} 个会员激活码,批次 ${batchId}`);

    return {
      batchId,
      codes,
      count: dto.count,
    };
  }

  /**
   * 兑换会员激活码(开发者)
   */
  async redeem(developerId: string, dto: RedeemMembershipCodeDto) {
    return this.tenantPrisma.tx(developerId, async (tx) => {
      // 查找激活码(遍历所有 UNUSED,比对 hash)
      // 注:激活码是全局表(不属于租户),但兑换操作在租户事务内
      const unusedCodes = await this.prisma.membershipCode.findMany({
        where: { status: 'UNUSED' },
        select: { id: true, codeHash: true, codeSalt: true, level: true, durationDays: true },
      });

      let matched: { id: string; level: VipLevel; durationDays: number } | null = null;
      for (const c of unusedCodes) {
        const hash = this.hashCode(dto.code, c.codeSalt);
        if (hash === c.codeHash) {
          matched = c;
          break;
        }
      }

      if (!matched) {
        throw new NotFoundException('MEMBERSHIP_CODE_NOT_FOUND');
      }

      // 原子更新:UNUSED -> USED(防止并发兑换)
      const updated = await this.prisma.membershipCode.updateMany({
        where: { id: matched.id, status: 'UNUSED' },
        data: {
          status: 'USED',
          redeemedBy: developerId,
          redeemedAt: new Date(),
        },
      });

      if (updated.count === 0) {
        throw new ConflictException('MEMBERSHIP_CODE_ALREADY_REDEEMED');
      }

      // 计算新会员等级 + 过期时间
      const developer = await tx.developer.findUnique({
        where: { id: developerId },
        select: { vipLevel: true, vipExpiresAt: true },
      });
      if (!developer) {
        throw new NotFoundException('DEVELOPER_NOT_FOUND');
      }

      const now = new Date();
      let baseExpiresAt = developer.vipExpiresAt;
      if (developer.vipLevel !== VipLevel.FREE && baseExpiresAt && baseExpiresAt > now) {
        // 已有有效会员,在原到期时间基础上延长
      } else {
        baseExpiresAt = now;
      }

      const newExpiresAt = new Date(baseExpiresAt);
      if (matched.durationDays === -1) {
        // PERMANENT:100 年(实际永久)
        newExpiresAt.setFullYear(newExpiresAt.getFullYear() + 100);
      } else {
        newExpiresAt.setDate(newExpiresAt.getDate() + matched.durationDays);
      }

      // 更新开发者会员
      await tx.developer.update({
        where: { id: developerId },
        data: {
          vipLevel: matched.level,
          vipExpiresAt: newExpiresAt,
        },
      });

      this.logger.log(
        `开发者 ${developerId} 兑换激活码,等级 ${matched.level},到期 ${newExpiresAt.toISOString()}`,
      );

      return {
        level: matched.level,
        durationDays: matched.durationDays,
        newVipLevel: matched.level,
        newVipExpiresAt: newExpiresAt,
      };
    });
  }

  /**
   * 列出激活码(管理员)
   */
  async list(params: { page?: number; pageSize?: number; status?: string; batchId?: string }) {
    const page = params.page ?? 1;
    const pageSize = params.pageSize ?? 20;
    const where: { status?: string; batchId?: string } = {};
    if (params.status) where.status = params.status;
    if (params.batchId) where.batchId = params.batchId;

    const [items, total] = await Promise.all([
      this.prisma.membershipCode.findMany({
        where,
        select: {
          id: true,
          codePrefix: true,
          level: true,
          durationDays: true,
          status: true,
          redeemedBy: true,
          redeemedAt: true,
          batchId: true,
          remark: true,
          createdAt: true,
        },
        skip: (page - 1) * pageSize,
        take: pageSize,
        orderBy: { createdAt: 'desc' },
      }),
      this.prisma.membershipCode.count({ where }),
    ]);

    return {
      items,
      total,
      page,
      pageSize,
      totalPages: Math.ceil(total / pageSize),
    };
  }

  /**
   * 禁用激活码(管理员)
   */
  async disable(id: string) {
    const code = await this.prisma.membershipCode.findUnique({ where: { id } });
    if (!code) {
      throw new NotFoundException('MEMBERSHIP_CODE_NOT_FOUND');
    }
    if (code.status === 'USED') {
      throw new BadRequestException('CANNOT_DISABLE_USED_CODE');
    }
    return this.prisma.membershipCode.update({
      where: { id },
      data: { status: 'DISABLED' },
    });
  }

  /**
   * 生成激活码明文(16 字符,字母数字,无连字符)
   * 格式:与卡密相同字符集(去 0/O/1/I)
   */
  private generateCode(): string {
    const charset = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
    const bytes = crypto.randomBytes(16);
    let code = '';
    for (let i = 0; i < 16; i++) {
      code += charset[bytes[i] % charset.length];
    }
    return code;
  }

  /**
   * 哈希激活码(SHA-256(明文 + salt))
   */
  private hashCode(code: string, salt: string): string {
    return crypto
      .createHash('sha256')
      .update(code + salt)
      .digest('hex');
  }
}
