import {
  Injectable,
  ForbiddenException,
  Logger,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

/**
 * 自有 APK 诊断三重校验器(ADR 0077 §2)
 *
 * 校验 1:包名白名单 -- APK 包名必须在 admin-web 注册(本租户的 application.packageName)
 * 校验 2:签名 hash 比对 -- APK 签名 SHA-256 必须在 application.signHashAllowList 内
 * 校验 3:本地私有目录隔离 -- 由 AuditOwnService 在调用时保证(本 service 不直接操作文件系统)
 *
 * 任一校验失败抛 ForbiddenException,不提供跳过开关(ADR 0027 安全基线)
 *
 * 例外 A(签名回填,ADR 0077 §2.1):重签流程前置三重校验,通过后才允许重签
 * 例外 B(梆梆适配器,ADR 0077 §2.1 + ADR 0078):待律师意见落地,本 service 不涉及
 */
@Injectable()
export class AuditOwnValidators {
  private readonly logger = new Logger(AuditOwnValidators.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * 校验 1:包名白名单
   *
   * 查询本租户下是否存在 packageName 匹配的 application。
   * 用 raw prisma(非 TenantPrismaService)因为此处需要跨租户验证唯一性场景,
   * 但只查本租户的 application(developerId 必须匹配)。
   *
   * @returns 匹配的 application(含 id / signHashAllowList)
   * @throws ForbiddenException 包名不在白名单
   */
  async validatePackageName(developerId: string, packageName: string): Promise<{
    id: string;
    name: string;
    signHashAllowList: string[];
  }> {
    const app = await this.prisma.application.findFirst({
      where: { developerId, packageName },
      select: { id: true, name: true, signHashAllowList: true },
    });
    if (!app) {
      this.logger.warn(
        `包名白名单校验失败:developerId=${developerId} packageName=${packageName}`,
      );
      throw new ForbiddenException('APP_NOT_OWNED', {
        cause: 'package name not in developer whitelist',
      });
    }
    return app;
  }

  /**
   * 校验 2:签名 hash 比对
   *
   * APK 签名 SHA-256 必须在 application.signHashAllowList 内。
   * 空白名单 -> 拒绝(开发者必须在 admin-web 预先配置)
   *
   * @throws ForbiddenException 签名不匹配 / 白名单为空
   */
  async validateSignatureHash(
    signHashAllowList: string[],
    signatureHash: string,
  ): Promise<void> {
    if (!signHashAllowList || signHashAllowList.length === 0) {
      throw new ForbiddenException('SIGNATURE_WHITELIST_EMPTY', {
        cause: 'developer must configure signHashAllowList in admin-web first',
      });
    }
    const normalized = signatureHash.toLowerCase();
    const matched = signHashAllowList.some(
      (h) => h.toLowerCase() === normalized,
    );
    if (!matched) {
      this.logger.warn(
        `签名 hash 校验失败:expected one of ${signHashAllowList.length} hashes, got ${normalized}`,
      );
      throw new ForbiddenException('SIGNATURE_MISMATCH', {
        cause: 'apk signature hash not in developer allowlist',
      });
    }
  }

  /**
   * 校验 3:目录隔离(由 AuditOwnService 在调用方保证)
   *
   * 本方法仅作占位,实际隔离由 AuditOwnService 在 /tmp/audit/<taskId>/ 完成:
   *  - 目录权限 700
   *  - 仅 xcj-claude(运行用户)可读写
   *  - 诊断/回填完成后立即 rm -rf
   *
   * 本 service 不操作文件系统,返回 true 表示记录用(始终 true)。
   */
  validateDirectoryIsolation(): boolean {
    return true;
  }
}
