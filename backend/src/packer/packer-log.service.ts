import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import type { Prisma } from '@prisma/client';

/**
 * Packer 审计日志服务(ADR 0081 §审计日志字段)
 *
 * 写入 packer_log 表,保留 1 年(ADR 0032)。
 * 字段脱敏:
 *  - 不记录 APK 内容,只记录 SHA-256 hash
 *  - 不记录 keystore 密码,只记录 keystore 指纹(SHA-256)
 */
@Injectable()
export class PackerLogService {
  private readonly logger = new Logger(PackerLogService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * 记录封装操作(七锁校验结果 + dex 注入状态)
   */
  async record(params: {
    developerId: string;
    appId: string;
    apkHash: string;
    apkSize: number;
    packageName: string;
    signatureHash: string;
    check1Passed: boolean;
    check2Passed: boolean;
    check3Passed: boolean;
    check4Passed: boolean;
    check5Passed: boolean;
    check6Passed: boolean;
    check7Passed: boolean;
    status: 'SUCCESS' | 'REJECTED' | 'FAILED';
    rejectReason?: string | null;
    dexInjected: boolean;
    multidexHandled: boolean;
    injectedDexHash?: string | null;
    resignedApkHash?: string | null;
    keystoreFingerprint?: string | null;
    ip: string;
    userAgent?: string | null;
  }): Promise<void> {
    try {
      await this.prisma.packerLog.create({
        data: {
          developerId: params.developerId,
          appId: params.appId,
          apkHash: params.apkHash,
          apkSize: params.apkSize,
          packageName: params.packageName,
          signatureHash: params.signatureHash,
          check1Passed: params.check1Passed,
          check2Passed: params.check2Passed,
          check3Passed: params.check3Passed,
          check4Passed: params.check4Passed,
          check5Passed: params.check5Passed,
          check6Passed: params.check6Passed,
          check7Passed: params.check7Passed,
          status: params.status,
          rejectReason: params.rejectReason ?? null,
          dexInjected: params.dexInjected,
          multidexHandled: params.multidexHandled,
          injectedDexHash: params.injectedDexHash ?? null,
          resignedApkHash: params.resignedApkHash ?? null,
          keystoreFingerprint: params.keystoreFingerprint ?? null,
          ip: params.ip,
          userAgent: params.userAgent ?? null,
        },
      });
    } catch (e) {
      this.logger.error(`packer_log 写入失败: ${(e as Error).message}`);
    }
  }

  /**
   * 查询某开发者的封装历史
   */
  async listByDeveloper(
    developerId: string,
    options: { limit?: number; offset?: number } = {},
  ): Promise<Prisma.PackerLogGetPayload<{}>[]> {
    const { limit = 50, offset = 0 } = options;
    return this.prisma.packerLog.findMany({
      where: { developerId },
      orderBy: { createdAt: 'desc' },
      take: limit,
      skip: offset,
    });
  }
}
