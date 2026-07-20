import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import type { Prisma } from '@prisma/client';

/**
 * 自有 APK 诊断审计日志服务(ADR 0077 §4)
 *
 * 独立于 AuditService(老的开发者后台操作日志),专门记录三重校验结果 + 诊断/回填状态。
 * 写入 audit_log_own 表,保留 1 年(ADR 0032)。
 *
 * 字段脱敏:
 *  - 不记录 APK 内容,只记录 SHA-256 hash
 *  - 不记录 keystore 密码,只记录 keystore 指纹(SHA-256)
 *  - 不记录卡密明文(本服务不涉及卡密)
 */
@Injectable()
export class AuditLogOwnService {
  private readonly logger = new Logger(AuditLogOwnService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * 记录诊断/回填操作
   * 异步写入,不阻塞主流程(失败只 log,不抛错)
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
    status: 'SUCCESS' | 'REJECTED' | 'FAILED' | 'RESIGN';
    rejectReason?: string | null;
    reportPath?: string | null;
    operation: 'ANALYZE' | 'RESIGN';
    resignFromHash?: string | null;
    resignToHash?: string | null;
    keystoreFingerprint?: string | null;
    ip: string;
    userAgent?: string | null;
  }): Promise<void> {
    const {
      developerId,
      appId,
      apkHash,
      apkSize,
      packageName,
      signatureHash,
      check1Passed,
      check2Passed,
      check3Passed,
      status,
      rejectReason,
      reportPath,
      operation,
      resignFromHash,
      resignToHash,
      keystoreFingerprint,
      ip,
      userAgent,
    } = params;

    try {
      await this.prisma.auditLogOwn.create({
        data: {
          developerId,
          appId,
          apkHash,
          apkSize,
          packageName,
          signatureHash,
          check1Passed,
          check2Passed,
          check3Passed,
          status,
          rejectReason: rejectReason ?? null,
          reportPath: reportPath ?? null,
          operation,
          resignFromHash: resignFromHash ?? null,
          resignToHash: resignToHash ?? null,
          keystoreFingerprint: keystoreFingerprint ?? null,
          ip,
          userAgent: userAgent ?? null,
        },
      });
    } catch (e) {
      // 审计日志写入失败不影响主流程,但记录错误
      this.logger.error(
        `audit_log_own 写入失败: ${(e as Error).message}`,
      );
    }
  }

  /**
   * 查询某开发者的诊断历史(分页)
   * 用于 admin-web 的"自有诊断"Tab 展示
   */
  async listByDeveloper(
    developerId: string,
    options: { limit?: number; offset?: number } = {},
  ): Promise<Prisma.AuditLogOwnGetPayload<{}>[]> {
    const { limit = 50, offset = 0 } = options;
    return this.prisma.auditLogOwn.findMany({
      where: { developerId },
      orderBy: { createdAt: 'desc' },
      take: limit,
      skip: offset,
    });
  }

  /**
   * 导出某开发者的诊断历史为 CSV(合规审计用,ADR 0032)
   *
   * 字段:时间/操作/状态/包名/APK hash/APK 大小/签名 hash/校验1/校验2/拒绝原因/回填后 hash/keystore 指纹/IP/UA
   *
   * @returns CSV 字符串(UTF-8 with BOM,Excel 友好)
   */
  async exportCsvByDeveloper(
    developerId: string,
    options: { limit?: number } = {},
  ): Promise<string> {
    const { limit = 10000 } = options;
    const logs = await this.prisma.auditLogOwn.findMany({
      where: { developerId },
      orderBy: { createdAt: 'desc' },
      take: Math.min(limit, 50000), // 上限 5 万行,防止滥用
    });

    const headers = [
      'createdAt',
      'operation',
      'status',
      'packageName',
      'apkHash',
      'apkSize',
      'signatureHash',
      'check1Passed',
      'check2Passed',
      'check3Passed',
      'rejectReason',
      'resignFromHash',
      'resignToHash',
      'keystoreFingerprint',
      'appId',
      'ip',
      'userAgent',
    ];

    const escapeCsv = (val: unknown): string => {
      if (val === null || val === undefined) return '';
      const s = String(val);
      // 含逗号/引号/换行的字段用双引号包裹,内部引号转义为两个引号
      if (/[",\n\r]/.test(s)) {
        return `"${s.replace(/"/g, '""')}"`;
      }
      return s;
    };

    const lines = [headers.join(',')];
    for (const log of logs) {
      lines.push(
        [
          log.createdAt.toISOString(),
          log.operation,
          log.status,
          log.packageName,
          log.apkHash,
          log.apkSize,
          log.signatureHash,
          log.check1Passed,
          log.check2Passed,
          log.check3Passed,
          log.rejectReason,
          log.resignFromHash,
          log.resignToHash,
          log.keystoreFingerprint,
          log.appId,
          log.ip,
          log.userAgent,
        ]
          .map(escapeCsv)
          .join(','),
      );
    }

    // UTF-8 BOM(Excel 友好,中文不乱码)
    return '\ufeff' + lines.join('\r\n');
  }
}
