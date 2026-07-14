import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import type { AuditAction, Prisma } from '@prisma/client';

/**
 * 审计日志服务
 * 详见 ADR 0027 (审计日志 1 年保留)
 *
 * 记录开发者后台操作(注册/登录/创建应用/生成卡密等)
 * 字段:developerId, action, target, ip, userAgent, meta(jsonb), createdAt
 */
@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * 记录审计日志
   * 异步写入,不阻塞主流程
   */
  async record(params: {
    developerId: string;
    action: AuditAction;
    target?: string;
    ip?: string;
    userAgent?: string;
    meta?: Record<string, unknown>;
  }): Promise<void> {
    const { developerId, action, target, ip, userAgent, meta } = params;
    try {
      await this.prisma.auditLog.create({
        data: {
          developerId,
          action,
          target,
          ip: ip ?? 'unknown',
          userAgent,
          meta: meta ? (JSON.parse(JSON.stringify(meta)) as Prisma.InputJsonValue) : undefined,
        },
      });
    } catch (e) {
      // 审计日志写入失败不影响主流程,但记录错误
      this.logger.error(`审计日志写入失败: ${(e as Error).message}`);
    }
  }
}
