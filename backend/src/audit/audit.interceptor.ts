import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable, tap } from 'rxjs';
import type { Request } from 'express';
import { AuditService } from './audit.service';
import { AUDIT_KEY } from './audit.decorator';
import type { AuthenticatedRequest } from '../common/decorators/current-developer.decorator';
import type { AuditAction } from '@prisma/client';

/**
 * 审计日志拦截器
 * 自动记录被 @Audit() 装饰器标记的接口操作
 *
 * 记录内容:
 *  - developerId: 从 JWT payload (request.user.sub)
 *  - action: 装饰器参数
 *  - target: 返回值的 id 字段(如果有)
 *  - ip: 请求 IP
 *  - userAgent: 请求 User-Agent
 *  - meta: 返回值的非敏感字段(可选)
 */
@Injectable()
export class AuditInterceptor implements NestInterceptor {
  constructor(
    private readonly auditService: AuditService,
    private readonly reflector: Reflector,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const action = this.reflector.get<AuditAction>(AUDIT_KEY, context.getHandler());
    if (!action) {
      return next.handle();
    }

    const request = context.switchToHttp().getRequest<AuthenticatedRequest & Request>();
    const developerId = request.user?.sub;
    const ip =
      (request.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      request.socket.remoteAddress;
    const userAgent = request.headers['user-agent'];

    return next.handle().pipe(
      tap((result) => {
        // 异步记录,不阻塞响应
        if (!developerId) return;

        const target = this.extractTarget(result);
        const meta = this.extractMeta(request.method, request.body, result);

        this.auditService.record({
          developerId,
          action,
          target,
          ip,
          userAgent,
          meta,
        });
      }),
    );
  }

  /**
   * 从返回值提取 target(通常是 id)
   */
  private extractTarget(result: unknown): string | undefined {
    if (!result || typeof result !== 'object') return undefined;
    const obj = result as Record<string, unknown>;
    if (typeof obj.id === 'string') return obj.id;
    if (typeof obj.batchId === 'string') return obj.batchId;
    return undefined;
  }

  /**
   * 提取元数据(请求方法 + 路径 + 非敏感参数)
   */
  private extractMeta(method: string, body: unknown, result: unknown): Record<string, unknown> {
    const meta: Record<string, unknown> = { method };

    if (body && typeof body === 'object') {
      const b = body as Record<string, unknown>;
      // 只记录非敏感字段
      if (typeof b.type === 'string') meta.type = b.type;
      if (typeof b.count === 'number') meta.count = b.count;
      if (typeof b.name === 'string') meta.name = b.name;
      if (typeof b.packageName === 'string') meta.packageName = b.packageName;
    }

    if (result && typeof result === 'object') {
      const r = result as Record<string, unknown>;
      if (typeof r.count === 'number') meta.resultCount = r.count;
    }

    return meta;
  }
}
