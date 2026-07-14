import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { Observable } from 'rxjs';
import type { AuthenticatedRequest } from '../common/decorators/current-developer.decorator';

/**
 * 租户拦截器
 * 从 JWT payload 提取 developerId,存到 request.tenantId
 * 业务层用 TenantPrismaService.tx(request.tenantId, ...) 执行查询
 *
 * 注意:此拦截器只提取 tenant_id,不设置 SET LOCAL
 * SET LOCAL 在 TenantPrismaService.tx 的事务内执行(因为 SET LOCAL 只在事务内有效)
 *
 * 详见 ADR 0018 (多租户隔离)
 */
@Injectable()
export class TenantInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();

    // 从 JWT payload 提取 developerId 作为 tenant_id
    if (request.user?.sub) {
      (request as unknown as { tenantId?: string }).tenantId = request.user.sub;
    }

    return next.handle();
  }
}
