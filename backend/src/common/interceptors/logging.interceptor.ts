import { CallHandler, ExecutionContext, Injectable, Logger, NestInterceptor } from '@nestjs/common';
import { Observable, tap } from 'rxjs';
import type { Request } from 'express';
import { v4 as uuidv4 } from 'uuid';

/**
 * 请求日志拦截器
 * 记录每个请求的方法/路径/耗时/状态
 * 不记录请求体(防卡密明文泄露,见 ADR 0027)
 */
@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger('HTTP');

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const request = context.switchToHttp().getRequest<Request>();
    const requestId = (request.headers['x-request-id'] as string) ?? uuidv4();
    request.headers['x-request-id'] = requestId;

    const { method, url } = request;
    const startTime = Date.now();

    return next.handle().pipe(
      tap({
        next: () => {
          const duration = Date.now() - startTime;
          this.logger.log(`requestId=${requestId} ${method} ${url} ${duration}ms`);
        },
        error: (err: unknown) => {
          const duration = Date.now() - startTime;
          const status =
            err && typeof err === 'object' && 'status' in err
              ? (err as { status: number }).status
              : 500;
          this.logger.warn(`requestId=${requestId} ${method} ${url} ${status} ${duration}ms`);
        },
      }),
    );
  }
}
