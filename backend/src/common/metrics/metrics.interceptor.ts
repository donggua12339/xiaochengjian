import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import type { Request, Response } from 'express';
import { MetricsService } from './metrics.service';

/**
 * Prometheus HTTP 指标拦截器(ADR 0032 扩展)
 *
 * 全局注入,自动记录:
 *  - xcj_http_requests_total(按方法/路径/状态码)
 *  - xcj_http_request_duration_seconds(按方法/路径)
 *
 * 排除 /health 和 /metrics 端点(避免自监控噪声)。
 */
@Injectable()
export class MetricsInterceptor implements NestInterceptor {
  constructor(private readonly metrics: MetricsService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const req = context.switchToHttp().getRequest<Request>();
    const method = req.method;
    const path = req.route?.path ?? req.path;

    // 排除健康检查和指标端点
    if (path === '/health' || path === '/metrics') {
      return next.handle();
    }

    const start = process.hrtime.bigint();

    return next.handle().pipe(
      tap({
        next: () => {
          const res = context.switchToHttp().getResponse<Response>();
          const status = String(res.statusCode);
          const duration = Number(process.hrtime.bigint() - start) / 1e9;

          this.metrics.httpRequestsTotal.inc({ method, path, status });
          this.metrics.httpRequestDurationSeconds.observe({ method, path }, duration);
        },
        error: (err) => {
          const status = String(err?.status ?? 500);
          const duration = Number(process.hrtime.bigint() - start) / 1e9;

          this.metrics.httpRequestsTotal.inc({ method, path, status });
          this.metrics.httpRequestDurationSeconds.observe({ method, path }, duration);
        },
      }),
    );
  }
}
