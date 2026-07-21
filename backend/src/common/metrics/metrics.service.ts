import { Injectable } from '@nestjs/common';
import { Registry, Counter, Histogram, collectDefaultMetrics } from 'prom-client';

/**
 * Prometheus 指标服务(ADR 0032 扩展)
 *
 * 提供:
 *  - HTTP 请求计数(按方法/路径/状态码)
 *  - HTTP 请求延迟(按方法/路径)
 *  - 默认进程指标(Node.js runtime)
 *
 * 通过 MetricsInterceptor 全局注入,所有请求自动记录。
 */
@Injectable()
export class MetricsService {
  private readonly registry = new Registry();

  readonly httpRequestsTotal: Counter<string>;
  readonly httpRequestDurationSeconds: Histogram<string>;

  constructor() {
    // 默认进程指标(uptime / memory / CPU / event loop lag 等)
    collectDefaultMetrics({ register: this.registry, prefix: 'xcj_' });

    // HTTP 请求计数
    this.httpRequestsTotal = new Counter({
      name: 'xcj_http_requests_total',
      help: 'Total HTTP requests',
      labelNames: ['method', 'path', 'status'],
      registers: [this.registry],
    });

    // HTTP 请求延迟
    this.httpRequestDurationSeconds = new Histogram({
      name: 'xcj_http_request_duration_seconds',
      help: 'HTTP request duration in seconds',
      labelNames: ['method', 'path'],
      buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
      registers: [this.registry],
    });
  }

  /**
   * 获取所有指标(prometheus exposition format)
   */
  async getMetrics(): Promise<string> {
    return this.registry.metrics();
  }

  /**
   * 获取指标内容类型
   */
  getContentType(): string {
    return this.registry.contentType;
  }
}
