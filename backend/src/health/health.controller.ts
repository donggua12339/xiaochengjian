import { Controller, Get, Header } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiExcludeEndpoint } from '@nestjs/swagger';
import { PrismaService } from '../prisma/prisma.service';
import { MetricsService } from '../common/metrics/metrics.service';

@ApiTags('health')
@Controller()
export class HealthController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly metricsService: MetricsService,
  ) {}

  @Get('health')
  @ApiOperation({ summary: '健康检查' })
  async check(): Promise<{ status: string; db: string; timestamp: string }> {
    let dbStatus = 'ok';
    try {
      await this.prisma.$queryRaw`SELECT 1`;
    } catch {
      dbStatus = 'error';
    }
    return {
      status: dbStatus === 'ok' ? 'ok' : 'degraded',
      db: dbStatus,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Prometheus 指标端点
   * 返回进程指标 + HTTP 请求指标(prom-client)
   * 详见 ADR 0032 (监控告警)
   */
  @Get('metrics')
  @ApiExcludeEndpoint()
  @Header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
  async metrics(): Promise<string> {
    // prom-client 默认指标(进程 + HTTP)
    const promMetrics = await this.metricsService.getMetrics();

    // 自定义 DB 连通性指标
    const dbUp = await this.checkDb() ? 1 : 0;
    const dbMetric = [
      '# HELP xcj_db_up Database connectivity (1=up, 0=down)',
      '# TYPE xcj_db_up gauge',
      `xcj_db_up ${dbUp}`,
      '',
    ].join('\n');

    return promMetrics + '\n' + dbMetric;
  }

  private async checkDb(): Promise<boolean> {
    try {
      await this.prisma.$queryRaw`SELECT 1`;
      return true;
    } catch {
      return false;
    }
  }
}
