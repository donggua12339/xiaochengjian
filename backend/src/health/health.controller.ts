import { Controller, Get, Header } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiExcludeEndpoint } from '@nestjs/swagger';
import { PrismaService } from '../prisma/prisma.service';

@ApiTags('health')
@Controller()
export class HealthController {
  constructor(private readonly prisma: PrismaService) {}

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
   * 返回基础进程指标(prometheus exposition format)
   * 详见 ADR 0032 (监控告警)
   */
  @Get('metrics')
  @ApiExcludeEndpoint()
  @Header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
  async metrics(): Promise<string> {
    const mem = process.memoryUsage();
    const uptime = process.uptime();
    const cpu = process.cpuUsage();

    return [
      '# HELP xcj_process_uptime_seconds Process uptime in seconds',
      '# TYPE xcj_process_uptime_seconds counter',
      `xcj_process_uptime_seconds ${uptime.toFixed(2)}`,
      '',
      '# HELP xcj_process_resident_memory_bytes Resident memory size in bytes',
      '# TYPE xcj_process_resident_memory_bytes gauge',
      `xcj_process_resident_memory_bytes ${mem.rss}`,
      '',
      '# HELP xcj_process_heap_used_bytes Heap used in bytes',
      '# TYPE xcj_process_heap_used_bytes gauge',
      `xcj_process_heap_used_bytes ${mem.heapUsed}`,
      '',
      '# HELP xcj_process_heap_total_bytes Heap total in bytes',
      '# TYPE xcj_process_heap_total_bytes gauge',
      `xcj_process_heap_total_bytes ${mem.heapTotal}`,
      '',
      '# HELP xcj_process_cpu_user_microseconds User CPU time in microseconds',
      '# TYPE xcj_process_cpu_user_microseconds counter',
      `xcj_process_cpu_user_microseconds ${cpu.user}`,
      '',
      '# HELP xcj_process_cpu_system_microseconds System CPU time in microseconds',
      '# TYPE xcj_process_cpu_system_microseconds counter',
      `xcj_process_cpu_system_microseconds ${cpu.system}`,
      '',
      '# HELP xcj_db_up Database connectivity (1=up, 0=down)',
      '# TYPE xcj_db_up gauge',
      `xcj_db_up ${await this.checkDb() ? 1 : 0}`,
      '',
    ].join('\n');
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
