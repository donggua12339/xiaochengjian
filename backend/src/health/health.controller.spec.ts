import { Test } from '@nestjs/testing';
import { HealthController } from './health.controller';
import { PrismaService } from '../prisma/prisma.service';

/**
 * HealthController 单元测试
 *
 * 覆盖 2 个端点:
 *  - GET /health(健康检查 + DB 状态)
 *  - GET /metrics(Prometheus 指标)
 */
describe('HealthController', () => {
  let controller: HealthController;
  let prismaService: { $queryRaw: jest.Mock };

  beforeEach(async () => {
    prismaService = {
      $queryRaw: jest.fn().mockResolvedValue([{ '?column?': 1 }]),
    };

    const moduleRef = await Test.createTestingModule({
      controllers: [HealthController],
      providers: [{ provide: PrismaService, useValue: prismaService }],
    }).compile();
    controller = moduleRef.get(HealthController);
  });

  describe('check', () => {
    it('DB 正常时返回 status=ok db=ok', async () => {
      const result = await controller.check();
      expect(result.status).toBe('ok');
      expect(result.db).toBe('ok');
      expect(result.timestamp).toBeTruthy();
      expect(prismaService.$queryRaw).toHaveBeenCalled();
    });

    it('DB 异常时返回 status=degraded db=error', async () => {
      prismaService.$queryRaw.mockRejectedValueOnce(new Error('connection refused'));
      const result = await controller.check();
      expect(result.status).toBe('degraded');
      expect(result.db).toBe('error');
    });

    it('timestamp 是合法 ISO 字符串', async () => {
      const result = await controller.check();
      const d = new Date(result.timestamp);
      expect(d.getTime()).not.toBeNaN();
    });
  });

  describe('metrics', () => {
    it('返回 Prometheus exposition format 字符串', async () => {
      const result = await controller.metrics();
      expect(typeof result).toBe('string');
      expect(result).toContain('# HELP xcj_process_uptime_seconds');
      expect(result).toContain('# TYPE xcj_process_uptime_seconds counter');
      expect(result).toContain('xcj_process_uptime_seconds');
      expect(result).toContain('xcj_process_resident_memory_bytes');
      expect(result).toContain('xcj_process_heap_used_bytes');
      expect(result).toContain('xcj_process_cpu_user_microseconds');
      expect(result).toContain('xcj_db_up');
    });

    it('DB 正常时 xcj_db_up=1', async () => {
      const result = await controller.metrics();
      expect(result).toMatch(/xcj_db_up 1/);
    });

    it('DB 异常时 xcj_db_up=0', async () => {
      prismaService.$queryRaw.mockRejectedValueOnce(new Error('down'));
      const result = await controller.metrics();
      expect(result).toMatch(/xcj_db_up 0/);
    });
  });
});
