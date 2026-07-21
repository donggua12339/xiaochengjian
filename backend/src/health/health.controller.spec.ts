import { Test } from '@nestjs/testing';
import { HealthController } from './health.controller';
import { PrismaService } from '../prisma/prisma.service';
import { MetricsService } from '../common/metrics/metrics.service';

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
  let metricsService: { getMetrics: jest.Mock };

  beforeEach(async () => {
    prismaService = {
      $queryRaw: jest.fn().mockResolvedValue([{ '?column?': 1 }]),
    };
    metricsService = {
      getMetrics: jest.fn().mockResolvedValue('# HELP xcj_test\n# TYPE xcj_test gauge\nxcj_test 1\n'),
    };

    const moduleRef = await Test.createTestingModule({
      controllers: [HealthController],
      providers: [
        { provide: PrismaService, useValue: prismaService },
        { provide: MetricsService, useValue: metricsService },
      ],
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
    it('返回 Prometheus exposition format 字符串(prom-client + DB 指标)', async () => {
      const result = await controller.metrics();
      expect(typeof result).toBe('string');
      // prom-client mock 输出
      expect(result).toContain('# HELP xcj_test');
      expect(result).toContain('xcj_test 1');
      // 自定义 DB 指标
      expect(result).toContain('# HELP xcj_db_up');
      expect(result).toContain('xcj_db_up 1');
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
