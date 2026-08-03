import { MetricsService } from './metrics.service';

describe('MetricsService', () => {
  let service: MetricsService;

  beforeEach(() => {
    service = new MetricsService();
  });

  it('httpRequestsTotal 计数后 getMetrics 应含该指标', async () => {
    service.httpRequestsTotal.inc({ method: 'GET', path: '/v1/x', status: '200' });
    const metrics = await service.getMetrics();
    expect(metrics).toContain('xcj_http_requests_total');
    expect(metrics).toContain('/v1/x');
  });

  it('httpRequestDurationSeconds 观测后 getMetrics 应含直方图', async () => {
    service.httpRequestDurationSeconds.observe({ method: 'POST', path: '/v1/y' }, 0.123);
    const metrics = await service.getMetrics();
    expect(metrics).toContain('xcj_http_request_duration_seconds');
  });

  it('getContentType 应返回 prometheus 内容类型', () => {
    expect(service.getContentType()).toMatch(/text\/plain|openmetrics/);
  });

  it('getMetrics 应含默认进程指标(xcj_ 前缀)', async () => {
    const metrics = await service.getMetrics();
    expect(metrics).toContain('xcj_');
  });
});
