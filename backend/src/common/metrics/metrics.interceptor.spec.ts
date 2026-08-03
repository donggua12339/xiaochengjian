import { type ExecutionContext, type CallHandler } from '@nestjs/common';
import { of, throwError, lastValueFrom } from 'rxjs';
import { MetricsInterceptor } from './metrics.interceptor';
import { MetricsService } from './metrics.service';

describe('MetricsInterceptor', () => {
  let interceptor: MetricsInterceptor;
  let metrics: {
    httpRequestsTotal: { inc: jest.Mock };
    httpRequestDurationSeconds: { observe: jest.Mock };
  };

  beforeEach(() => {
    metrics = {
      httpRequestsTotal: { inc: jest.fn() },
      httpRequestDurationSeconds: { observe: jest.fn() },
    };
    interceptor = new MetricsInterceptor(metrics as unknown as MetricsService);
  });

  function makeContext(method: string, path: string, statusCode = 200) {
    return {
      switchToHttp: () => ({
        getRequest: () => ({ method, route: { path }, path }),
        getResponse: () => ({ statusCode }),
      }),
    } as unknown as ExecutionContext;
  }

  it('/health 应跳过指标记录', async () => {
    const ctx = makeContext('GET', '/health');
    const next = { handle: () => of('ok') } as CallHandler;
    const result = await lastValueFrom(interceptor.intercept(ctx, next));
    expect(result).toBe('ok');
    expect(metrics.httpRequestsTotal.inc).not.toHaveBeenCalled();
  });

  it('/metrics 应跳过指标记录', async () => {
    const ctx = makeContext('GET', '/metrics');
    const next = { handle: () => of('m') } as CallHandler;
    await lastValueFrom(interceptor.intercept(ctx, next));
    expect(metrics.httpRequestsTotal.inc).not.toHaveBeenCalled();
  });

  it('成功请求应记录 total + duration(status 200)', async () => {
    const ctx = makeContext('POST', '/v1/packer/pack', 201);
    const next = { handle: () => of({ ok: true }) } as CallHandler;
    await lastValueFrom(interceptor.intercept(ctx, next));
    expect(metrics.httpRequestsTotal.inc).toHaveBeenCalledWith({
      method: 'POST',
      path: '/v1/packer/pack',
      status: '201',
    });
    expect(metrics.httpRequestDurationSeconds.observe).toHaveBeenCalledWith(
      { method: 'POST', path: '/v1/packer/pack' },
      expect.any(Number),
    );
  });

  it('出错请求应记录错误状态码', async () => {
    const ctx = makeContext('GET', '/v1/x', 500);
    const err = Object.assign(new Error('boom'), { status: 404 });
    const next = { handle: () => throwError(() => err) } as CallHandler;
    await expect(lastValueFrom(interceptor.intercept(ctx, next))).rejects.toThrow('boom');
    expect(metrics.httpRequestsTotal.inc).toHaveBeenCalledWith(
      expect.objectContaining({ status: '404' }),
    );
  });

  it('无 route 时回退 req.path', async () => {
    const ctx = {
      switchToHttp: () => ({
        getRequest: () => ({ method: 'GET', route: undefined, path: '/fallback' }),
        getResponse: () => ({ statusCode: 200 }),
      }),
    } as unknown as ExecutionContext;
    const next = { handle: () => of('x') } as CallHandler;
    await lastValueFrom(interceptor.intercept(ctx, next));
    expect(metrics.httpRequestsTotal.inc).toHaveBeenCalledWith(
      expect.objectContaining({ path: '/fallback' }),
    );
  });
});
