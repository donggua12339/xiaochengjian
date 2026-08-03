import { type ExecutionContext, HttpException, HttpStatus } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { DeveloperRateLimitGuard, DEVELOPER_RATE_LIMIT_KEY } from './developer-rate-limit.guard';
import { RateLimitService } from './rate-limit.service';

describe('DeveloperRateLimitGuard', () => {
  let guard: DeveloperRateLimitGuard;
  let rateLimit: { checkDeveloperRateLimit: jest.Mock };
  let reflectorGet: jest.Mock;

  function makeContext(user?: { sub: string }) {
    const setHeader = jest.fn();
    const ctx = {
      getHandler: () => ({}),
      switchToHttp: () => ({
        getRequest: () => ({ user }),
        getResponse: () => ({ setHeader }),
      }),
    } as unknown as ExecutionContext;
    return { ctx, setHeader };
  }

  beforeEach(() => {
    rateLimit = { checkDeveloperRateLimit: jest.fn() };
    reflectorGet = jest.fn();
    const reflector = { get: reflectorGet } as unknown as Reflector;
    guard = new DeveloperRateLimitGuard(rateLimit as unknown as RateLimitService, reflector);
  });

  it('未配置限流元数据应放行', async () => {
    reflectorGet.mockReturnValue(undefined);
    const { ctx } = makeContext({ sub: 'dev-1' });
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
    expect(rateLimit.checkDeveloperRateLimit).not.toHaveBeenCalled();
  });

  it('未认证(无 developerId)应放行', async () => {
    reflectorGet.mockReturnValue({ limit: 10, window: 60 });
    const { ctx } = makeContext(undefined);
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
    expect(rateLimit.checkDeveloperRateLimit).not.toHaveBeenCalled();
  });

  it('允许通过应设置限流 header', async () => {
    reflectorGet.mockReturnValue({ limit: 100, window: 60 });
    rateLimit.checkDeveloperRateLimit.mockResolvedValue({
      allowed: true,
      remaining: 99,
      retryAfter: 0,
    });
    const { ctx, setHeader } = makeContext({ sub: 'dev-1' });
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
    expect(rateLimit.checkDeveloperRateLimit).toHaveBeenCalledWith('dev-1', 100, 60);
    expect(setHeader).toHaveBeenCalledWith('X-RateLimit-Limit', 100);
    expect(setHeader).toHaveBeenCalledWith('X-RateLimit-Remaining', 99);
  });

  it('超限应抛 429', async () => {
    reflectorGet.mockReturnValue({ limit: 5, window: 60 });
    rateLimit.checkDeveloperRateLimit.mockResolvedValue({
      allowed: false,
      remaining: 0,
      retryAfter: 42,
    });
    const { ctx } = makeContext({ sub: 'dev-1' });
    await expect(guard.canActivate(ctx)).rejects.toMatchObject({
      status: HttpStatus.TOO_MANY_REQUESTS,
    });
    try {
      await guard.canActivate(ctx);
    } catch (e) {
      expect(e).toBeInstanceOf(HttpException);
    }
  });

  it('limit/window 缺省应用默认 100/60', async () => {
    reflectorGet.mockReturnValue({});
    rateLimit.checkDeveloperRateLimit.mockResolvedValue({
      allowed: true,
      remaining: 1,
      retryAfter: 0,
    });
    const { ctx } = makeContext({ sub: 'dev-1' });
    await guard.canActivate(ctx);
    expect(rateLimit.checkDeveloperRateLimit).toHaveBeenCalledWith('dev-1', 100, 60);
  });

  it('装饰器键常量应稳定', () => {
    expect(DEVELOPER_RATE_LIMIT_KEY).toBe('developerRateLimit');
  });
});
