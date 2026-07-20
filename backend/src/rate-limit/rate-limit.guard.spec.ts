import { Test } from '@nestjs/testing';
import { ExecutionContext, HttpException, HttpStatus } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RateLimitGuard } from './rate-limit.guard';
import { RateLimitService } from './rate-limit.service';

/**
 * RateLimitGuard 单元测试
 *
 * 覆盖:
 *  - 无 @RateLimit() 装饰器时直接放行
 *  - 限流通过:挂载 X-RateLimit-* header
 *  - 限流拒绝:抛 429 TOO_MANY_REQUESTS
 *  - IP 提取优先级(x-forwarded-for > socket.remoteAddress > unknown)
 *  - 默认 limit/window(60/60)
 */
describe('RateLimitGuard', () => {
  let guard: RateLimitGuard;
  let rateLimitService: { checkIpRateLimit: jest.Mock };
  let reflector: { get: jest.Mock };

  beforeEach(async () => {
    rateLimitService = {
      checkIpRateLimit: jest.fn(),
    };
    reflector = {
      get: jest.fn(),
    };
    const moduleRef = await Test.createTestingModule({
      providers: [
        RateLimitGuard,
        { provide: RateLimitService, useValue: rateLimitService },
        { provide: Reflector, useValue: reflector },
      ],
    }).compile();
    guard = moduleRef.get(RateLimitGuard);
  });

  function makeContext(opts: {
    handlerRateLimit?: { ip?: number; window?: number };
    headers?: Record<string, string>;
    socketAddr?: string;
    setHeader?: jest.Mock;
  }): ExecutionContext {
    const request: any = {
      headers: opts.headers ?? {},
      socket: { remoteAddress: opts.socketAddr },
    };
    const response: any = {
      setHeader: opts.setHeader ?? jest.fn(),
    };
    const ctx: any = {
      switchToHttp: () => ({
        getRequest: () => request,
        getResponse: () => response,
      }),
      getHandler: () => ({}),
    };
    reflector.get.mockReturnValue(opts.handlerRateLimit ?? null);
    return ctx;
  }

  it('无 @RateLimit() 装饰器时直接放行(不调 service)', async () => {
    const ctx = makeContext({});
    const result = await guard.canActivate(ctx);
    expect(result).toBe(true);
    expect(rateLimitService.checkIpRateLimit).not.toHaveBeenCalled();
  });

  it('限流通过应挂载 X-RateLimit-* header', async () => {
    rateLimitService.checkIpRateLimit.mockResolvedValue({
      allowed: true,
      remaining: 59,
      retryAfter: 0,
    });
    const setHeader = jest.fn();
    const ctx = makeContext({
      handlerRateLimit: { ip: 60, window: 60 },
      headers: { 'x-forwarded-for': '1.2.3.4' },
      setHeader,
    });
    const result = await guard.canActivate(ctx);
    expect(result).toBe(true);
    expect(setHeader).toHaveBeenCalledWith('X-RateLimit-Limit', 60);
    expect(setHeader).toHaveBeenCalledWith('X-RateLimit-Remaining', 59);
  });

  it('限流拒绝应抛 429 TOO_MANY_REQUESTS', async () => {
    rateLimitService.checkIpRateLimit.mockResolvedValue({
      allowed: false,
      remaining: 0,
      retryAfter: 30,
    });
    const ctx = makeContext({
      handlerRateLimit: { ip: 60, window: 60 },
      headers: { 'x-forwarded-for': '1.2.3.4' },
    });
    await expect(guard.canActivate(ctx)).rejects.toThrow(HttpException);
    try {
      await guard.canActivate(ctx);
    } catch (e) {
      expect((e as HttpException).getStatus()).toBe(HttpStatus.TOO_MANY_REQUESTS);
    }
  });

  it('x-forwarded-for 缺失时用 socket.remoteAddress', async () => {
    rateLimitService.checkIpRateLimit.mockResolvedValue({
      allowed: true,
      remaining: 59,
      retryAfter: 0,
    });
    const ctx = makeContext({
      handlerRateLimit: { ip: 60, window: 60 },
      socketAddr: '5.6.7.8',
    });
    await guard.canActivate(ctx);
    expect(rateLimitService.checkIpRateLimit).toHaveBeenCalledWith(
      '5.6.7.8',
      60,
      60,
    );
  });

  it('x-forwarded-for + socket 都缺失时用 unknown', async () => {
    rateLimitService.checkIpRateLimit.mockResolvedValue({
      allowed: true,
      remaining: 59,
      retryAfter: 0,
    });
    const ctx = makeContext({
      handlerRateLimit: { ip: 60, window: 60 },
    });
    await guard.canActivate(ctx);
    expect(rateLimitService.checkIpRateLimit).toHaveBeenCalledWith(
      'unknown',
      60,
      60,
    );
  });

  it('x-forwarded-for 含多个 IP 时取第一个', async () => {
    rateLimitService.checkIpRateLimit.mockResolvedValue({
      allowed: true,
      remaining: 59,
      retryAfter: 0,
    });
    const ctx = makeContext({
      handlerRateLimit: { ip: 60, window: 60 },
      headers: { 'x-forwarded-for': '1.2.3.4, 5.6.7.8' },
    });
    await guard.canActivate(ctx);
    expect(rateLimitService.checkIpRateLimit).toHaveBeenCalledWith(
      '1.2.3.4',
      60,
      60,
    );
  });

  it('装饰器未指定 ip/window 时用默认值 60/60', async () => {
    rateLimitService.checkIpRateLimit.mockResolvedValue({
      allowed: true,
      remaining: 59,
      retryAfter: 0,
    });
    const ctx = makeContext({
      handlerRateLimit: {},
      headers: { 'x-forwarded-for': '1.2.3.4' },
    });
    await guard.canActivate(ctx);
    expect(rateLimitService.checkIpRateLimit).toHaveBeenCalledWith(
      '1.2.3.4',
      60,
      60,
    );
  });
});
