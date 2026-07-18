import { Test } from '@nestjs/testing';
import { of, lastValueFrom } from 'rxjs';
import { TenantInterceptor } from './tenant.interceptor';

describe('TenantInterceptor', () => {
  let interceptor: TenantInterceptor;

  beforeEach(async () => {
    const moduleRef = await Test.createTestingModule({
      providers: [TenantInterceptor],
    }).compile();
    interceptor = moduleRef.get(TenantInterceptor);
  });

  function buildContext(user?: { sub?: string }): any {
    const request: any = { user };
    return {
      switchToHttp: () => ({ getRequest: () => request }),
    };
  }

  it('有 user.sub 应设置 request.tenantId', async () => {
    const ctx = buildContext({ sub: 'dev-1' });
    const result = await lastValueFrom(
      interceptor.intercept(ctx, { handle: () => of('ok') } as any),
    );
    expect(result).toBe('ok');
    expect(ctx.switchToHttp().getRequest().tenantId).toBe('dev-1');
  });

  it('无 user 应不设置 tenantId', async () => {
    const ctx = buildContext(undefined);
    await lastValueFrom(
      interceptor.intercept(ctx, { handle: () => of('ok') } as any),
    );
    expect(ctx.switchToHttp().getRequest().tenantId).toBeUndefined();
  });

  it('user 无 sub 应不设置 tenantId', async () => {
    const ctx = buildContext({});
    await lastValueFrom(
      interceptor.intercept(ctx, { handle: () => of('ok') } as any),
    );
    expect(ctx.switchToHttp().getRequest().tenantId).toBeUndefined();
  });

  it('应原样透传 handler 结果', async () => {
    const ctx = buildContext({ sub: 'dev-1' });
    const expected = { id: '1', name: 'test' };
    const result = await lastValueFrom(
      interceptor.intercept(ctx, { handle: () => of(expected) } as any),
    );
    expect(result).toBe(expected);
  });
});
