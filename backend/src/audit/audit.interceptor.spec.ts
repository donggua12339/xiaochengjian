import { Test } from '@nestjs/testing';
import { Reflector } from '@nestjs/core';
import { of, lastValueFrom } from 'rxjs';
import { AuditInterceptor } from './audit.interceptor';
import { AuditService } from './audit.service';

/**
 * AuditInterceptor 单元测试
 *
 * 覆盖:
 *  - 无 @Audit 装饰器应跳过
 *  - 有 @Audit 应调用 auditService.record
 *  - developerId 缺失应跳过
 *  - extractTarget: id / batchId / 无
 *  - extractMeta: method + 非敏感字段
 *  - X-Forwarded-For 优先于 socket.remoteAddress
 */
describe('AuditInterceptor', () => {
  let interceptor: AuditInterceptor;
  let auditService: { record: jest.Mock };
  let reflector: { get: jest.Mock };

  beforeEach(async () => {
    auditService = { record: jest.fn().mockResolvedValue(undefined) };
    reflector = { get: jest.fn() };
    const moduleRef = await Test.createTestingModule({
      providers: [
        AuditInterceptor,
        { provide: AuditService, useValue: auditService },
        { provide: Reflector, useValue: reflector },
      ],
    }).compile();
    interceptor = moduleRef.get(AuditInterceptor);
  });

  /** 构建 mock ExecutionContext */
  function buildContext(opts: {
    action?: string;
    user?: { sub?: string };
    method?: string;
    body?: unknown;
    headers?: Record<string, string | string[] | undefined>;
    socketRemoteAddress?: string;
  } = {}): any {
    const handler = { name: 'testHandler' };
    return {
      getHandler: () => handler,
      switchToHttp: () => ({
        getRequest: () => ({
          method: opts.method ?? 'POST',
          body: opts.body ?? {},
          headers: opts.headers ?? {},
          socket: { remoteAddress: opts.socketRemoteAddress ?? '127.0.0.1' },
          user: opts.user,
        }),
      }),
    };
  }

  describe('无 @Audit 装饰器', () => {
    it('应跳过记录(reflector.get 返回 undefined)', async () => {
      reflector.get.mockReturnValue(undefined);
      const ctx = buildContext();
      const result = await lastValueFrom(
        interceptor.intercept(ctx, { handle: () => of({ id: '1' }) } as any),
      );
      expect(result).toEqual({ id: '1' });
      expect(auditService.record).not.toHaveBeenCalled();
    });
  });

  describe('有 @Audit 装饰器', () => {
    beforeEach(() => {
      reflector.get.mockReturnValue('GENERATE_CARDS');
    });

    it('应调用 auditService.record 带 action + developerId', async () => {
      const ctx = buildContext({
        user: { sub: 'dev-1' },
        headers: { 'user-agent': 'Mozilla/5.0' },
      });
      const result = { id: 'card-1', count: 3 };
      await lastValueFrom(
        interceptor.intercept(ctx, { handle: () => of(result) } as any),
      );
      expect(auditService.record).toHaveBeenCalledWith(
        expect.objectContaining({
          developerId: 'dev-1',
          action: 'GENERATE_CARDS',
          target: 'card-1',
          userAgent: 'Mozilla/5.0',
        }),
      );
    });

    it('developerId 缺失应跳过记录', async () => {
      const ctx = buildContext({ user: undefined });
      await lastValueFrom(
        interceptor.intercept(ctx, { handle: () => of({ id: '1' }) } as any),
      );
      expect(auditService.record).not.toHaveBeenCalled();
    });

    it('user.sub 缺失应跳过记录', async () => {
      const ctx = buildContext({ user: {} });
      await lastValueFrom(
        interceptor.intercept(ctx, { handle: () => of({ id: '1' }) } as any),
      );
      expect(auditService.record).not.toHaveBeenCalled();
    });

    it('X-Forwarded-For 优先于 socket.remoteAddress', async () => {
      const ctx = buildContext({
        user: { sub: 'dev-1' },
        headers: { 'x-forwarded-for': '1.2.3.4, 5.6.7.8' },
        socketRemoteAddress: '127.0.0.1',
      });
      await lastValueFrom(
        interceptor.intercept(ctx, { handle: () => of({ id: '1' }) } as any),
      );
      expect(auditService.record).toHaveBeenCalledWith(
        expect.objectContaining({ ip: '1.2.3.4' }),
      );
    });

    it('无 X-Forwarded-For 应使用 socket.remoteAddress', async () => {
      const ctx = buildContext({
        user: { sub: 'dev-1' },
        headers: {},
        socketRemoteAddress: '192.168.1.100',
      });
      await lastValueFrom(
        interceptor.intercept(ctx, { handle: () => of({ id: '1' }) } as any),
      );
      expect(auditService.record).toHaveBeenCalledWith(
        expect.objectContaining({ ip: '192.168.1.100' }),
      );
    });

    it('X-Forwarded-For 多 IP 应取第一个(去空格)', async () => {
      const ctx = buildContext({
        user: { sub: 'dev-1' },
        headers: { 'x-forwarded-for': '  10.0.0.1  , 10.0.0.2' },
      });
      await lastValueFrom(
        interceptor.intercept(ctx, { handle: () => of({ id: '1' }) } as any),
      );
      expect(auditService.record).toHaveBeenCalledWith(
        expect.objectContaining({ ip: '10.0.0.1' }),
      );
    });
  });

  describe('extractTarget(通过 record 调用验证)', () => {
    beforeEach(() => {
      reflector.get.mockReturnValue('CREATE_APP');
    });

    it('返回值含 id 应作为 target', async () => {
      const ctx = buildContext({ user: { sub: 'dev-1' } });
      await lastValueFrom(
        interceptor.intercept(ctx, { handle: () => of({ id: 'app-1' }) } as any),
      );
      expect(auditService.record).toHaveBeenCalledWith(
        expect.objectContaining({ target: 'app-1' }),
      );
    });

    it('返回值含 batchId 应作为 target(无 id 时)', async () => {
      const ctx = buildContext({ user: { sub: 'dev-1' } });
      await lastValueFrom(
        interceptor.intercept(ctx, { handle: () => of({ batchId: 'batch-1' }) } as any),
      );
      expect(auditService.record).toHaveBeenCalledWith(
        expect.objectContaining({ target: 'batch-1' }),
      );
    });

    it('返回值无 id/batchId 应 target undefined', async () => {
      const ctx = buildContext({ user: { sub: 'dev-1' } });
      await lastValueFrom(
        interceptor.intercept(ctx, { handle: () => of({ success: true }) } as any),
      );
      expect(auditService.record).toHaveBeenCalledWith(
        expect.objectContaining({ target: undefined }),
      );
    });

    it('返回值非对象应 target undefined', async () => {
      const ctx = buildContext({ user: { sub: 'dev-1' } });
      await lastValueFrom(
        interceptor.intercept(ctx, { handle: () => of('string-result') } as any),
      );
      expect(auditService.record).toHaveBeenCalledWith(
        expect.objectContaining({ target: undefined }),
      );
    });

    it('返回 null 应 target undefined', async () => {
      const ctx = buildContext({ user: { sub: 'dev-1' } });
      await lastValueFrom(
        interceptor.intercept(ctx, { handle: () => of(null) } as any),
      );
      expect(auditService.record).toHaveBeenCalledWith(
        expect.objectContaining({ target: undefined }),
      );
    });
  });

  describe('extractMeta(通过 record 调用验证)', () => {
    beforeEach(() => {
      reflector.get.mockReturnValue('GENERATE_CARDS');
    });

    it('应记录 method + body 的非敏感字段(type/count)', async () => {
      const ctx = buildContext({
        user: { sub: 'dev-1' },
        method: 'POST',
        body: { type: 'MONTH', count: 5, name: '月卡' },
      });
      await lastValueFrom(
        interceptor.intercept(ctx, { handle: () => of({ batchId: 'b1', count: 5 }) } as any),
      );
      const call = auditService.record.mock.calls[0][0];
      expect(call.meta).toEqual({
        method: 'POST',
        type: 'MONTH',
        count: 5,
        name: '月卡',
        resultCount: 5,
      });
    });

    it('应记录 packageName(创建应用时)', async () => {
      reflector.get.mockReturnValue('CREATE_APP');
      const ctx = buildContext({
        user: { sub: 'dev-1' },
        method: 'POST',
        body: { name: '我的应用', packageName: 'com.xcj.test' },
      });
      await lastValueFrom(
        interceptor.intercept(ctx, { handle: () => of({ id: 'app-1' }) } as any),
      );
      const call = auditService.record.mock.calls[0][0];
      expect(call.meta.name).toBe('我的应用');
      expect(call.meta.packageName).toBe('com.xcj.test');
    });

    it('body 缺失应只记录 method', async () => {
      const ctx = buildContext({
        user: { sub: 'dev-1' },
        method: 'POST',
        body: {},
      });
      await lastValueFrom(
        interceptor.intercept(ctx, { handle: () => of({ id: '1' }) } as any),
      );
      const call = auditService.record.mock.calls[0][0];
      expect(call.meta).toEqual({ method: 'POST' });
    });

    it('body 非对象应只记录 method', async () => {
      const ctx = buildContext({
        user: { sub: 'dev-1' },
        method: 'POST',
        body: 'invalid',
      });
      await lastValueFrom(
        interceptor.intercept(ctx, { handle: () => of({ id: '1' }) } as any),
      );
      const call = auditService.record.mock.calls[0][0];
      expect(call.meta).toEqual({ method: 'POST' });
    });

    it('敏感字段(password/cardKey)不应进入 meta', async () => {
      const ctx = buildContext({
        user: { sub: 'dev-1' },
        method: 'POST',
        body: { password: 'secret123', cardKey: 'ABCD-EFGH-IJKL-MNOP', name: 'test' },
      });
      await lastValueFrom(
        interceptor.intercept(ctx, { handle: () => of({ id: '1' }) } as any),
      );
      const call = auditService.record.mock.calls[0][0];
      expect(call.meta).not.toHaveProperty('password');
      expect(call.meta).not.toHaveProperty('cardKey');
    });
  });

  describe('Observable 透传', () => {
    it('应原样返回 handler 的结果', async () => {
      reflector.get.mockReturnValue('TEST');
      const ctx = buildContext({ user: { sub: 'dev-1' } });
      const expectedResult = { id: 'x', data: [1, 2, 3] };
      const result = await lastValueFrom(
        interceptor.intercept(ctx, { handle: () => of(expectedResult) } as any),
      );
      expect(result).toBe(expectedResult);
    });

    it('无装饰器时应原样透传', async () => {
      reflector.get.mockReturnValue(undefined);
      const ctx = buildContext();
      const result = await lastValueFrom(
        interceptor.intercept(ctx, { handle: () => of('ok') } as any),
      );
      expect(result).toBe('ok');
    });
  });
});
