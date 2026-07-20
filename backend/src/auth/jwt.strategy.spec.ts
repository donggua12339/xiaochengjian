import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { UnauthorizedException } from '@nestjs/common';
import { JwtStrategy } from './jwt.strategy';

/**
 * JwtStrategy 单元测试
 *
 * 覆盖:
 *  - 构造:从 ConfigService 读 jwtAccessSecret
 *  - validate: payload 含 sub + email 返回 payload
 *  - validate: payload 缺 sub 抛 UnauthorizedException
 *  - validate: payload 缺 email 抛 UnauthorizedException
 */
describe('JwtStrategy', () => {
  let strategy: JwtStrategy;

  beforeEach(async () => {
    const moduleRef = await Test.createTestingModule({
      providers: [
        JwtStrategy,
        {
          provide: ConfigService,
          useValue: {
            get: (key: string) => {
              if (key === 'jwtAccessSecret') return 'test-secret-at-least-32-chars-long';
              return undefined;
            },
          },
        },
      ],
    }).compile();
    strategy = moduleRef.get(JwtStrategy);
  });

  it('应正确构造(从 ConfigService 读 secret)', () => {
    expect(strategy).toBeDefined();
  });

  it('validate: payload 含 sub + email 应返回 payload', async () => {
    const payload = { sub: 'dev-1', email: 'a@b.com', role: 'DEVELOPER' };
    const result = await strategy.validate(payload);
    expect(result).toEqual(payload);
  });

  it('validate: payload 缺 sub 应抛 UnauthorizedException', async () => {
    await expect(
      strategy.validate({ sub: '', email: 'a@b.com', role: 'DEVELOPER' }),
    ).rejects.toThrow(UnauthorizedException);
  });

  it('validate: payload 缺 email 应抛 UnauthorizedException', async () => {
    await expect(
      strategy.validate({ sub: 'dev-1', email: '', role: 'DEVELOPER' }),
    ).rejects.toThrow(UnauthorizedException);
  });

  it('validate: payload 缺 sub + email 应抛 UnauthorizedException', async () => {
    await expect(
      strategy.validate({ sub: '', email: '', role: 'DEVELOPER' }),
    ).rejects.toThrow(UnauthorizedException);
  });
});
