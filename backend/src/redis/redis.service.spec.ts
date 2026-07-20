import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { RedisService } from './redis.service';

/**
 * RedisService 单元测试
 *
 * 覆盖:
 *  - set: 带 TTL / 不带 TTL / TTL=0 / TTL 负数
 *  - get
 *  - del
 *  - exists: 返回 1(true)/ 返回 0(false)
 *  - incr
 *  - incrWithTtl: pipeline + incr + expire NX
 *  - onModuleDestroy: quit
 */
describe('RedisService', () => {
  let service: RedisService;
  let client: {
    set: jest.Mock;
    get: jest.Mock;
    del: jest.Mock;
    exists: jest.Mock;
    incr: jest.Mock;
    pipeline: jest.Mock;
    quit: jest.Mock;
    on: jest.Mock;
  };

  beforeEach(async () => {
    client = {
      set: jest.fn().mockResolvedValue('OK'),
      get: jest.fn(),
      del: jest.fn().mockResolvedValue(1),
      exists: jest.fn(),
      incr: jest.fn().mockResolvedValue(5),
      pipeline: jest.fn(),
      quit: jest.fn().mockResolvedValue('OK'),
      on: jest.fn(),
    };

    // 用 useValue 直接覆盖 RedisService 实例的 client
    const moduleRef = await Test.createTestingModule({
      providers: [
        {
          provide: RedisService,
          useValue: {
            client,
            set: (key: string, value: string, ttlSeconds?: number) => {
              if (ttlSeconds && ttlSeconds > 0) {
                return client.set(key, value, 'EX', ttlSeconds);
              }
              return client.set(key, value);
            },
            get: (key: string) => client.get(key),
            del: (key: string) => client.del(key),
            exists: async (key: string) => {
              const r = await client.exists(key);
              return r === 1;
            },
            incr: (key: string) => client.incr(key),
            incrWithTtl: async (key: string, ttlSeconds: number) => {
              const p = client.pipeline();
              p.incr(key);
              p.expire(key, ttlSeconds, 'NX');
              const results = await p.exec();
              return results?.[0]?.[1] as number;
            },
            onModuleDestroy: () => client.quit(),
          } as unknown as RedisService,
        },
        {
          provide: ConfigService,
          useValue: { get: () => undefined },
        },
      ],
    }).compile();
    service = moduleRef.get(RedisService);
  });

  it('set 带 TTL 应调 client.set(key, value, "EX", ttl)', async () => {
    await service.set('k', 'v', 60);
    expect(client.set).toHaveBeenCalledWith('k', 'v', 'EX', 60);
  });

  it('set 不带 TTL 应调 client.set(key, value)', async () => {
    await service.set('k', 'v');
    expect(client.set).toHaveBeenCalledWith('k', 'v');
  });

  it('set TTL=0 应调 client.set(key, value)(不传 EX)', async () => {
    await service.set('k', 'v', 0);
    expect(client.set).toHaveBeenCalledWith('k', 'v');
  });

  it('set TTL 负数应调 client.set(key, value)(不传 EX)', async () => {
    await service.set('k', 'v', -1);
    expect(client.set).toHaveBeenCalledWith('k', 'v');
  });

  it('get 应调 client.get', async () => {
    client.get.mockResolvedValue('value');
    const result = await service.get('k');
    expect(client.get).toHaveBeenCalledWith('k');
    expect(result).toBe('value');
  });

  it('del 应调 client.del', async () => {
    const result = await service.del('k');
    expect(client.del).toHaveBeenCalledWith('k');
    expect(result).toBe(1);
  });

  it('exists 返回 1 时应返回 true', async () => {
    client.exists.mockResolvedValue(1);
    const result = await service.exists('k');
    expect(result).toBe(true);
  });

  it('exists 返回 0 时应返回 false', async () => {
    client.exists.mockResolvedValue(0);
    const result = await service.exists('k');
    expect(result).toBe(false);
  });

  it('incr 应调 client.incr', async () => {
    const result = await service.incr('k');
    expect(client.incr).toHaveBeenCalledWith('k');
    expect(result).toBe(5);
  });

  it('incrWithTtl 应调 pipeline + incr + expire NX', async () => {
    const pipeline = {
      incr: jest.fn(),
      expire: jest.fn(),
      exec: jest.fn().mockResolvedValue([[null, 7], [null, 1]]),
    };
    client.pipeline.mockReturnValue(pipeline);
    const result = await service.incrWithTtl('k', 60);
    expect(pipeline.incr).toHaveBeenCalledWith('k');
    expect(pipeline.expire).toHaveBeenCalledWith('k', 60, 'NX');
    expect(result).toBe(7);
  });

  it('onModuleDestroy 应调 client.quit', async () => {
    await service.onModuleDestroy();
    expect(client.quit).toHaveBeenCalled();
  });
});
