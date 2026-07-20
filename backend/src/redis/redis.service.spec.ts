import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';

// mock ioredis:在 RedisService 构造时返回我们的 mock client
const mockClient = {
  set: jest.fn().mockResolvedValue('OK'),
  get: jest.fn(),
  del: jest.fn().mockResolvedValue(1),
  exists: jest.fn(),
  incr: jest.fn().mockResolvedValue(5),
  pipeline: jest.fn(),
  quit: jest.fn().mockResolvedValue('OK'),
  on: jest.fn(),
};

jest.mock('ioredis', () => ({
  __esModule: true,
  default: jest.fn().mockImplementation(() => mockClient),
}));

// import 必须在 jest.mock 之后
// eslint-disable-next-line import/first
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
 *  - 构造时注册 connect / error 事件回调
 */
describe('RedisService', () => {
  let service: RedisService;

  beforeEach(async () => {
    jest.clearAllMocks();
    const moduleRef = await Test.createTestingModule({
      providers: [
        RedisService,
        {
          provide: ConfigService,
          useValue: {
            get: (key: string) => {
              const config: Record<string, unknown> = {
                redisHost: 'localhost',
                redisPort: 6379,
                redisPassword: '',
                redisDb: 0,
              };
              return config[key];
            },
          },
        },
      ],
    }).compile();
    service = moduleRef.get(RedisService);
  });

  it('构造时应注册 connect + error 事件回调', () => {
    expect(mockClient.on).toHaveBeenCalledWith('connect', expect.any(Function));
    expect(mockClient.on).toHaveBeenCalledWith('error', expect.any(Function));
  });

  it('set 带 TTL 应调 client.set(key, value, "EX", ttl)', async () => {
    await service.set('k', 'v', 60);
    expect(mockClient.set).toHaveBeenCalledWith('k', 'v', 'EX', 60);
  });

  it('set 不带 TTL 应调 client.set(key, value)', async () => {
    await service.set('k', 'v');
    expect(mockClient.set).toHaveBeenCalledWith('k', 'v');
  });

  it('set TTL=0 应调 client.set(key, value)(不传 EX)', async () => {
    await service.set('k', 'v', 0);
    expect(mockClient.set).toHaveBeenCalledWith('k', 'v');
  });

  it('set TTL 负数应调 client.set(key, value)(不传 EX)', async () => {
    await service.set('k', 'v', -1);
    expect(mockClient.set).toHaveBeenCalledWith('k', 'v');
  });

  it('get 应调 client.get', async () => {
    mockClient.get.mockResolvedValue('value');
    const result = await service.get('k');
    expect(mockClient.get).toHaveBeenCalledWith('k');
    expect(result).toBe('value');
  });

  it('del 应调 client.del', async () => {
    const result = await service.del('k');
    expect(mockClient.del).toHaveBeenCalledWith('k');
    expect(result).toBe(1);
  });

  it('exists 返回 1 时应返回 true', async () => {
    mockClient.exists.mockResolvedValue(1);
    const result = await service.exists('k');
    expect(result).toBe(true);
  });

  it('exists 返回 0 时应返回 false', async () => {
    mockClient.exists.mockResolvedValue(0);
    const result = await service.exists('k');
    expect(result).toBe(false);
  });

  it('incr 应调 client.incr', async () => {
    const result = await service.incr('k');
    expect(mockClient.incr).toHaveBeenCalledWith('k');
    expect(result).toBe(5);
  });

  it('incrWithTtl 应调 pipeline + incr + expire NX', async () => {
    const pipeline = {
      incr: jest.fn(),
      expire: jest.fn(),
      exec: jest.fn().mockResolvedValue([[null, 7], [null, 1]]),
    };
    mockClient.pipeline.mockReturnValue(pipeline);
    const result = await service.incrWithTtl('k', 60);
    expect(pipeline.incr).toHaveBeenCalledWith('k');
    expect(pipeline.expire).toHaveBeenCalledWith('k', 60, 'NX');
    expect(result).toBe(7);
  });

  it('onModuleDestroy 应调 client.quit', async () => {
    await service.onModuleDestroy();
    expect(mockClient.quit).toHaveBeenCalled();
  });
});
