import { Test } from '@nestjs/testing';
import { RateLimitService } from './rate-limit.service';
import { RedisService } from '../redis/redis.service';

/**
 * RateLimitService 单元测试
 *
 * 覆盖:
 *  - checkIpRateLimit: 允许 / 超限 / retryAfter
 *  - checkDeviceRateLimit: 同上
 *  - checkFailLock: 未锁定(ttl=-2) / 已锁定(ttl>0) / 异常(ttl=-1)
 *  - recordFailure: 未达阈值 / 达到阈值触发锁定 + 清理 failCount
 *  - clearFailures
 *  - computeCardKeyDelay: 指数退避 500/1000/2000/4000 + 上限 30s
 */
describe('RateLimitService', () => {
  let service: RateLimitService;
  let redis: {
    incrWithTtl: jest.Mock;
    set: jest.Mock;
    del: jest.Mock;
    client: { ttl: jest.Mock };
  };

  beforeEach(async () => {
    redis = {
      incrWithTtl: jest.fn(),
      set: jest.fn().mockResolvedValue(undefined),
      del: jest.fn().mockResolvedValue(1),
      client: { ttl: jest.fn() },
    };
    const moduleRef = await Test.createTestingModule({
      providers: [
        RateLimitService,
        { provide: RedisService, useValue: redis },
      ],
    }).compile();
    service = moduleRef.get(RateLimitService);
  });

  describe('checkIpRateLimit', () => {
    it('未超限应返回 allowed=true + remaining', async () => {
      redis.incrWithTtl.mockResolvedValue(5);
      const result = await service.checkIpRateLimit('1.2.3.4', 60);
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(55);
      expect(redis.incrWithTtl).toHaveBeenCalledWith('rl:ip:1.2.3.4', 60);
    });

    it('超限应返回 allowed=false + retryAfter', async () => {
      redis.incrWithTtl.mockResolvedValue(61);
      redis.client.ttl.mockResolvedValue(45);
      const result = await service.checkIpRateLimit('1.2.3.4', 60);
      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
      expect(result.retryAfter).toBe(45);
    });

    it('超限但 ttl 异常时应返回 windowSeconds', async () => {
      redis.incrWithTtl.mockResolvedValue(61);
      redis.client.ttl.mockResolvedValue(-1); // 异常
      const result = await service.checkIpRateLimit('1.2.3.4', 60, 120);
      expect(result.allowed).toBe(false);
      expect(result.retryAfter).toBe(120);
    });
  });

  describe('checkDeviceRateLimit', () => {
    it('应使用 rl:device: 前缀', async () => {
      redis.incrWithTtl.mockResolvedValue(1);
      await service.checkDeviceRateLimit('machine-1', 30);
      expect(redis.incrWithTtl).toHaveBeenCalledWith('rl:device:machine-1', 60);
    });
  });

  describe('checkFailLock', () => {
    it('ttl=-2 表示未锁定', async () => {
      redis.client.ttl.mockResolvedValue(-2);
      const result = await service.checkFailLock('id1', 5, 3600);
      expect(result.locked).toBe(false);
    });

    it('ttl>0 表示已锁定,返回剩余秒数', async () => {
      redis.client.ttl.mockResolvedValue(1800);
      const result = await service.checkFailLock('id1', 5, 3600);
      expect(result.locked).toBe(true);
      expect(result.retryAfter).toBe(1800);
    });

    it('ttl=-1(异常)应返回 lockTtl 兜底', async () => {
      redis.client.ttl.mockResolvedValue(-1);
      const result = await service.checkFailLock('id1', 5, 3600);
      expect(result.locked).toBe(true);
      expect(result.retryAfter).toBe(3600);
    });
  });

  describe('recordFailure', () => {
    it('未达阈值应返回 locked=false + failCount', async () => {
      redis.incrWithTtl.mockResolvedValue(3);
      const result = await service.recordFailure('id1', 5, 3600);
      expect(result.locked).toBe(false);
      expect(result.failCount).toBe(3);
      // 不应设锁
      expect(redis.set).not.toHaveBeenCalled();
    });

    it('达到阈值应触发锁定 + 清理 failCount', async () => {
      redis.incrWithTtl.mockResolvedValue(5);
      const result = await service.recordFailure('id1', 5, 3600);
      expect(result.locked).toBe(true);
      expect(result.failCount).toBe(5);
      // 应设锁
      expect(redis.set).toHaveBeenCalledWith('rl:lock:id1', '1', 3600);
      // 应清理 failCount
      expect(redis.del).toHaveBeenCalledWith('rl:fail:id1');
    });

    it('超过阈值也应触发锁定(failCount > threshold)', async () => {
      redis.incrWithTtl.mockResolvedValue(10);
      const result = await service.recordFailure('id1', 5, 3600);
      expect(result.locked).toBe(true);
    });
  });

  describe('clearFailures', () => {
    it('应删除 rl:fail: 前缀的 key', async () => {
      await service.clearFailures('id1');
      expect(redis.del).toHaveBeenCalledWith('rl:fail:id1');
    });
  });

  describe('computeCardKeyDelay', () => {
    it('第 0 次失败应延迟 500ms', () => {
      expect(service.computeCardKeyDelay(0)).toBe(500);
    });

    it('第 1 次失败应延迟 1000ms', () => {
      expect(service.computeCardKeyDelay(1)).toBe(1000);
    });

    it('第 2 次失败应延迟 2000ms', () => {
      expect(service.computeCardKeyDelay(2)).toBe(2000);
    });

    it('第 3 次失败应延迟 4000ms', () => {
      expect(service.computeCardKeyDelay(3)).toBe(4000);
    });

    it('延迟应上限 30s', () => {
      // 500 * 2^10 = 512000 > 30000
      expect(service.computeCardKeyDelay(10)).toBe(30000);
      expect(service.computeCardKeyDelay(100)).toBe(30000);
    });
  });
});
