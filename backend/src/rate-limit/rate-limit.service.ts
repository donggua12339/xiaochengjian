import { Injectable, Logger } from '@nestjs/common';
import { RedisService } from '../redis/redis.service';

/**
 * 限流服务
 * 详见 ADR 0022 (服务端防爆破)
 *
 * 四层防护:
 *  1. IP 限流:同 IP 每分钟 N 次(默认 60)
 *  2. 设备指纹限流:同 machineId 每分钟 N 次(默认 30)
 *  3. 失败次数锁定:同设备/IP 连续失败 N 次锁 1 小时
 *  4. 卡密错误延迟:指数退避(0.5s -> 1s -> 2s -> 4s...)
 */
@Injectable()
export class RateLimitService {
  private readonly logger = new Logger(RateLimitService.name);

  constructor(private readonly redis: RedisService) {}

  /**
   * 检查 IP 限流
   * @returns { allowed, remaining, retryAfter }
   */
  async checkIpRateLimit(
    ip: string,
    limit: number,
    windowSeconds = 60,
  ): Promise<{ allowed: boolean; remaining: number; retryAfter?: number }> {
    const key = `rl:ip:${ip}`;
    return this.checkRateLimit(key, limit, windowSeconds);
  }

  /**
   * 检查设备指纹限流
   */
  async checkDeviceRateLimit(
    machineId: string,
    limit: number,
    windowSeconds = 60,
  ): Promise<{ allowed: boolean; remaining: number; retryAfter?: number }> {
    const key = `rl:device:${machineId}`;
    return this.checkRateLimit(key, limit, windowSeconds);
  }

  /**
   * 检查失败锁定
   * @returns { locked, retryAfter } locked=true 表示已锁定
   *
   * 用单次 TTL 调用判断,避免 exists + ttl 双调用之间的竞态(锁过期):
   *  - ttl === -2: key 不存在(未锁定)
   *  - ttl === -1: key 存在但无 TTL(异常情况,用 lockTtl 兜底)
   *  - ttl > 0: 剩余锁定秒数
   */
  async checkFailLock(
    identifier: string,
    threshold: number,
    lockTtl: number,
  ): Promise<{ locked: boolean; retryAfter?: number }> {
    // threshold 在 recordFailure 中使用(达到阈值才设锁);
    // checkFailLock 只检查锁是否已存在,不需要 threshold,但保留参数以统一调用接口
    void threshold;
    const lockKey = `rl:lock:${identifier}`;
    const ttl = await this.redis.client.ttl(lockKey);
    if (ttl === -2) {
      return { locked: false };
    }
    return { locked: true, retryAfter: ttl > 0 ? ttl : lockTtl };
  }

  /**
   * 记录失败(达到阈值则锁定)
   * @returns { locked, failCount } locked=true 表示本次失败触发了锁定
   */
  async recordFailure(
    identifier: string,
    threshold: number,
    lockTtl: number,
  ): Promise<{ locked: boolean; failCount: number }> {
    const failKey = `rl:fail:${identifier}`;
    const failCount = await this.redis.incrWithTtl(failKey, lockTtl);

    if (failCount >= threshold) {
      const lockKey = `rl:lock:${identifier}`;
      await this.redis.set(lockKey, '1', lockTtl);
      await this.redis.del(failKey);
      this.logger.warn(`失败锁定触发: ${identifier} (连续失败 ${failCount} 次,锁定 ${lockTtl}s)`);
      return { locked: true, failCount };
    }

    return { locked: false, failCount };
  }

  /**
   * 清除失败计数(成功时调用)
   */
  async clearFailures(identifier: string): Promise<void> {
    await this.redis.del(`rl:fail:${identifier}`);
  }

  /**
   * 卡密错误延迟(指数退避)
   * @param failCount 当前失败次数(0 = 第一次)
   * @returns 延迟毫秒数
   *
   * 第 1 次失败: 500ms
   * 第 2 次: 1000ms
   * 第 3 次: 2000ms
   * 第 4 次: 4000ms
   * ...上限 30s
   */
  computeCardKeyDelay(failCount: number): number {
    const delay = Math.min(500 * Math.pow(2, failCount), 30000);
    return delay;
  }

  /**
   * 通用限流检查(slide window 用 Redis INCR + EXPIRE)
   */
  private async checkRateLimit(
    key: string,
    limit: number,
    windowSeconds: number,
  ): Promise<{ allowed: boolean; remaining: number; retryAfter?: number }> {
    const count = await this.redis.incrWithTtl(key, windowSeconds);
    if (count > limit) {
      const ttl = await this.redis.client.ttl(key);
      return {
        allowed: false,
        remaining: 0,
        retryAfter: ttl > 0 ? ttl : windowSeconds,
      };
    }
    return { allowed: true, remaining: limit - count };
  }
}
