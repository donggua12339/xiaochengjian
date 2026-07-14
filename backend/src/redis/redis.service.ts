import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import type { AppConfig } from '../config/configuration';

/**
 * Redis 服务
 * 用于:
 *  - JWT refresh token 存储(可撤销,ADR 0027)
 *  - nonce 防重放(M1.8)
 *  - 限流计数器(M1.9)
 *  - 卡密验证结果缓存(M1.8)
 *
 * 详见 ADR 0007 (Redis)
 */
@Injectable()
export class RedisService implements OnModuleDestroy {
  private readonly logger = new Logger(RedisService.name);
  readonly client: Redis;

  constructor(configService: ConfigService<AppConfig, true>) {
    const host = configService.get('redisHost', { infer: true });
    const port = configService.get('redisPort', { infer: true });
    const password = configService.get('redisPassword', { infer: true }) || undefined;
    const db = configService.get('redisDb', { infer: true });

    this.client = new Redis({
      host,
      port,
      password,
      db,
      lazyConnect: false,
      maxRetriesPerRequest: 3,
      enableReadyCheck: true,
      retryStrategy: (times) => Math.min(times * 200, 2000),
    });

    this.client.on('connect', () => this.logger.log('Redis 连接已建立'));
    this.client.on('error', (err) => this.logger.error(`Redis 错误: ${err.message}`, err.stack));
  }

  async onModuleDestroy(): Promise<void> {
    await this.client.quit();
    this.logger.log('Redis 连接已关闭');
  }

  /**
   * 设置键值(带 TTL)
   */
  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    if (ttlSeconds && ttlSeconds > 0) {
      await this.client.set(key, value, 'EX', ttlSeconds);
    } else {
      await this.client.set(key, value);
    }
  }

  /**
   * 获取键值
   */
  async get(key: string): Promise<string | null> {
    return this.client.get(key);
  }

  /**
   * 删除键
   */
  async del(key: string): Promise<number> {
    return this.client.del(key);
  }

  /**
   * 检查键是否存在
   */
  async exists(key: string): Promise<boolean> {
    const result = await this.client.exists(key);
    return result === 1;
  }

  /**
   * 原子递增(用于限流计数)
   */
  async incr(key: string): Promise<number> {
    return this.client.incr(key);
  }

  /**
   * 带 TTL 的原子递增(首次递增时设置 TTL)
   */
  async incrWithTtl(key: string, ttlSeconds: number): Promise<number> {
    const pipeline = this.client.pipeline();
    pipeline.incr(key);
    pipeline.expire(key, ttlSeconds, 'NX'); // NX: 仅当 key 没有 TTL 时设置
    const results = await pipeline.exec();
    return results?.[0]?.[1] as number;
  }
}
