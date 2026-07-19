import { plainToInstance } from 'class-transformer';
import { IsEnum, IsInt, IsString, Min, Max, validateSync } from 'class-validator';

enum NodeEnv {
  Development = 'development',
  Test = 'test',
  Production = 'production',
}

export class AppConfig {
  @IsEnum(NodeEnv)
  nodeEnv!: NodeEnv;

  @IsInt()
  @Min(1)
  @Max(65535)
  port!: number;

  @IsString()
  databaseUrl!: string;

  @IsString()
  redisHost!: string;

  @IsInt()
  @Min(1)
  @Max(65535)
  redisPort!: number;

  @IsString()
  redisPassword!: string;

  @IsInt()
  @Min(0)
  redisDb!: number;

  @IsString()
  jwtAccessSecret!: string;

  @IsString()
  jwtRefreshSecret!: string;

  @IsString()
  jwtAccessExpiresIn!: string;

  @IsString()
  jwtRefreshExpiresIn!: string;

  @IsString()
  totpIssuer!: string;

  @IsString()
  totpAlgorithm!: string;

  @IsInt()
  totpDigits!: number;

  @IsInt()
  totpStep!: number;

  @IsString()
  rsaPrivateKeyPath!: string;

  @IsString()
  rsaPublicKeyPath!: string;

  @IsInt()
  sdkSessionTtl!: number;

  @IsInt()
  rateLimitIpPerMinute!: number;

  @IsInt()
  rateLimitDevicePerMinute!: number;

  @IsInt()
  rateLimitFailLockThreshold!: number;

  @IsInt()
  rateLimitFailLockTtl!: number;

  @IsInt()
  offlineCacheDefaultDays!: number;

  @IsInt()
  offlineCacheMaxDays!: number;

  @IsInt()
  cardKeyBatchMax!: number;

  @IsString()
  logLevel!: string;

  corsOrigins!: string[];

  @IsString()
  adminWebUrl!: string;

  // ============= OAuth(ADR 0074,可选)=============
  githubClientId?: string;
  githubClientSecret?: string;
  qqAppId?: string;
  qqAppKey?: string;
}

export const appConfig = (): AppConfig => ({
  nodeEnv: (process.env.NODE_ENV ?? 'development') as AppConfig['nodeEnv'],
  port: parseInt(process.env.PORT ?? '3000', 10),
  databaseUrl: process.env.DATABASE_URL ?? '',
  redisHost: process.env.REDIS_HOST ?? 'localhost',
  redisPort: parseInt(process.env.REDIS_PORT ?? '6379', 10),
  redisPassword: process.env.REDIS_PASSWORD ?? '',
  redisDb: parseInt(process.env.REDIS_DB ?? '0', 10),
  jwtAccessSecret: process.env.JWT_ACCESS_SECRET ?? 'dev-access-secret-change-in-production',
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET ?? 'dev-refresh-secret-change-in-production',
  jwtAccessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN ?? '15m',
  jwtRefreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN ?? '7d',
  totpIssuer: process.env.TOTP_ISSUER ?? 'Xiaochengjian',
  totpAlgorithm: process.env.TOTP_ALGORITHM ?? 'sha1',
  totpDigits: parseInt(process.env.TOTP_DIGITS ?? '6', 10),
  totpStep: parseInt(process.env.TOTP_STEP ?? '30', 10),
  rsaPrivateKeyPath: process.env.RSA_PRIVATE_KEY_PATH ?? './keys/private.pem',
  rsaPublicKeyPath: process.env.RSA_PUBLIC_KEY_PATH ?? './keys/public.pem',
  sdkSessionTtl: parseInt(process.env.SDK_SESSION_TTL ?? '3600', 10),
  rateLimitIpPerMinute: parseInt(process.env.RATE_LIMIT_IP_PER_MINUTE ?? '60', 10),
  rateLimitDevicePerMinute: parseInt(process.env.RATE_LIMIT_DEVICE_PER_MINUTE ?? '30', 10),
  rateLimitFailLockThreshold: parseInt(process.env.RATE_LIMIT_FAIL_LOCK_THRESHOLD ?? '5', 10),
  rateLimitFailLockTtl: parseInt(process.env.RATE_LIMIT_FAIL_LOCK_TTL ?? '3600', 10),
  offlineCacheDefaultDays: parseInt(process.env.OFFLINE_CACHE_DEFAULT_DAYS ?? '7', 10),
  offlineCacheMaxDays: parseInt(process.env.OFFLINE_CACHE_MAX_DAYS ?? '30', 10),
  cardKeyBatchMax: parseInt(process.env.CARD_KEY_BATCH_MAX ?? '10000', 10),
  logLevel: process.env.LOG_LEVEL ?? 'info',
  corsOrigins: (process.env.CORS_ORIGINS ?? 'http://localhost:5173').split(','),
  adminWebUrl: process.env.ADMIN_WEB_URL ?? 'http://localhost:5173',
  // OAuth(ADR 0074,可选,未配则 OAuth 接口拒绝)
  githubClientId: process.env.GITHUB_CLIENT_ID || undefined,
  githubClientSecret: process.env.GITHUB_CLIENT_SECRET || undefined,
  qqAppId: process.env.QQ_APP_ID || undefined,
  qqAppKey: process.env.QQ_APP_KEY || undefined,
});

export const validate = (_raw: unknown): AppConfig => {
  // 直接调 appConfig() 读 process.env(已处理大小写映射与类型转换)
  // 不依赖 raw 参数,因为 @nestjs/config 传入的 raw 是 process.env 快照(key 大写),
  // 而 AppConfig 属性是 camelCase,plainToInstance 不会自动映射
  // 再用 plainToInstance 把 plain object 转成 AppConfig 实例,触发 class-validator 装饰器元数据
  const config = plainToInstance(AppConfig, appConfig(), { enableImplicitConversion: true });
  const errors = validateSync(config, { skipMissingProperties: false });
  if (errors.length > 0) {
    const messages = errors.map((e) => Object.values(e.constraints ?? {}).join(', ')).join('; ');
    throw new Error(`配置校验失败: ${messages}`);
  }

  // 生产环境额外检查
  if (config.nodeEnv === NodeEnv.Production) {
    if (config.jwtAccessSecret.includes('dev-access-secret')) {
      throw new Error('生产环境 JWT_ACCESS_SECRET 必须修改');
    }
    if (config.jwtRefreshSecret.includes('dev-refresh-secret')) {
      throw new Error('生产环境 JWT_REFRESH_SECRET 必须修改');
    }
    if (config.jwtAccessSecret.length < 32) {
      throw new Error('生产环境 JWT_ACCESS_SECRET 至少 32 字符');
    }
    if (config.jwtRefreshSecret.length < 32) {
      throw new Error('生产环境 JWT_REFRESH_SECRET 至少 32 字符');
    }
  }

  return config;
};
