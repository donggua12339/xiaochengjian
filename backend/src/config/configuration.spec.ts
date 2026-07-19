/**
 * configuration.ts 单元测试
 *
 * 覆盖:
 *  - appConfig() 从环境变量读取(默认值 + 自定义值)
 *  - validate() 校验通过(开发 + 生产)
 *  - validate() 校验失败(缺失必填 / 类型错 / 范围超)
 *  - 生产环境额外检查(JWT 密钥强度 + 默认值检测)
 */

// 必须在 import configuration 之前加载 reflect-metadata
// (class-validator + class-transformer 依赖 Reflect.getMetadata,但 NestJS main.ts 才全局 import,
// 单测直接 import configuration 不会触发,需显式加载)
import 'reflect-metadata';

describe('configuration', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    // 每个测试前重置环境变量
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  describe('appConfig', () => {
    let appConfig: typeof import('./configuration').appConfig;

    beforeEach(async () => {
      jest.resetModules();
      ({ appConfig } = await import('./configuration'));
    });

    it('无环境变量时使用默认值', () => {
      // 清空所有相关环境变量
      delete process.env.NODE_ENV;
      delete process.env.PORT;
      delete process.env.DATABASE_URL;
      delete process.env.REDIS_HOST;
      delete process.env.REDIS_PORT;
      delete process.env.REDIS_DB;
      delete process.env.JWT_ACCESS_SECRET;
      delete process.env.JWT_REFRESH_SECRET;

      const config = appConfig();
      expect(config.nodeEnv).toBe('development');
      expect(config.port).toBe(3000);
      expect(config.redisHost).toBe('localhost');
      expect(config.redisPort).toBe(6379);
      expect(config.redisDb).toBe(0);
      expect(config.jwtAccessSecret).toContain('dev-access-secret');
      expect(config.jwtRefreshSecret).toContain('dev-refresh-secret');
      expect(config.totpIssuer).toBe('Xiaochengjian');
      expect(config.totpAlgorithm).toBe('sha1');
      expect(config.totpDigits).toBe(6);
      expect(config.totpStep).toBe(30);
      expect(config.sdkSessionTtl).toBe(3600);
      expect(config.rateLimitIpPerMinute).toBe(60);
      expect(config.rateLimitDevicePerMinute).toBe(30);
      expect(config.rateLimitFailLockThreshold).toBe(5);
      expect(config.rateLimitFailLockTtl).toBe(3600);
      expect(config.offlineCacheDefaultDays).toBe(7);
      expect(config.offlineCacheMaxDays).toBe(30);
      expect(config.cardKeyBatchMax).toBe(10000);
      expect(config.logLevel).toBe('info');
      expect(config.corsOrigins).toEqual(['http://localhost:5173']);
      expect(config.adminWebUrl).toBe('http://localhost:5173');
    });

    it('从环境变量读取自定义值', () => {
      process.env.NODE_ENV = 'production';
      process.env.PORT = '8080';
      process.env.DATABASE_URL = 'postgresql://user:pass@host:5432/db';
      process.env.REDIS_HOST = 'redis-host';
      process.env.REDIS_PORT = '6380';
      process.env.REDIS_PASSWORD = 'redis-pass';
      process.env.REDIS_DB = '1';
      process.env.JWT_ACCESS_SECRET = 'a'.repeat(32);
      process.env.JWT_REFRESH_SECRET = 'b'.repeat(32);
      process.env.JWT_ACCESS_EXPIRES_IN = '30m';
      process.env.JWT_REFRESH_EXPIRES_IN = '14d';
      process.env.TOTP_ISSUER = 'TestIssuer';
      process.env.CORS_ORIGINS = 'https://a.com,https://b.com';
      process.env.ADMIN_WEB_URL = 'https://admin.example.com';

      const config = appConfig();
      expect(config.nodeEnv).toBe('production');
      expect(config.port).toBe(8080);
      expect(config.databaseUrl).toBe('postgresql://user:pass@host:5432/db');
      expect(config.redisHost).toBe('redis-host');
      expect(config.redisPort).toBe(6380);
      expect(config.redisPassword).toBe('redis-pass');
      expect(config.redisDb).toBe(1);
      expect(config.jwtAccessSecret).toBe('a'.repeat(32));
      expect(config.jwtRefreshSecret).toBe('b'.repeat(32));
      expect(config.jwtAccessExpiresIn).toBe('30m');
      expect(config.jwtRefreshExpiresIn).toBe('14d');
      expect(config.totpIssuer).toBe('TestIssuer');
      expect(config.corsOrigins).toEqual(['https://a.com', 'https://b.com']);
      expect(config.adminWebUrl).toBe('https://admin.example.com');
    });

    it('CORS_ORIGINS 单个值时返回单元素数组', () => {
      process.env.CORS_ORIGINS = 'https://only.com';
      const config = appConfig();
      expect(config.corsOrigins).toEqual(['https://only.com']);
    });

    it('PORT 非法时 parseInt 返回 NaN', () => {
      process.env.PORT = 'not-a-number';
      const config = appConfig();
      expect(Number.isNaN(config.port)).toBe(true);
    });
  });

  describe('validate', () => {
    let validate: typeof import('./configuration').validate;

    beforeEach(async () => {
      jest.resetModules();
      ({ validate } = await import('./configuration'));
    });

    const setValidDevConfig = () => {
      process.env.NODE_ENV = 'development';
      process.env.PORT = '3000';
      process.env.DATABASE_URL = 'postgresql://user:pass@host:5432/db';
      process.env.REDIS_HOST = 'localhost';
      process.env.REDIS_PORT = '6379';
      process.env.REDIS_PASSWORD = 'pass';
      process.env.REDIS_DB = '0';
      process.env.JWT_ACCESS_SECRET = 'dev-access-secret-change-in-production';
      process.env.JWT_REFRESH_SECRET = 'dev-refresh-secret-change-in-production';
    };

    it('开发环境:合法配置应通过校验', () => {
      setValidDevConfig();
      expect(() => validate({})).not.toThrow();
    });

    it('PORT 超范围应拒绝(> 65535)', () => {
      setValidDevConfig();
      process.env.PORT = '70000';
      expect(() => validate({})).toThrow(/配置校验失败/);
    });

    it('PORT 为 0 应拒绝', () => {
      setValidDevConfig();
      process.env.PORT = '0';
      expect(() => validate({})).toThrow(/配置校验失败/);
    });

    it('REDIS_PORT 超范围应拒绝', () => {
      setValidDevConfig();
      process.env.REDIS_PORT = '99999';
      expect(() => validate({})).toThrow(/配置校验失败/);
    });

    it('TOTP_DIGITS 非整数应拒绝', () => {
      setValidDevConfig();
      process.env.TOTP_DIGITS = 'abc';
      expect(() => validate({})).toThrow();
    });

    it('生产环境:JWT_ACCESS_SECRET 含 dev-access-secret 应拒绝', () => {
      setValidDevConfig();
      process.env.NODE_ENV = 'production';
      process.env.JWT_ACCESS_SECRET = 'dev-access-secret-change-in-production';
      process.env.JWT_REFRESH_SECRET = 'b'.repeat(32);
      expect(() => validate({})).toThrow(/JWT_ACCESS_SECRET 必须修改/);
    });

    it('生产环境:JWT_REFRESH_SECRET 含 dev-refresh-secret 应拒绝', () => {
      setValidDevConfig();
      process.env.NODE_ENV = 'production';
      process.env.JWT_ACCESS_SECRET = 'a'.repeat(32);
      process.env.JWT_REFRESH_SECRET = 'dev-refresh-secret-change-in-production';
      expect(() => validate({})).toThrow(/JWT_REFRESH_SECRET 必须修改/);
    });

    it('生产环境:JWT_ACCESS_SECRET < 32 字符应拒绝', () => {
      setValidDevConfig();
      process.env.NODE_ENV = 'production';
      process.env.JWT_ACCESS_SECRET = 'short';
      process.env.JWT_REFRESH_SECRET = 'b'.repeat(32);
      expect(() => validate({})).toThrow(/JWT_ACCESS_SECRET 至少 32 字符/);
    });

    it('生产环境:JWT_REFRESH_SECRET < 32 字符应拒绝', () => {
      setValidDevConfig();
      process.env.NODE_ENV = 'production';
      process.env.JWT_ACCESS_SECRET = 'a'.repeat(32);
      process.env.JWT_REFRESH_SECRET = 'short';
      expect(() => validate({})).toThrow(/JWT_REFRESH_SECRET 至少 32 字符/);
    });

    it('生产环境:合法强密钥应通过', () => {
      setValidDevConfig();
      process.env.NODE_ENV = 'production';
      process.env.JWT_ACCESS_SECRET = 'a'.repeat(32);
      process.env.JWT_REFRESH_SECRET = 'b'.repeat(32);
      // 水印 AES-256 密钥(32 字节 hex = 64 字符,ADR 0030 §c)
      process.env.WATERMARK_AES_KEY = 'c'.repeat(64);
      expect(() => validate({})).not.toThrow();
    });

    it('生产环境:WATERMARK_AES_KEY 非 64 字符应拒绝', () => {
      setValidDevConfig();
      process.env.NODE_ENV = 'production';
      process.env.JWT_ACCESS_SECRET = 'a'.repeat(32);
      process.env.JWT_REFRESH_SECRET = 'b'.repeat(32);
      process.env.WATERMARK_AES_KEY = 'short';
      expect(() => validate({})).toThrow(/WATERMARK_AES_KEY/);
    });

    it('开发环境:JWT 默认密钥允许通过(豁免)', () => {
      setValidDevConfig();
      process.env.NODE_ENV = 'development';
      process.env.JWT_ACCESS_SECRET = 'dev-access-secret-change-in-production';
      process.env.JWT_REFRESH_SECRET = 'dev-refresh-secret-change-in-production';
      expect(() => validate({})).not.toThrow();
    });

    it('NODE_ENV 非法值应拒绝', () => {
      setValidDevConfig();
      process.env.NODE_ENV = 'invalid-env';
      expect(() => validate({})).toThrow(/配置校验失败/);
    });

    it('返回的 config 是 AppConfig 实例(触发装饰器元数据)', () => {
      setValidDevConfig();
      const config = validate({});
      expect(config).toBeDefined();
      expect(config.nodeEnv).toBe('development');
      expect(typeof config.port).toBe('number');
      expect(Array.isArray(config.corsOrigins)).toBe(true);
    });
  });
});
