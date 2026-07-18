import { Test } from '@nestjs/testing';
import { ConfigModule } from '@nestjs/config';
import * as fs from 'fs';
import { SecurityCheckService } from './security-check.service';

/**
 * SecurityCheckService 单元测试
 *
 * 覆盖 10 项安全基线检查:
 *  - JWT access/refresh secret(强度 + 默认值检测)
 *  - DATABASE_URL(弱密码模式)
 *  - CORS(生产必须 https)
 *  - RATE_LIMIT(范围)
 *  - LOG_LEVEL(valid + 非 debug in production)
 *  - RSA_KEYS(文件存在)
 *  - TOTP_CONFIG(digits + step)
 *  - OFFLINE_CACHE(defaultDays + maxDays)
 *  - CARD_KEY_BATCH_MAX
 *
 * 用真实 ConfigModule 加载内存配置,避免 mock 复杂度
 */
describe('SecurityCheckService', () => {
  async function buildService(env: Record<string, unknown>): Promise<SecurityCheckService> {
    // 清空所有相关 env(避免上一个测试残留)
    const keysToClean = [
      'NODE_ENV', 'JWT_ACCESS_SECRET', 'JWT_REFRESH_SECRET', 'DATABASE_URL',
      'CORS_ORIGINS', 'RATE_LIMIT_IP_PER_MINUTE', 'RATE_LIMIT_DEVICE_PER_MINUTE',
      'RATE_LIMIT_FAIL_LOCK_THRESHOLD', 'LOG_LEVEL', 'RSA_PRIVATE_KEY_PATH',
      'RSA_PUBLIC_KEY_PATH', 'TOTP_DIGITS', 'TOTP_STEP', 'OFFLINE_CACHE_DEFAULT_DAYS',
      'OFFLINE_CACHE_MAX_DAYS', 'CARD_KEY_BATCH_MAX',
    ];
    for (const k of keysToClean) delete process.env[k];

    // 注入配置到 process.env(configuration.ts 从 process.env 读)
    for (const [k, v] of Object.entries(env)) {
      if (typeof v === 'string') process.env[k] = v;
    }
    // CORS_ORIGINS 是数组,转逗号分隔
    if (Array.isArray(env.corsOrigins)) {
      process.env.CORS_ORIGINS = env.corsOrigins.join(',');
    }
    const moduleRef = Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          load: [() => env],
        }),
      ],
      providers: [SecurityCheckService],
    });
    const compiled = await moduleRef.compile();
    return compiled.get(SecurityCheckService);
  }

  /** 构建完整通过的 production 配置 */
  function buildPassingConfig(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      nodeEnv: 'production',
      jwtAccessSecret: 'a'.repeat(64),
      jwtRefreshSecret: 'b'.repeat(64),
      databaseUrl: 'postgresql://xcj_dba:strongRandomSecret789@host:5432/db',
      corsOrigins: ['https://xcj.winmelon.cn'],
      rateLimitIpPerMinute: 60,
      rateLimitDevicePerMinute: 30,
      rateLimitFailLockThreshold: 5,
      logLevel: 'info',
      rsaPrivateKeyPath: './keys/private.pem',
      rsaPublicKeyPath: './keys/public.pem',
      totpDigits: 6,
      totpStep: 30,
      offlineCacheDefaultDays: 7,
      offlineCacheMaxDays: 30,
      cardKeyBatchMax: 10000,
      ...overrides,
    };
  }

  describe('生产环境(production)完整通过', () => {
    it('应通过 10/10 检查', async () => {
      const svc = await buildService(buildPassingConfig());
      await expect(svc.onModuleInit()).resolves.toBeUndefined();
    });
  });

  describe('JWT secret 检查', () => {
    it('生产环境默认 secret 应失败(dev-access-secret)', async () => {
      const svc = await buildService(
        buildPassingConfig({ jwtAccessSecret: 'dev-access-secret-xxx' }),
      );
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });

    it('生产环境默认 secret 应失败(dev-refresh-secret)', async () => {
      const svc = await buildService(
        buildPassingConfig({ jwtRefreshSecret: 'dev-refresh-secret-xxx' }),
      );
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });

    it('生产环境 secret < 32 字符应失败', async () => {
      const svc = await buildService(buildPassingConfig({ jwtAccessSecret: 'short' }));
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });

    it('开发环境短 secret 应通过(不检查)', async () => {
      const svc = await buildService(
        buildPassingConfig({ nodeEnv: 'development', jwtAccessSecret: 'short' }),
      );
      await expect(svc.onModuleInit()).resolves.toBeUndefined();
    });
  });

  describe('DATABASE_URL 检查', () => {
    it('含 changeme 应失败', async () => {
      const svc = await buildService(
        buildPassingConfig({
          databaseUrl: 'postgresql://user:changeme@host/db',
        }),
      );
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });

    it('含 password 应失败', async () => {
      const svc = await buildService(
        buildPassingConfig({
          databaseUrl: 'postgresql://user:password123@host/db',
        }),
      );
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });

    it('含 123456 应失败', async () => {
      const svc = await buildService(
        buildPassingConfig({
          databaseUrl: 'postgresql://user:123456@host/db',
        }),
      );
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });

    it('含 admin 应失败', async () => {
      const svc = await buildService(
        buildPassingConfig({
          databaseUrl: 'postgresql://user:admin@host/db',
        }),
      );
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });

    it('开发环境弱密码应通过', async () => {
      const svc = await buildService(
        buildPassingConfig({
          nodeEnv: 'development',
          databaseUrl: 'postgresql://user:password@host/db',
        }),
      );
      await expect(svc.onModuleInit()).resolves.toBeUndefined();
    });
  });

  describe('CORS 检查', () => {
    it('生产环境 http origin 应失败', async () => {
      const svc = await buildService(
        buildPassingConfig({
          corsOrigins: ['http://localhost', 'https://xcj.winmelon.cn'],
        }),
      );
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });

    it('开发环境 http origin 应通过', async () => {
      const svc = await buildService(
        buildPassingConfig({
          nodeEnv: 'development',
          corsOrigins: ['http://localhost'],
        }),
      );
      await expect(svc.onModuleInit()).resolves.toBeUndefined();
    });

    it('空 corsOrigins 应失败', async () => {
      const svc = await buildService(buildPassingConfig({ corsOrigins: [] }));
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });
  });

  describe('RATE_LIMIT 检查', () => {
    it('ip <= 0 应失败', async () => {
      const svc = await buildService(buildPassingConfig({ rateLimitIpPerMinute: 0 }));
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });

    it('ip > 1000 应失败', async () => {
      const svc = await buildService(buildPassingConfig({ rateLimitIpPerMinute: 1500 }));
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });

    it('device > 500 应失败', async () => {
      const svc = await buildService(buildPassingConfig({ rateLimitDevicePerMinute: 600 }));
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });

    it('threshold <= 0 应失败', async () => {
      const svc = await buildService(buildPassingConfig({ rateLimitFailLockThreshold: 0 }));
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });
  });

  describe('LOG_LEVEL 检查', () => {
    it('无效级别应失败', async () => {
      const svc = await buildService(buildPassingConfig({ logLevel: 'invalid' }));
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });

    it('生产环境 debug 应失败', async () => {
      const svc = await buildService(buildPassingConfig({ logLevel: 'debug' }));
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });

    it('开发环境 debug 应通过', async () => {
      const svc = await buildService(
        buildPassingConfig({ nodeEnv: 'development', logLevel: 'debug' }),
      );
      await expect(svc.onModuleInit()).resolves.toBeUndefined();
    });
  });

  describe('RSA_KEYS 检查', () => {
    it('私钥文件不存在应失败', async () => {
      const svc = await buildService(
        buildPassingConfig({ rsaPrivateKeyPath: '/nonexistent/private.pem' }),
      );
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });

    it('公钥文件不存在应失败', async () => {
      const svc = await buildService(
        buildPassingConfig({ rsaPublicKeyPath: '/nonexistent/public.pem' }),
      );
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });

    it('存在的 keys 应通过', async () => {
      // 用 backend/keys/(实际存在)
      const exists = fs.existsSync('./keys/private.pem') && fs.existsSync('./keys/public.pem');
      if (!exists) {
        // CI 环境可能没 keys,跳过
        return;
      }
      const svc = await buildService(buildPassingConfig());
      await expect(svc.onModuleInit()).resolves.toBeUndefined();
    });
  });

  describe('TOTP_CONFIG 检查', () => {
    it('digits 非 6/8 应失败', async () => {
      const svc = await buildService(buildPassingConfig({ totpDigits: 7 }));
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });

    it('digits = 8 应通过', async () => {
      const svc = await buildService(buildPassingConfig({ totpDigits: 8 }));
      await expect(svc.onModuleInit()).resolves.toBeUndefined();
    });

    it('step < 15 应失败', async () => {
      const svc = await buildService(buildPassingConfig({ totpStep: 10 }));
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });

    it('step > 120 应失败', async () => {
      const svc = await buildService(buildPassingConfig({ totpStep: 200 }));
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });
  });

  describe('OFFLINE_CACHE 检查', () => {
    it('defaultDays < 1 应失败', async () => {
      const svc = await buildService(buildPassingConfig({ offlineCacheDefaultDays: 0 }));
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });

    it('defaultDays > maxDays 应失败', async () => {
      const svc = await buildService(
        buildPassingConfig({ offlineCacheDefaultDays: 40, offlineCacheMaxDays: 30 }),
      );
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });

    it('maxDays > 90 应失败', async () => {
      const svc = await buildService(buildPassingConfig({ offlineCacheMaxDays: 120 }));
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });
  });

  describe('CARD_KEY_BATCH_MAX 检查', () => {
    it('< 1 应失败', async () => {
      const svc = await buildService(buildPassingConfig({ cardKeyBatchMax: 0 }));
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });

    it('> 100000 应失败', async () => {
      const svc = await buildService(buildPassingConfig({ cardKeyBatchMax: 200000 }));
      await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
    });
  });

  describe('开发环境(dev)整体通过', () => {
    it('dev 环境弱配置应通过(不检查严格规则)', async () => {
      const svc = await buildService({
        nodeEnv: 'development',
        jwtAccessSecret: 'dev',
        jwtRefreshSecret: 'dev',
        databaseUrl: 'postgresql://user:password@host/db',
        corsOrigins: ['http://localhost'],
        rateLimitIpPerMinute: 60,
        rateLimitDevicePerMinute: 30,
        rateLimitFailLockThreshold: 5,
        logLevel: 'debug',
        rsaPrivateKeyPath: './keys/private.pem',
        rsaPublicKeyPath: './keys/public.pem',
        totpDigits: 6,
        totpStep: 30,
        offlineCacheDefaultDays: 7,
        offlineCacheMaxDays: 30,
        cardKeyBatchMax: 10000,
      });
      // dev 模式下 RSA_KEYS 仍检查(不区分 dev/prod)
      const keysExist = fs.existsSync('./keys/private.pem') && fs.existsSync('./keys/public.pem');
      if (keysExist) {
        await expect(svc.onModuleInit()).resolves.toBeUndefined();
      } else {
        await expect(svc.onModuleInit()).rejects.toThrow('安全基线检查失败');
      }
    });
  });
});
