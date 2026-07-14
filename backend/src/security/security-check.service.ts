import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs';
import type { AppConfig } from '../config/configuration';

/**
 * 安全基线检查服务
 * 详见 ADR 0027 (服务端安全基线)
 *
 * 启动时检查 10 项安全基线,不达标拒绝启动
 * 不提供跳过开关(否则等于没检查)
 *
 * 检查项:
 *  1. JWT access secret 强度(生产 ≥ 32 字符,不含默认值)
 *  2. JWT refresh secret 强度(同上)
 *  3. DB 密码强度(生产不含 changeme/dev_only)
 *  4. CORS 配置(生产必须 https)
 *  5. 限流配置(生产必须启用)
 *  6. 日志级别(生产不应为 debug)
 *  7. RSA 密钥文件存在
 *  8. 2FA 配置(TOTP 参数合理)
 *  9. 离线缓存配置(1-30 天)
 *  10. 卡密批量上限(合理范围)
 */
@Injectable()
export class SecurityCheckService implements OnModuleInit {
  private readonly logger = new Logger(SecurityCheckService.name);

  constructor(private readonly configService: ConfigService<AppConfig, true>) {}

  async onModuleInit(): Promise<void> {
    const isProduction = this.configService.get('nodeEnv', { infer: true }) === 'production';

    const checks: Array<{ name: string; passed: boolean; detail?: string }> = [
      this.checkJwtSecret('JWT_ACCESS_SECRET', 'jwtAccessSecret', isProduction),
      this.checkJwtSecret('JWT_REFRESH_SECRET', 'jwtRefreshSecret', isProduction),
      this.checkDbPassword(isProduction),
      this.checkCors(isProduction),
      this.checkRateLimit(),
      this.checkLogLevel(isProduction),
      this.checkRsaKeys(),
      this.checkTotpConfig(),
      this.checkOfflineCache(),
      this.checkCardKeyBatchMax(),
    ];

    const failures = checks.filter((c) => !c.passed);

    if (failures.length > 0) {
      this.logger.error('========================================');
      this.logger.error('安全基线检查失败,拒绝启动');
      this.logger.error('========================================');
      for (const f of failures) {
        this.logger.error(`[FAIL] ${f.name}${f.detail ? ': ' + f.detail : ''}`);
      }
      this.logger.error('');
      this.logger.error('修复后重试。不提供跳过开关(ADR 0027)。');
      throw new Error(`安全基线检查失败: ${failures.map((f) => f.name).join(', ')}`);
    }

    this.logger.log('========================================');
    this.logger.log('安全基线检查通过(10/10)');
    this.logger.log('========================================');
    for (const c of checks) {
      this.logger.log(`[OK] ${c.name}`);
    }
  }

  private checkJwtSecret(
    name: string,
    key: 'jwtAccessSecret' | 'jwtRefreshSecret',
    isProduction: boolean,
  ): { name: string; passed: boolean; detail?: string } {
    const secret = this.configService.get(key, { infer: true });

    if (!secret) {
      return { name, passed: false, detail: '未设置' };
    }

    if (isProduction) {
      if (secret.includes('dev-access-secret') || secret.includes('dev-refresh-secret')) {
        return { name, passed: false, detail: '生产环境使用默认 secret' };
      }
      if (secret.length < 32) {
        return { name, passed: false, detail: `生产环境至少 32 字符(当前 ${secret.length})` };
      }
    }

    return { name, passed: true };
  }

  private checkDbPassword(isProduction: boolean): {
    name: string;
    passed: boolean;
    detail?: string;
  } {
    const dbUrl = this.configService.get('databaseUrl', { infer: true });

    if (!dbUrl) {
      return { name: 'DATABASE_URL', passed: false, detail: '未设置' };
    }

    if (isProduction) {
      const weakPatterns = ['changeme', 'dev_only', 'password', '123456', 'admin'];
      const lower = dbUrl.toLowerCase();
      for (const pattern of weakPatterns) {
        if (lower.includes(pattern)) {
          return {
            name: 'DATABASE_URL',
            passed: false,
            detail: `生产环境密码含弱模式 "${pattern}"`,
          };
        }
      }
    }

    return { name: 'DATABASE_URL', passed: true };
  }

  private checkCors(isProduction: boolean): { name: string; passed: boolean; detail?: string } {
    const origins = this.configService.get('corsOrigins', { infer: true });

    if (!origins || origins.length === 0) {
      return { name: 'CORS_ORIGINS', passed: false, detail: '未设置' };
    }

    if (isProduction) {
      const httpOrigins = origins.filter((o) => o.startsWith('http://'));
      if (httpOrigins.length > 0) {
        return {
          name: 'CORS_ORIGINS',
          passed: false,
          detail: `生产环境必须 https: ${httpOrigins.join(', ')}`,
        };
      }
    }

    return { name: 'CORS_ORIGINS', passed: true };
  }

  private checkRateLimit(): { name: string; passed: boolean; detail?: string } {
    const ip = this.configService.get('rateLimitIpPerMinute', { infer: true });
    const device = this.configService.get('rateLimitDevicePerMinute', { infer: true });
    const threshold = this.configService.get('rateLimitFailLockThreshold', { infer: true });

    if (ip <= 0 || device <= 0 || threshold <= 0) {
      return { name: 'RATE_LIMIT', passed: false, detail: '限流值必须 > 0' };
    }
    if (ip > 1000 || device > 500) {
      return {
        name: 'RATE_LIMIT',
        passed: false,
        detail: `限流值过大(ip=${ip}, device=${device})`,
      };
    }

    return { name: 'RATE_LIMIT', passed: true };
  }

  private checkLogLevel(isProduction: boolean): { name: string; passed: boolean; detail?: string } {
    const level = this.configService.get('logLevel', { infer: true });
    const validLevels = ['debug', 'info', 'warn', 'error'];

    if (!validLevels.includes(level)) {
      return { name: 'LOG_LEVEL', passed: false, detail: `无效级别: ${level}` };
    }

    if (isProduction && level === 'debug') {
      return {
        name: 'LOG_LEVEL',
        passed: false,
        detail: '生产环境不应使用 debug',
      };
    }

    return { name: 'LOG_LEVEL', passed: true };
  }

  private checkRsaKeys(): { name: string; passed: boolean; detail?: string } {
    const privatePath = this.configService.get('rsaPrivateKeyPath', { infer: true });
    const publicPath = this.configService.get('rsaPublicKeyPath', { infer: true });

    try {
      if (!fs.existsSync(privatePath)) {
        return { name: 'RSA_KEYS', passed: false, detail: `私钥不存在: ${privatePath}` };
      }
      if (!fs.existsSync(publicPath)) {
        return { name: 'RSA_KEYS', passed: false, detail: `公钥不存在: ${publicPath}` };
      }
    } catch (e) {
      return {
        name: 'RSA_KEYS',
        passed: false,
        detail: `检查失败: ${(e as Error).message}`,
      };
    }

    return { name: 'RSA_KEYS', passed: true };
  }

  private checkTotpConfig(): { name: string; passed: boolean; detail?: string } {
    const digits = this.configService.get('totpDigits', { infer: true });
    const step = this.configService.get('totpStep', { infer: true });

    if (digits !== 6 && digits !== 8) {
      return { name: 'TOTP_CONFIG', passed: false, detail: `digits 应为 6 或 8(当前 ${digits})` };
    }
    if (step < 15 || step > 120) {
      return { name: 'TOTP_CONFIG', passed: false, detail: `step 应在 15-120(当前 ${step})` };
    }

    return { name: 'TOTP_CONFIG', passed: true };
  }

  private checkOfflineCache(): { name: string; passed: boolean; detail?: string } {
    const defaultDays = this.configService.get('offlineCacheDefaultDays', { infer: true });
    const maxDays = this.configService.get('offlineCacheMaxDays', { infer: true });

    if (defaultDays < 1 || defaultDays > maxDays) {
      return {
        name: 'OFFLINE_CACHE',
        passed: false,
        detail: `defaultDays 应在 1-${maxDays}(当前 ${defaultDays})`,
      };
    }
    if (maxDays > 90) {
      return {
        name: 'OFFLINE_CACHE',
        passed: false,
        detail: `maxDays 过大(当前 ${maxDays},建议 ≤ 90)`,
      };
    }

    return { name: 'OFFLINE_CACHE', passed: true };
  }

  private checkCardKeyBatchMax(): { name: string; passed: boolean; detail?: string } {
    const max = this.configService.get('cardKeyBatchMax', { infer: true });

    if (max < 1 || max > 100000) {
      return {
        name: 'CARD_KEY_BATCH_MAX',
        passed: false,
        detail: `应在 1-100000(当前 ${max})`,
      };
    }

    return { name: 'CARD_KEY_BATCH_MAX', passed: true };
  }
}
