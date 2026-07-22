import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

/**
 * defender 模块配置(单个模块)
 *
 * 与 DefenderConfig.kt ModuleConfig 对齐
 */
export interface DefenderModuleConfigInput {
  enabled: boolean;
  onViolation: 'kill' | 'warn' | 'none';
}

/**
 * defender 配置输入(从 admin-web 传入)
 *
 * 与 DefenderConfig.kt 字段对齐,缺失字段用默认值
 */
export interface DefenderConfigInput {
  appId: string;
  serverUrl: string;
  signatureExpectedHash?: string;
  signatureVerify?: DefenderModuleConfigInput;
  antiDebug?: DefenderModuleConfigInput;
  antiFrida?: DefenderModuleConfigInput;
  antiDump?: DefenderModuleConfigInput;
  rootDetect?: DefenderModuleConfigInput;
  xposedDetect?: DefenderModuleConfigInput & { killThreshold?: number };
  emulatorDetect?: DefenderModuleConfigInput;
  integrityCheck?: DefenderModuleConfigInput;
  secureScreen?: { enabled: boolean; excludeActivities?: string[] };
  onViolationKill?: {
    delayMinMs?: number;
    delayMaxMs?: number;
    method?: 'sigabrt' | 'exit';
    showToast?: boolean;
    toastMessage?: string;
  };
  report?: { enabled?: boolean; throttleMs?: number };
  /* M6:integrity 预期表(Packer 封装时遍历 APK entry 生成) */
  integrityCrcTable?: string[]; // 每项 "entry名:crc32hex"(如 "classes.dex:1a2b3c4d")
  integrityFileList?: string[]; // 每项一个 entry 名
}

/**
 * Defender 配置生成器(ADR 0088 §config)
 *
 * 功能:
 *  1. 接收 admin-web 传入的模块开关配置
 *  2. 生成 defender-config.json(与 DefenderConfig.kt 默认值对齐)
 *  3. 注入到 APK 的 assets/defender-config.json
 *
 * 安全约束:
 *  - 默认全关,仅 signatureVerify + integrityCheck 默认开(防误杀)
 *  - 不含敏感隐私字段(锁 6 数据锁定)
 *  - onViolation 必须是 kill/warn/none 之一
 */
@Injectable()
export class DefenderConfigGenerator {
  private readonly logger = new Logger(DefenderConfigGenerator.name);

  /** 默认配置(与 DefenderConfig.kt 默认值严格对齐) */
  private readonly defaults = {
    signatureVerify: { enabled: true, onViolation: 'kill' as const },
    antiDebug: { enabled: false, onViolation: 'kill' as const },
    antiFrida: { enabled: false, onViolation: 'kill' as const },
    antiDump: { enabled: false, onViolation: 'kill' as const },
    rootDetect: { enabled: false, onViolation: 'warn' as const },
    xposedDetect: { enabled: false, onViolation: 'kill' as const, killThreshold: 70 },
    emulatorDetect: { enabled: false, onViolation: 'warn' as const },
    integrityCheck: { enabled: true, onViolation: 'kill' as const },
    secureScreen: { enabled: false, excludeActivities: [] as string[] },
    onViolationKill: {
      delayMinMs: 3000,
      delayMaxMs: 15000,
      method: 'sigabrt' as const,
      showToast: true,
      toastMessage: '检测到安全风险',
    },
    report: { enabled: false, throttleMs: 300000 },
  };

  /**
   * 生成 defender-config.json 字符串
   *
   * 缺失字段用默认值,确保 SDK 端总能读到完整配置
   */
  generate(input: DefenderConfigInput): string {
    this.validateInput(input);

    const config = {
      version: 1,
      appId: input.appId,
      serverUrl: input.serverUrl,
      signatureExpectedHash: input.signatureExpectedHash ?? '',
      signatureVerify: input.signatureVerify ?? this.defaults.signatureVerify,
      antiDebug: input.antiDebug ?? this.defaults.antiDebug,
      antiFrida: input.antiFrida ?? this.defaults.antiFrida,
      antiDump: input.antiDump ?? this.defaults.antiDump,
      rootDetect: input.rootDetect ?? this.defaults.rootDetect,
      xposedDetect: {
        ...this.defaults.xposedDetect,
        ...input.xposedDetect,
      },
      emulatorDetect: input.emulatorDetect ?? this.defaults.emulatorDetect,
      integrityCheck: input.integrityCheck ?? this.defaults.integrityCheck,
      secureScreen: {
        enabled: input.secureScreen?.enabled ?? this.defaults.secureScreen.enabled,
        excludeActivities: input.secureScreen?.excludeActivities ?? [],
      },
      onViolationKill: {
        ...this.defaults.onViolationKill,
        ...input.onViolationKill,
      },
      report: {
        ...this.defaults.report,
        ...input.report,
      },
      /* M6:integrity 预期表(Packer 封装时生成,Native 层运行时读取校验) */
      integrityCrcTable: input.integrityCrcTable ?? [],
      integrityFileList: input.integrityFileList ?? [],
    };

    return JSON.stringify(config, null, 2);
  }

  /**
   * 校验输入(锁 6 数据锁定:不含敏感字段)
   */
  private validateInput(input: DefenderConfigInput): void {
    const validViolations = ['kill', 'warn', 'none'];
    const modules: Array<[string, DefenderModuleConfigInput | undefined]> = [
      ['signatureVerify', input.signatureVerify],
      ['antiDebug', input.antiDebug],
      ['antiFrida', input.antiFrida],
      ['antiDump', input.antiDump],
      ['rootDetect', input.rootDetect],
      ['xposedDetect', input.xposedDetect],
      ['emulatorDetect', input.emulatorDetect],
      ['integrityCheck', input.integrityCheck],
    ];

    for (const [name, cfg] of modules) {
      if (cfg && !validViolations.includes(cfg.onViolation)) {
        throw new BadRequestException('INVALID_DEFENDER_CONFIG', {
          cause: `${name}.onViolation must be one of ${validViolations.join('/')}`,
        });
      }
    }

    // xposedDetect.killThreshold 范围校验
    if (input.xposedDetect?.killThreshold !== undefined) {
      const t = input.xposedDetect.killThreshold;
      if (t < 0 || t > 100) {
        throw new BadRequestException('INVALID_DEFENDER_CONFIG', {
          cause: 'xposedDetect.killThreshold must be 0-100',
        });
      }
    }

    // onViolationKill 延迟范围校验
    if (input.onViolationKill) {
      const { delayMinMs, delayMaxMs } = input.onViolationKill;
      if (delayMinMs !== undefined && delayMinMs < 0) {
        throw new BadRequestException('INVALID_DEFENDER_CONFIG', {
          cause: 'onViolationKill.delayMinMs must be >= 0',
        });
      }
      if (delayMaxMs !== undefined && delayMinMs !== undefined && delayMaxMs < delayMinMs) {
        throw new BadRequestException('INVALID_DEFENDER_CONFIG', {
          cause: 'onViolationKill.delayMaxMs must be >= delayMinMs',
        });
      }
    }
  }

  /**
   * 注入 defender-config.json 到 APK 的 assets/
   */
  async injectConfig(apkPath: string, configJson: string, workDir: string): Promise<void> {
    const stagingDir = path.join(workDir, 'assets-staging');
    await fs.rm(stagingDir, { recursive: true, force: true });
    await fs.mkdir(path.join(stagingDir, 'assets'), { recursive: true });

    const configPath = path.join(stagingDir, 'assets', 'defender-config.json');
    await fs.writeFile(configPath, configJson, 'utf-8');

    try {
      await execFileAsync('zip', [apkPath, 'assets/defender-config.json'], {
        timeout: 30_000,
        cwd: stagingDir,
      });
      this.logger.log('defender-config.json 注入完成(assets/defender-config.json)');
    } catch (e) {
      throw new BadRequestException('CONFIG_INJECT_FAILED', {
        cause: `failed to inject defender-config.json: ${(e as Error).message}`,
      });
    }
  }
}
