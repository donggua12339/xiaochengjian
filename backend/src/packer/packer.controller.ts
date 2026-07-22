import {
  Controller,
  Post,
  Get,
  UseGuards,
  UseInterceptors,
  Body,
  Query,
  Req,
  Logger,
  BadRequestException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiTags,
  ApiConsumes,
  ApiBody,
  ApiQuery,
} from '@nestjs/swagger';
import * as fs from 'fs/promises';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentDeveloper } from '../common/decorators/current-developer.decorator';
import { PackerService } from './packer.service';
import { PackerLogService } from './packer-log.service';
import type { DefenderConfigInput } from './defender-config-generator';
import type { AppConfig } from '../config/configuration';
import type { AuthenticatedRequest } from '../common/decorators/current-developer.decorator';

/**
 * Packer Controller(ADR 0081)
 *
 * 端点:
 *  - POST /v1/packer/pack       上传 APK + Keystore + SDK 配置,执行封装
 *  - GET  /v1/packer/logs       查询封装历史
 *  - GET  /v1/packer/logs/export 导出 CSV
 *
 * 鉴权:JWT(锁 5 权限锁定,仅开发者自身)
 */
@ApiTags('自有 APK SDK 封装')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('packer')
export class PackerController {
  private readonly logger = new Logger(PackerController.name);

  constructor(
    private readonly packerService: PackerService,
    private readonly packerLogService: PackerLogService,
    private readonly configService: ConfigService<AppConfig, true>,
  ) {}

  /**
   * POST /v1/packer/pack
   * 上传 APK + Keystore + SDK 配置,执行封装(七锁校验)
   */
  @Post('pack')
  @ApiOperation({ summary: '自有 APK SDK 封装(七锁校验,ADR 0081)' })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        apk: { type: 'string', format: 'binary' },
        keystore: { type: 'string', format: 'binary' },
        keystorePassword: { type: 'string' },
        keyAlias: { type: 'string' },
        keyPassword: { type: 'string' },
        sdkConfig: { type: 'string', description: 'JSON 字符串' },
        xcjAuthSdkDex: { type: 'string', format: 'binary', description: 'classes-xcj.dex' },
        originalName: { type: 'string' },
        defenderEnabled: {
          type: 'string',
          description: 'ADR 0088:是否启用 defender-sdk 注入("true"/"false")',
        },
        defenderConfig: {
          type: 'string',
          description: 'ADR 0088:defender 模块配置 JSON 字符串(9 模块开关 + 响应策略)',
        },
      },
      required: ['apk', 'keystore', 'keystorePassword', 'keyAlias', 'keyPassword', 'xcjAuthSdkDex'],
    },
  })
  @UseInterceptors(
    FileInterceptor('apk', {
      limits: { fileSize: 200 * 1024 * 1024 },
    }),
  )
  async pack(
    @CurrentDeveloper() developerId: string,
    @Req() req: AuthenticatedRequest,
    @Body()
    body: {
      keystorePassword: string;
      keyAlias: string;
      keyPassword: string;
      sdkConfig?: string;
      originalName?: string;
      defenderEnabled?: string;
      defenderConfig?: string;
    },
    @Body('keystore') keystoreFile: Express.Multer.File,
    @Body('xcjAuthSdkDex') xcjAuthSdkDexFile: Express.Multer.File,
    file: Express.Multer.File,
  ) {
    if (!file) {
      throw new BadRequestException('APK_FILE_REQUIRED');
    }
    if (!keystoreFile) {
      throw new BadRequestException('KEYSTORE_FILE_REQUIRED');
    }
    if (!xcjAuthSdkDexFile) {
      throw new BadRequestException('XCJ_AUTH_SDK_DEX_REQUIRED');
    }
    if (!body.keystorePassword || !body.keyAlias || !body.keyPassword) {
      throw new BadRequestException('KEYSTORE_CREDENTIALS_REQUIRED');
    }

    const ip = (req.headers['x-forwarded-for'] as string) || req.ip || 'unknown';
    const userAgent = req.headers['user-agent'];

    let sdkConfig: Record<string, unknown> = {};
    if (body.sdkConfig) {
      try {
        sdkConfig = JSON.parse(body.sdkConfig);
      } catch {
        throw new BadRequestException('INVALID_SDK_CONFIG_JSON');
      }
    }

    // ADR 0088:defender-sdk 注入(可选)
    const defenderEnabled = body.defenderEnabled === 'true';
    let defenderConfig: DefenderConfigInput | undefined;
    if (defenderEnabled) {
      if (!body.defenderConfig) {
        throw new BadRequestException('DEFENDER_CONFIG_REQUIRED');
      }
      try {
        defenderConfig = JSON.parse(body.defenderConfig) as DefenderConfigInput;
      } catch {
        throw new BadRequestException('INVALID_DEFENDER_CONFIG_JSON');
      }
    }

    // 从配置读 defender .aar + .dex 路径(defender 启用时必须存在)
    let defenderAarPath: string | undefined;
    let defenderDex: Buffer | undefined;
    if (defenderEnabled) {
      defenderAarPath = this.configService.get('defenderAarPath', { infer: true });
      if (!defenderAarPath) {
        throw new BadRequestException('DEFENDER_AAR_NOT_CONFIGURED', {
          cause: 'server DEFENDER_AAR_PATH not set, defender injection unavailable',
        });
      }
      try {
        await fs.access(defenderAarPath);
      } catch {
        throw new BadRequestException('DEFENDER_AAR_NOT_FOUND', {
          cause: `defender aar not found at ${defenderAarPath}`,
        });
      }

      const defenderDexPath = this.configService.get('defenderDexPath', { infer: true });
      if (defenderDexPath) {
        try {
          defenderDex = await fs.readFile(defenderDexPath);
        } catch {
          this.logger.warn(`defender dex not found at ${defenderDexPath}, skipping dex injection`);
        }
      }
    }

    const result = await this.packerService.pack({
      developerId,
      apkBuffer: file.buffer,
      originalName: body.originalName || file.originalname,
      keystoreBuffer: keystoreFile.buffer,
      keystorePassword: body.keystorePassword,
      keyAlias: body.keyAlias,
      keyPassword: body.keyPassword,
      sdkConfig,
      xcjAuthSdkDex: xcjAuthSdkDexFile.buffer,
      ip,
      userAgent,
      defenderEnabled,
      defenderConfig,
      defenderAarPath,
      defenderDex,
    });

    return {
      taskId: result.taskId,
      packedApkHash: result.packedApkHash,
      injectedDexHash: result.injectedDexHash,
      injectedDefenderDexHash: result.injectedDefenderDexHash,
      injectedSoHash: result.injectedSoHash,
      defenderSoName: result.defenderSoName,
      keystoreFingerprint: result.keystoreFingerprint,
      packedApkBase64: result.packedApk.toString('base64'),
      packedApkSize: result.packedApk.length,
    };
  }

  /**
   * GET /v1/packer/logs
   * 查询封装历史
   */
  @Get('logs')
  @ApiOperation({ summary: '查询本人封装历史' })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  @ApiQuery({ name: 'offset', required: false, type: Number })
  async listLogs(
    @CurrentDeveloper() developerId: string,
    @Query('limit') limit?: string,
    @Query('offset') offset?: string,
  ) {
    const parsedLimit = limit ? parseInt(limit, 10) : 50;
    const parsedOffset = offset ? parseInt(offset, 10) : 0;
    if (isNaN(parsedLimit) || parsedLimit < 1 || parsedLimit > 200) {
      throw new BadRequestException('INVALID_LIMIT');
    }
    if (isNaN(parsedOffset) || parsedOffset < 0) {
      throw new BadRequestException('INVALID_OFFSET');
    }
    return this.packerLogService.listByDeveloper(developerId, {
      limit: parsedLimit,
      offset: parsedOffset,
    });
  }
}
