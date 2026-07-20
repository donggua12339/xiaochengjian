import {
  Controller,
  Post,
  Get,
  UseGuards,
  UseInterceptors,
  Body,
  Query,
  Req,
  BadRequestException,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiTags,
  ApiConsumes,
  ApiBody,
  ApiQuery,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentDeveloper } from '../common/decorators/current-developer.decorator';
import { AuditOwnService } from './audit-own.service';
import { AuditLogOwnService } from './audit-log-own.service';
import type { AuthenticatedRequest } from '../common/decorators/current-developer.decorator';

/**
 * 自有 APK 诊断 Controller(ADR 0077)
 *
 * 端点:
 *  - POST /v1/audit/analyze   上传 APK + 诊断(只读)
 *  - POST /v1/audit/resign    签名回填(例外 A)
 *  - GET  /v1/audit/logs      查询本人诊断历史
 *
 * 鉴权:JWT(自有 APK 诊断仅限开发者本人)
 */
@ApiTags('自有 APK 诊断')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('audit')
export class AuditOwnController {
  constructor(
    private readonly auditOwnService: AuditOwnService,
    private readonly auditLogOwnService: AuditLogOwnService,
  ) {}

  /**
   * POST /v1/audit/analyze
   * 上传 APK + 三重校验 + 诊断(只读)
   */
  @Post('analyze')
  @ApiOperation({ summary: '自有 APK 诊断(只读:JADX/签名/SDK 后门扫描)' })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        apk: { type: 'string', format: 'binary' },
      },
      required: ['apk'],
    },
  })
  @UseInterceptors(
    FileInterceptor('apk', {
      limits: { fileSize: 200 * 1024 * 1024 }, // 200MB,ADR 0077 §7
    }),
  )
  async analyze(
    @CurrentDeveloper() developerId: string,
    @Req() req: AuthenticatedRequest,
    @Body('originalName') originalName: string,
    file: Express.Multer.File,
  ) {
    if (!file) {
      throw new BadRequestException('APK_FILE_REQUIRED');
    }
    const ip = (req.headers['x-forwarded-for'] as string) || req.ip || 'unknown';
    const userAgent = req.headers['user-agent'];

    const result = await this.auditOwnService.analyze({
      developerId,
      apkBuffer: file.buffer,
      originalName: originalName || file.originalname,
      ip,
      userAgent,
    });

    return {
      taskId: result.taskId,
      report: result.report,
    };
  }

  /**
   * POST /v1/audit/resign
   * 签名回填(例外 A,ADR 0077 §2.1)
   *
   * 约束:
   *  - 仅修改 META-INF/ 下签名文件(apksigner 只生成签名块)
   *  - 必须使用开发者自有 keystore(无默认)
   *  - V1+V2+V3 签名
   *  - 回填后 hash 自动入白名单
   *  - 三重校验前置
   */
  @Post('resign')
  @ApiOperation({ summary: '自有 APK 签名回填(META-INF only + 自有 keystore + V1+V2+V3)' })
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
        originalName: { type: 'string' },
      },
      required: ['apk', 'keystore', 'keystorePassword', 'keyAlias', 'keyPassword'],
    },
  })
  @UseInterceptors(
    FileInterceptor('apk', {
      limits: { fileSize: 200 * 1024 * 1024 },
    }),
  )
  async resign(
    @CurrentDeveloper() developerId: string,
    @Req() req: AuthenticatedRequest,
    @Body() body: {
      keystorePassword: string;
      keyAlias: string;
      keyPassword: string;
      originalName?: string;
    },
    @Body('keystore') keystoreFile: Express.Multer.File,
    file: Express.Multer.File,
  ) {
    if (!file) {
      throw new BadRequestException('APK_FILE_REQUIRED');
    }
    if (!keystoreFile) {
      throw new BadRequestException('KEYSTORE_FILE_REQUIRED');
    }
    if (!body.keystorePassword || !body.keyAlias || !body.keyPassword) {
      throw new BadRequestException('KEYSTORE_CREDENTIALS_REQUIRED');
    }

    const ip = (req.headers['x-forwarded-for'] as string) || req.ip || 'unknown';
    const userAgent = req.headers['user-agent'];

    const result = await this.auditOwnService.resign({
      developerId,
      apkBuffer: file.buffer,
      originalName: body.originalName || file.originalname,
      keystoreBuffer: keystoreFile.buffer,
      keystorePassword: body.keystorePassword,
      keyAlias: body.keyAlias,
      keyPassword: body.keyPassword,
      ip,
      userAgent,
    });

    // 返回重签后 APK(以 base64 形式,client 端解码保存)
    // 注意:大文件场景应改用 streaming response,MVP 先用 base64
    return {
      taskId: result.taskId,
      oldHash: result.oldHash,
      newHash: result.newHash,
      resignedApkBase64: result.resignedApk.toString('base64'),
      resignedApkSize: result.resignedApk.length,
    };
  }

  /**
   * GET /v1/audit/logs
   * 查询本人诊断历史
   */
  @Get('logs')
  @ApiOperation({ summary: '查询本人自有 APK 诊断历史' })
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
    return this.auditLogOwnService.listByDeveloper(developerId, {
      limit: parsedLimit,
      offset: parsedOffset,
    });
  }

  /**
   * GET /v1/audit/logs/export
   * 导出本人诊断历史为 CSV(合规审计用,ADR 0032)
   *
   * 返回 text/csv + UTF-8 BOM,浏览器直接下载
   */
  @Get('logs/export')
  @ApiOperation({ summary: '导出本人诊断历史为 CSV' })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  async exportLogsCsv(
    @CurrentDeveloper() developerId: string,
    @Query('limit') limit?: string,
  ): Promise<{ csv: string; filename: string }> {
    const parsedLimit = limit ? parseInt(limit, 10) : 10000;
    if (isNaN(parsedLimit) || parsedLimit < 1 || parsedLimit > 50000) {
      throw new BadRequestException('INVALID_LIMIT');
    }
    const csv = await this.auditLogOwnService.exportCsvByDeveloper(developerId, {
      limit: parsedLimit,
    });
    const today = new Date().toISOString().slice(0, 10);
    return {
      csv,
      filename: `xcj-audit-logs-${developerId.slice(0, 8)}-${today}.csv`,
    };
  }
}
