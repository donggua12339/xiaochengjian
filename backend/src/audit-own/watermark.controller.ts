import {
  Controller,
  Post,
  Body,
  UseGuards,
  Req,
  BadRequestException,
  ForbiddenException,
  UploadedFile,
  UseInterceptors,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiTags,
  ApiBody,
  ApiConsumes,
} from '@nestjs/swagger';
import { IsString, MaxLength, MinLength } from 'class-validator';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentDeveloper } from '../common/decorators/current-developer.decorator';
import type { AuthenticatedRequest } from '../common/decorators/current-developer.decorator';
import { WatermarkService } from './watermark.service';

/**
 * 水印生成请求 DTO
 */
class GenerateWatermarkDto {
  @IsString()
  @MinLength(1)
  @MaxLength(128)
  watermarkId!: string;

  @IsString()
  @MaxLength(32)
  version?: string;
}

/**
 * 水印 Controller(ADR 0030 §c 防滥用机制)
 *
 * 端点:
 *  - POST /v1/watermark/generate  生成 AES-256-GCM 加密水印(Base64)
 *
 * 鉴权:JWT(开发者登录后调用)
 *
 * 用途:injector sign 子命令在 SaaS 模式下,调此端点拿加密水印,
 * 嵌入 APK 的 META-INF/xcj-watermark.enc.txt。
 * 攻击者拿到 APK 只能看到密文,服务端可解密追溯。
 */
@ApiTags('水印(防滥用)')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('watermark')
export class WatermarkController {
  constructor(private readonly watermarkService: WatermarkService) {}

  /**
   * POST /v1/watermark/generate
   * 生成加密水印(供 injector sign 嵌入 APK)
   */
  @Post('generate')
  @ApiOperation({ summary: '生成 AES-256-GCM 加密水印(ADR 0030 §c)' })
  @ApiBody({ type: GenerateWatermarkDto })
  async generate(
    @CurrentDeveloper() developerId: string,
    @Body() dto: GenerateWatermarkDto,
  ): Promise<{
    watermarkBase64: string;
    version: string;
    algorithm: string;
  }> {
    // watermarkId 默认用 developerId(若调用方未显式传则用 JWT 里的)
    const wid = dto.watermarkId || developerId;
    if (!wid) {
      throw new BadRequestException('WATERMARK_ID_REQUIRED');
    }
    return this.watermarkService.generateEncryptedWatermark(
      wid,
      dto.version ?? '0.2.0',
    );
  }

  /**
   * POST /v1/watermark/trace
   * 追溯水印(ADMIN only)
   *
   * 上传含 META-INF/xcj-watermark.enc.txt 的 APK,后端:
   *  1. 从 APK zip 中提取 META-INF/xcj-watermark.enc.txt
   *  2. AES-256-GCM 解密
   *  3. 返回明文(version / watermarkId / timestamp / nonce)
   *
   * 用途:被滥用时,管理员拿到 APK 可追溯水印来源(开发者 ID + 时间)
   */
  @Post('trace')
  @ApiOperation({ summary: '追溯水印(ADMIN only,ADR 0030 §c 追溯闭环)' })
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
      limits: { fileSize: 200 * 1024 * 1024 },
    }),
  )
  async trace(
    @Req() req: AuthenticatedRequest,
    @UploadedFile() file: Express.Multer.File,
  ): Promise<{
    found: boolean;
    watermark?: {
      version: string;
      watermarkId: string;
      timestamp: number;
      nonce: string;
    };
    extractedAt: string;
  }> {
    // 仅 ADMIN 可追溯(避免普通开发者解密他人 APK 水印)
    if (req.user?.role !== 'ADMIN') {
      throw new ForbiddenException('ADMIN_ONLY', {
        cause: 'watermark trace is admin-only (abuse investigation)',
      });
    }
    if (!file) {
      throw new BadRequestException('APK_FILE_REQUIRED');
    }

    const result = await this.watermarkService.extractAndDecryptFromApk(
      file.buffer,
    );

    return {
      found: result.found,
      watermark: result.watermark,
      extractedAt: new Date().toISOString(),
    };
  }
}
