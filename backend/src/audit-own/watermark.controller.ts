import {
  Controller,
  Post,
  Body,
  UseGuards,
  BadRequestException,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiTags,
  ApiBody,
} from '@nestjs/swagger';
import { IsString, MaxLength, MinLength } from 'class-validator';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentDeveloper } from '../common/decorators/current-developer.decorator';
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
}
