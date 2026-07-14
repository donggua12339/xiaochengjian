import {
  Body,
  Controller,
  Get,
  Post,
  Query,
  Res,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { FileFieldsInterceptor } from '@nestjs/platform-express';
import { ApiBearerAuth, ApiConsumes, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Response } from 'express';
import { InjectService } from './inject.service';
import { InjectApkDto } from './dto/inject.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { Audit } from '../audit/audit.decorator';

/**
 * APK 注入接口(SaaS 独占,ADR 0028/E1)
 *
 * 流程:
 *  1. POST /v1/admin/inject(上传 APK + keystore + 参数)-> 返回下载令牌
 *  2. GET /v1/admin/inject/download?token=xxx -> 下载注入后的 APK
 *
 * 注:注入后的 APK 5 分钟后自动删除(令牌过期)
 */
@ApiTags('APK 注入')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('admin/inject')
export class InjectController {
  constructor(private readonly injectService: InjectService) {}

  /**
   * 上传 APK + keystore,执行注入
   */
  @Post()
  @Audit('INJECT_APK')
  @ApiOperation({ summary: '上传 APK + keystore 执行注入(返回下载令牌)' })
  @ApiConsumes('multipart/form-data')
  @UseInterceptors(
    FileFieldsInterceptor(
      [
        { name: 'apk', maxCount: 1 },
        { name: 'keystore', maxCount: 1 },
      ],
      {
        limits: {
          fileSize: 200 * 1024 * 1024, // 200MB(APK 可能较大)
        },
      },
    ),
  )
  async inject(
    @Body() dto: InjectApkDto,
    @Body('apk') apkFile: Express.Multer.File,
    @Body('keystore') keystoreFile: Express.Multer.File,
  ) {
    // FileFieldsInterceptor 把文件挂到 Body 上
    const apk = (apkFile || (dto as unknown as { apk?: Express.Multer.File }).apk) as Express.Multer.File;
    const keystore = (keystoreFile || (dto as unknown as { keystore?: Express.Multer.File }).keystore) as Express.Multer.File;
    return this.injectService.inject(apk, keystore, {
      ksPass: dto.ksPass,
      ksKeyAlias: dto.ksKeyAlias,
      keyPass: dto.keyPass,
      watermarkId: dto.watermarkId,
    });
  }

  /**
   * 下载注入后的 APK
   */
  @Get('download')
  @ApiOperation({ summary: '用令牌下载注入后的 APK' })
  async download(@Query('token') token: string, @Res() res: Response) {
    const result = await this.injectService.download(token);
    res.setHeader('Content-Type', 'application/vnd.android.package-archive');
    res.setHeader('Content-Disposition', `attachment; filename="${result.fileName}"`);
    res.sendFile(result.filePath);
  }
}
