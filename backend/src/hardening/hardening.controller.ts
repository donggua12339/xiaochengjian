import {
  Controller,
  Post,
  Get,
  Param,
  UseGuards,
  UseInterceptors,
  UploadedFile,
  Body,
  Res,
  Logger,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiTags,
  ApiConsumes,
  ApiBody,
} from '@nestjs/swagger';
import type { Response } from 'express';
import * as fs from 'fs/promises';
import * as path from 'path';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentDeveloper } from '../common/decorators/current-developer.decorator';
import { HardeningService } from './hardening.service';
import type { HardeningConfig } from './hardening-config.dto';

/**
 * 加固控制器
 *
 * 端点:
 *  POST /v1/hardening/analyze    上传 APK,返回分析结果 + 推荐配置
 *  POST /v1/hardening/harden     提交加固配置 + Keystore,执行加固
 *  GET  /v1/hardening/status/:id 查询加固任务状态
 *  GET  /v1/hardening/download/:id 下载加固后的 APK
 *
 * 鉴权:JWT(仅开发者自身)
 */
@ApiTags('APK 加固')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('hardening')
export class HardeningController {
  private readonly logger = new Logger(HardeningController.name);

  constructor(
    private readonly hardeningService: HardeningService,
  ) {}

  /**
   * POST /v1/hardening/analyze
   * 上传 APK,分析结构,返回推荐加固配置
   */
  @Post('analyze')
  @ApiOperation({ summary: '上传 APK 分析结构(只读,不修改)' })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        apk: { type: 'string', format: 'binary', description: '待分析 APK 文件' },
      },
    },
  })
  @UseInterceptors(FileInterceptor('apk'))
  async analyze(
    @UploadedFile() file: Express.Multer.File,
    @CurrentDeveloper() developerId: string,
  ) {
    if (!file || !file.originalname.endsWith('.apk')) {
      throw new BadRequestException('请上传 .apk 文件');
    }

    this.logger.log(`分析请求: developer=${developerId} file=${file.originalname} size=${file.size}`);

    // 保存到临时目录
    const tmpDir = path.join(process.cwd(), 'tmp', 'hardening', developerId);
    await fs.mkdir(tmpDir, { recursive: true });
    const tmpPath = path.join(tmpDir, `${Date.now()}_${file.originalname}`);
    await fs.writeFile(tmpPath, file.buffer);

    try {
      const task = await this.hardeningService.analyze(tmpPath);
      return {
        taskId: task.id,
        analysis: task.analysis,
        // 临时文件路径存入 task(后续 harden 用)
        _tmpApkPath: tmpPath,
      };
    } catch (e) {
      await fs.unlink(tmpPath).catch(() => {});
      throw e;
    }
  }

  /**
   * POST /v1/hardening/harden
   * 提交加固配置 + Keystore,执行加固流水线
   */
  @Post('harden')
  @ApiOperation({ summary: '执行加固(注入 SDK + 修改 Manifest + 重签)' })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        apk: { type: 'string', format: 'binary', description: '待加固 APK' },
        keystore: { type: 'string', format: 'binary', description: '开发者 Keystore' },
        keystorePassword: { type: 'string' },
        keyAlias: { type: 'string' },
        keyPassword: { type: 'string' },
        config: { type: 'string', description: '加固配置 JSON(复选框选择结果)' },
        analysisJson: { type: 'string', description: '分析结果 JSON(来自 analyze 端点)' },
      },
    },
  })
  @UseInterceptors(
    FileInterceptor('apk'),
  )
  async harden(
    @UploadedFile() apkFile: Express.Multer.File,
    @CurrentDeveloper() developerId: string,
    @Body() body: {
      keystorePassword: string;
      keyAlias: string;
      keyPassword: string;
      config: string;
      analysisJson: string;
    },
  ) {
    if (!apkFile) throw new BadRequestException('请上传 APK 文件');
    if (!body.config) throw new BadRequestException('请提供加固配置');
    if (!body.keystorePassword || !body.keyAlias || !body.keyPassword) {
      throw new BadRequestException('请提供 Keystore 密码和别名');
    }

    // 注意:keystore 作为第二个文件上传,这里用 body 传递 base64 或者额外字段
    // 简化方案:keystore 通过单独字段传递(Multer 限制单 FileInterceptor)
    // 生产方案:用 @UseInterceptors(AnyFilesInterceptor) 接收多文件

    const config: HardeningConfig = JSON.parse(body.config);
    const analysis = JSON.parse(body.analysisJson);

    // 保存 APK 到临时目录
    const tmpDir = path.join(process.cwd(), 'tmp', 'hardening', developerId);
    await fs.mkdir(tmpDir, { recursive: true });
    const apkPath = path.join(tmpDir, `harden_${Date.now()}.apk`);
    await fs.writeFile(apkPath, apkFile.buffer);

    // TODO: keystore 处理(从上传文件或已有路径)
    const keystorePath = path.join(tmpDir, `ks_${Date.now()}.jks`);
    // keystore 需要从请求中获取,这里用占位
    // 实际实现中应通过 multipart 的第二个文件字段接收

    this.logger.log(
      `加固请求: developer=${developerId} ` +
      `productLine=${config.productLine} ` +
      `preset=${config.preset ?? 'manual'}`,
    );

    try {
      const task = await this.hardeningService.harden({
        apkPath,
        keystorePath,
        keystorePassword: body.keystorePassword,
        keyAlias: body.keyAlias,
        keyPassword: body.keyPassword,
        config,
        analysis,
      });

      return {
        taskId: task.id,
        status: task.status,
        message: task.message,
      };
    } catch (e) {
      await fs.unlink(apkPath).catch(() => {});
      throw e;
    }
  }

  /**
   * GET /v1/hardening/status/:taskId
   */
  @Get('status/:taskId')
  @ApiOperation({ summary: '查询加固任务状态' })
  async status(@Param('taskId') taskId: string) {
    const task = this.hardeningService.getTask(taskId);
    if (!task) throw new NotFoundException('任务不存在');
    return {
      id: task.id,
      status: task.status,
      progress: task.progress,
      message: task.message,
    };
  }

  /**
   * GET /v1/hardening/download/:taskId
   */
  @Get('download/:taskId')
  @ApiOperation({ summary: '下载加固后的 APK' })
  async download(
    @Param('taskId') taskId: string,
    @Res() res: Response,
  ) {
    const task = this.hardeningService.getTask(taskId);
    if (!task) throw new NotFoundException('任务不存在');
    if (task.status !== 'completed' || !task.outputPath) {
      throw new BadRequestException('加固尚未完成');
    }

    try {
      await fs.access(task.outputPath);
    } catch {
      throw new NotFoundException('加固文件不存在');
    }

    const fileName = `hardened_${taskId.slice(0, 8)}.apk`;
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    res.setHeader('Content-Type', 'application/vnd.android.package-archive');

    const fileContent = await fs.readFile(task.outputPath);
    res.send(fileContent);
  }
}
