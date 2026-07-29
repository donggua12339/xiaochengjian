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
import { ApiBearerAuth, ApiOperation, ApiTags, ApiConsumes } from '@nestjs/swagger';
import type { Response } from 'express';
import * as fs from 'fs/promises';
import * as path from 'path';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentDeveloper } from '../common/decorators/current-developer.decorator';
import { HardeningService } from './hardening.service';
import type { HardeningConfig } from './hardening-config.dto';

@ApiTags('APK 加固')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('hardening')
export class HardeningController {
  private readonly logger = new Logger(HardeningController.name);

  constructor(private readonly hardeningService: HardeningService) {}

  /**
   * POST /v1/hardening/analyze
   * 上传 APK,立即返回 taskId,后台异步分析。
   * 前端轮询 GET /v1/hardening/status/:taskId 获取进度。
   */
  @Post('analyze')
  @ApiOperation({ summary: '上传 APK 开始异步分析(返回 taskId)' })
  @ApiConsumes('multipart/form-data')
  @UseInterceptors(FileInterceptor('apk', { limits: { fileSize: 200 * 1024 * 1024 } }))
  async analyze(
    @UploadedFile() file: Express.Multer.File,
    @CurrentDeveloper() developerId: string,
  ) {
    if (!file || !file.originalname.endsWith('.apk')) {
      throw new BadRequestException('请上传 .apk 文件');
    }

    this.logger.log(
      `分析请求: developer=${developerId} file=${file.originalname} size=${file.size}`,
    );

    const tmpDir = path.join(process.cwd(), 'tmp', 'hardening', developerId);
    await fs.mkdir(tmpDir, { recursive: true });
    const tmpPath = path.join(tmpDir, `${Date.now()}_${file.originalname}`);
    await fs.writeFile(tmpPath, file.buffer);

    try {
      const task = await this.hardeningService.startAnalysis(
        tmpPath,
        developerId,
        file.originalname,
      );
      return { taskId: task.id };
    } catch (e) {
      await fs.unlink(tmpPath).catch(() => {});
      throw e;
    }
  }

  /**
   * POST /v1/hardening/harden
   * 提交加固配置 + Keystore,执行加固流水线(异步)
   */
  @Post('harden')
  @ApiOperation({ summary: '执行加固(异步,返回 taskId)' })
  @ApiConsumes('multipart/form-data')
  @UseInterceptors(FileInterceptor('apk', { limits: { fileSize: 200 * 1024 * 1024 } }))
  async harden(
    @UploadedFile() apkFile: Express.Multer.File,
    @CurrentDeveloper() developerId: string,
    @Body()
    body: {
      keystorePassword: string;
      keyAlias: string;
      keyPassword: string;
      config: string;
      analysisJson: string;
      ownershipConfirmed: string;
    },
  ) {
    if (!apkFile) throw new BadRequestException('请上传 APK 文件');
    if (!body.config) throw new BadRequestException('请提供加固配置');
    if (!body.keystorePassword || !body.keyAlias || !body.keyPassword) {
      throw new BadRequestException('请提供 Keystore 密码和别名');
    }
    if (body.ownershipConfirmed !== 'true') {
      throw new BadRequestException('请确认 APK 所有权声明(ADR 0097)');
    }

    const config: HardeningConfig = JSON.parse(body.config);
    const analysis = JSON.parse(body.analysisJson);

    // ADR 0097 审计日志
    this.logger.warn(
      `[ADR-0097 审计] developer=${developerId} ` +
        `pkg=${analysis?.packageName ?? 'unknown'} ` +
        `ownershipConfirmed=${body.ownershipConfirmed} ` +
        `productLine=${config.productLine} ` +
        `preset=${config.preset ?? 'manual'} ` +
        `timestamp=${new Date().toISOString()}`,
    );

    const tmpDir = path.join(process.cwd(), 'tmp', 'hardening', developerId);
    await fs.mkdir(tmpDir, { recursive: true });
    const apkPath = path.join(tmpDir, `harden_${Date.now()}.apk`);
    await fs.writeFile(apkPath, apkFile.buffer);

    const keystorePath = path.join(tmpDir, `ks_${Date.now()}.jks`);

    try {
      const task = await this.hardeningService.harden({
        apkPath,
        keystorePath,
        keystorePassword: body.keystorePassword,
        keyAlias: body.keyAlias,
        keyPassword: body.keyPassword,
        config,
        analysis,
        developerId,
      });

      return { taskId: task.id, status: task.status, message: task.message };
    } catch (e) {
      await fs.unlink(apkPath).catch(() => {});
      throw e;
    }
  }

  /**
   * GET /v1/hardening/status/:taskId
   * 查询任务状态(前端轮询用)
   */
  @Get('status/:taskId')
  @ApiOperation({ summary: '查询加固/分析任务状态' })
  async status(@Param('taskId') taskId: string, @CurrentDeveloper() developerId: string) {
    const task = await this.hardeningService.getTask(taskId);
    if (!task) throw new NotFoundException('任务不存在');
    if (task.developerId !== developerId) throw new NotFoundException('任务不存在');
    return {
      id: task.id,
      status: task.status,
      progress: task.progress,
      message: task.message,
      step: task.step,
      detail: task.detail,
      analysis: task.analysis,
      error: task.error,
      createdAt: task.createdAt,
      updatedAt: task.updatedAt,
    };
  }

  /**
   * GET /v1/hardening/tasks
   * 获取当前用户的所有加固任务列表(刷新页面后可恢复)
   */
  @Get('tasks')
  @ApiOperation({ summary: '获取当前用户的加固任务列表' })
  async tasks(@CurrentDeveloper() developerId: string) {
    const tasks = await this.hardeningService.getUserTasks(developerId);
    return {
      tasks: tasks.map((t) => ({
        id: t.id,
        status: t.status,
        progress: t.progress,
        message: t.message,
        step: t.step,
        detail: t.detail,
        apkFileName: t.apkFileName,
        analysis: t.analysis
          ? {
              packageName: t.analysis.packageName,
              nativeAbis: t.analysis.nativeAbis,
              dexFiles: t.analysis.dexFiles,
            }
          : null,
        createdAt: t.createdAt,
        updatedAt: t.updatedAt,
      })),
    };
  }

  /**
   * GET /v1/hardening/download/:taskId
   */
  @Get('download/:taskId')
  @ApiOperation({ summary: '下载加固后的 APK' })
  async download(
    @Param('taskId') taskId: string,
    @CurrentDeveloper() developerId: string,
    @Res() res: Response,
  ) {
    const task = await this.hardeningService.getTask(taskId);
    if (!task) throw new NotFoundException('任务不存在');
    if (task.developerId !== developerId) throw new NotFoundException('任务不存在');
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
