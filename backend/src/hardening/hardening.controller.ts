import {
  Controller,
  Post,
  Get,
  Delete,
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
import { ConfigService } from '@nestjs/config';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage, memoryStorage } from 'multer';
import { ApiBearerAuth, ApiOperation, ApiTags, ApiConsumes } from '@nestjs/swagger';
import type { Response } from 'express';
import { randomUUID } from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentDeveloper } from '../common/decorators/current-developer.decorator';
import { HardeningService } from './hardening.service';
import { FileStorageService } from './file-storage.service';
import { ChunkStorageService } from './chunk-storage.service';
import type { HardeningConfig } from './hardening-config.dto';
import type { AppConfig } from '../config/configuration';

/** APK magic bytes: PK\x03\x04 (ZIP format) */
const APK_MAGIC = Buffer.from([0x50, 0x4b, 0x03, 0x04]);

@ApiTags('APK 加固')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('hardening')
export class HardeningController {
  private readonly logger = new Logger(HardeningController.name);

  constructor(
    private readonly hardeningService: HardeningService,
    private readonly fileStorage: FileStorageService,
    private readonly chunkStorage: ChunkStorageService,
    private readonly configService: ConfigService<AppConfig, true>,
  ) {}

  /**
   * POST /v1/hardening/upload
   * 上传 APK 文件(diskStorage 流式写盘),返回 fileId。
   * 文件只上传一次,后续 analyze/harden 通过 fileId 引用。
   */
  @Post('upload')
  @ApiOperation({ summary: '上传 APK 文件(返回 fileId,带上传进度)' })
  @ApiConsumes('multipart/form-data')
  @UseInterceptors(
    FileInterceptor('apk', {
      storage: diskStorage({
        destination: (_req, _file, cb) => {
          // 临时目录,按开发者隔离
          const devId = (_req as unknown as { user?: { sub?: string } }).user?.sub ?? 'anonymous';
          const dir = path.join(process.cwd(), 'tmp', 'hardening', devId);
          fs.mkdir(dir, { recursive: true })
            .then(() => cb(null, dir))
            .catch((e) => cb(e, ''));
        },
        filename: (_req, file, cb) => {
          const id = randomUUID();
          cb(null, `${id}_${file.originalname}`);
        },
      }),
      limits: { fileSize: 200 * 1024 * 1024 },
    }),
  )
  async upload(@UploadedFile() file: Express.Multer.File, @CurrentDeveloper() developerId: string) {
    if (!file) {
      throw new BadRequestException('请上传 APK 文件');
    }

    // Magic bytes 校验: APK = ZIP = PK\x03\x04
    let validMagic = false;
    if (file.buffer && file.buffer.length >= 4) {
      validMagic = file.buffer.subarray(0, 4).equals(APK_MAGIC);
    } else if (file.path) {
      // diskStorage 模式: buffer 为空,读文件头
      try {
        const fd = await fs.open(file.path, 'r');
        const header = Buffer.alloc(4);
        await fd.read(header, 0, 4, 0);
        await fd.close();
        validMagic = header.equals(APK_MAGIC);
      } catch {
        validMagic = false;
      }
    }

    if (!validMagic) {
      if (file.path) await fs.unlink(file.path).catch(() => {});
      throw new BadRequestException('文件不是有效的 APK(ZIP 格式)');
    }

    const fileId = randomUUID();
    await this.fileStorage.save(fileId, developerId, file.path, file.originalname, file.size);

    this.logger.log(`上传完成: fileId=${fileId} dev=${developerId} size=${file.size}`);
    return { fileId, fileName: file.originalname, fileSize: file.size };
  }

  /**
   * POST /v1/hardening/upload/init
   * 初始化分片上传会话,返回 uploadId。
   */
  @Post('upload/init')
  @ApiOperation({ summary: '初始化分片上传(返回 uploadId)' })
  async uploadInit(
    @Body() body: { fileName: string; fileSize: number; totalChunks: number },
    @CurrentDeveloper() developerId: string,
  ) {
    if (!body?.fileName || !body?.fileSize || !body?.totalChunks) {
      throw new BadRequestException('请提供 fileName, fileSize, totalChunks');
    }
    return this.chunkStorage.createUpload(
      developerId,
      body.fileName,
      body.fileSize,
      body.totalChunks,
    );
  }

  /**
   * POST /v1/hardening/upload/chunk
   * 上传单个分片(5MB, memoryStorage)。
   */
  @Post('upload/chunk')
  @ApiOperation({ summary: '上传分片(5MB/片, 3 并发)' })
  @ApiConsumes('multipart/form-data')
  @UseInterceptors(
    FileInterceptor('chunk', {
      storage: memoryStorage(),
      limits: { fileSize: 6 * 1024 * 1024 }, // 6MB 余量
    }),
  )
  async uploadChunk(
    @UploadedFile() chunkFile: Express.Multer.File | undefined,
    @CurrentDeveloper() developerId: string,
    @Body() body: { uploadId: string; chunkIndex: string },
  ) {
    if (!body?.uploadId || body?.chunkIndex === undefined) {
      throw new BadRequestException('请提供 uploadId 和 chunkIndex');
    }
    if (!chunkFile) {
      throw new BadRequestException('请上传分片文件');
    }
    const chunkIndex = parseInt(body.chunkIndex, 10);
    if (isNaN(chunkIndex)) {
      throw new BadRequestException('chunkIndex 必须为数字');
    }
    return this.chunkStorage.receiveChunk(body.uploadId, developerId, chunkIndex, chunkFile.buffer);
  }

  /**
   * POST /v1/hardening/upload/complete
   * 所有分片上传完毕,拼接 + 校验 + 注册 fileId。
   */
  @Post('upload/complete')
  @ApiOperation({ summary: '完成分片上传(拼接+校验+返回 fileId)' })
  async uploadComplete(
    @Body() body: { uploadId: string },
    @CurrentDeveloper() developerId: string,
  ) {
    if (!body?.uploadId) {
      throw new BadRequestException('请提供 uploadId');
    }
    return this.chunkStorage.mergeChunks(body.uploadId, developerId);
  }

  /**
   * POST /v1/hardening/analyze
   * 传 fileId 启动异步分析(不再接收文件)。
   */
  @Post('analyze')
  @ApiOperation({ summary: '传 fileId 启动异步分析(返回 taskId)' })
  async analyze(@Body() body: { fileId: string }, @CurrentDeveloper() developerId: string) {
    if (!body?.fileId) {
      throw new BadRequestException('请提供 fileId');
    }

    const meta = await this.fileStorage.get(body.fileId, developerId);

    this.logger.log(`分析请求: dev=${developerId} fileId=${body.fileId} file=${meta.fileName}`);

    try {
      const task = await this.hardeningService.startAnalysis(meta.path, developerId, meta.fileName);

      // 分析启动后清理上传文件(分析过程会自己读文件)
      // 注意: 不立即删,因为分析是异步的,文件在分析期间需要存在
      // 文件清理由 TTL 兜底 + 分析完成回调处理

      return { taskId: task.id };
    } catch (e) {
      throw e;
    }
  }

  /**
   * POST /v1/hardening/harden
   * 传 fileId + keystore(memoryStorage 内存传) + 配置,执行加固。
   * 支持 useDefaultSign=true 使用服务端预配置的默认 Keystore。
   */
  @Post('harden')
  @ApiOperation({ summary: '传 fileId + Keystore 执行加固(异步)' })
  @ApiConsumes('multipart/form-data')
  @UseInterceptors(
    FileInterceptor('keystore', {
      storage: memoryStorage(),
      limits: { fileSize: 10 * 1024 * 1024 },
    }),
  )
  async harden(
    @UploadedFile() keystoreFile: Express.Multer.File | undefined,
    @CurrentDeveloper() developerId: string,
    @Body()
    body: {
      fileId: string;
      useDefaultSign?: string;
      keystorePassword?: string;
      keyAlias?: string;
      keyPassword?: string;
      config: string;
      analysisJson: string;
      ownershipConfirmed: string;
    },
  ) {
    if (!body?.fileId) throw new BadRequestException('请提供 fileId');
    if (!body.config) throw new BadRequestException('请提供加固配置');
    if (body.ownershipConfirmed !== 'true') {
      throw new BadRequestException('请确认 APK 所有权声明(ADR 0097)');
    }

    const meta = await this.fileStorage.get(body.fileId, developerId);
    const config: HardeningConfig = JSON.parse(body.config);
    const analysis = JSON.parse(body.analysisJson);

    // 解析签名来源
    let keystorePath: string;
    let keystorePassword: string;
    let keyAlias: string;
    let keyPassword: string;
    let signMethod: 'upload' | 'default';
    let tmpKeystorePath: string | null = null;

    if (body.useDefaultSign === 'true') {
      if (keystoreFile) {
        throw new BadRequestException('使用默认签名时不能同时上传 Keystore 文件');
      }
      const dk = this.configService.get('defaultKeystore');
      if (!dk?.enabled) {
        throw new BadRequestException('默认签名未启用');
      }
      try {
        await fs.stat(dk.path);
      } catch {
        throw new BadRequestException('默认 Keystore 文件不存在');
      }
      keystorePath = dk.path;
      keystorePassword = dk.password;
      keyAlias = dk.alias;
      keyPassword = dk.keyPassword;
      signMethod = 'default';
    } else {
      if (!body.keystorePassword || !body.keyAlias || !body.keyPassword) {
        throw new BadRequestException('请提供 Keystore 密码和别名');
      }
      if (!keystoreFile) {
        throw new BadRequestException('请上传 Keystore 文件');
      }
      // Keystore 写入临时文件(内存 → 磁盘,apksigner 需要文件路径)
      const tmpDir = path.join(process.cwd(), 'tmp', 'hardening', developerId);
      await fs.mkdir(tmpDir, { recursive: true });
      tmpKeystorePath = path.join(tmpDir, `ks_${Date.now()}.jks`);
      await fs.writeFile(tmpKeystorePath, keystoreFile.buffer);
      keystoreFile.buffer.fill(0);
      keystorePath = tmpKeystorePath;
      keystorePassword = body.keystorePassword;
      keyAlias = body.keyAlias;
      keyPassword = body.keyPassword;
      signMethod = 'upload';
    }

    // ADR 0097 审计日志
    this.logger.warn(
      `[ADR-0097 审计] developer=${developerId} ` +
        `pkg=${analysis?.packageName ?? 'unknown'} ` +
        `ownershipConfirmed=${body.ownershipConfirmed} ` +
        `productLine=${config.productLine} ` +
        `preset=${config.preset ?? 'manual'} ` +
        `signMethod=${signMethod} ` +
        `timestamp=${new Date().toISOString()}`,
    );

    try {
      const task = await this.hardeningService.harden({
        apkPath: meta.path,
        keystorePath,
        keystorePassword,
        keyAlias,
        keyPassword,
        config,
        analysis,
        developerId,
      });

      return { taskId: task.id, status: task.status, message: task.message };
    } catch (e) {
      if (tmpKeystorePath) await fs.unlink(tmpKeystorePath).catch(() => {});
      throw e;
    }
  }

  /**
   * GET /v1/hardening/default-sign-status
   * 查询默认签名是否可用(不返回密码)
   */
  @Get('default-sign-status')
  @ApiOperation({ summary: '查询默认签名是否可用' })
  defaultSignStatus(): { enabled: boolean; alias?: string } {
    const dk = this.configService.get('defaultKeystore');
    if (!dk?.enabled) return { enabled: false };
    return { enabled: true, alias: dk.alias };
  }

  /**
   * GET /v1/hardening/status/:taskId
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
   * DELETE /v1/hardening/tasks/:taskId
   * 取消任务(Bug E)
   */
  @Delete('tasks/:taskId')
  @ApiOperation({ summary: '取消加固/分析任务' })
  async cancelTask(@Param('taskId') taskId: string, @CurrentDeveloper() developerId: string) {
    const task = await this.hardeningService.getTask(taskId);
    if (!task) throw new NotFoundException('任务不存在');
    if (task.developerId !== developerId) throw new NotFoundException('任务不存在');
    if (task.status === 'completed' || task.status === 'cancelled') {
      throw new BadRequestException('任务已结束,无法取消');
    }
    await this.hardeningService.cancelTask(taskId);
    return { cancelled: true };
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
