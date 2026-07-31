import { Injectable, Logger, NotFoundException, BadRequestException } from '@nestjs/common';
import { RedisService } from '../redis/redis.service';
import { FileStorageService } from './file-storage.service';
import * as fs from 'fs/promises';
import * as path from 'path';
import { randomUUID } from 'crypto';

/** Redis 中存储的上传元数据 */
export interface UploadMeta {
  devId: string;
  fileName: string;
  fileSize: number;
  totalChunks: number;
  receivedChunks: number[];
  createdAt: string;
}

const UPLOAD_KEY_PREFIX = 'hardening:upload:';
const UPLOAD_TTL = 3600; // 1 小时
export const CHUNK_SIZE = 5 * 1024 * 1024; // 5MB
export const MAX_FILE_SIZE = 1024 * 1024 * 1024; // 1GB
const CHUNKS_DIR = 'tmp/chunks';

/** APK magic bytes: PK\x03\x04 */
const APK_MAGIC = Buffer.from([0x50, 0x4b, 0x03, 0x04]);

/**
 * 分片上传存储服务
 *
 * 管理分片上传的全生命周期:
 * - createUpload: init 时创建元数据 + 磁盘目录
 * - receiveChunk: 接收分片写磁盘 + 更新 Redis
 * - isComplete: 检查是否所有分片已收
 * - mergeChunks: 拼接分片 + 校验 + 注册 fileId
 * - cleanup: 清理分片目录 + Redis
 */
@Injectable()
export class ChunkStorageService {
  private readonly logger = new Logger(ChunkStorageService.name);

  constructor(
    private readonly redis: RedisService,
    private readonly fileStorage: FileStorageService,
  ) {}

  private key(uploadId: string): string {
    return `${UPLOAD_KEY_PREFIX}${uploadId}`;
  }

  private chunksDir(uploadId: string): string {
    return path.join(process.cwd(), CHUNKS_DIR, uploadId);
  }

  /**
   * 创建上传会话
   */
  async createUpload(
    devId: string,
    fileName: string,
    fileSize: number,
    totalChunks: number,
  ): Promise<{ uploadId: string; chunkSize: number }> {
    if (fileSize > MAX_FILE_SIZE) {
      throw new BadRequestException('APK 体积过大(上限 1GB)');
    }
    if (totalChunks < 1 || totalChunks > 200) {
      throw new BadRequestException('分片数不合法(1-200)');
    }

    const uploadId = randomUUID();
    const dir = this.chunksDir(uploadId);
    await fs.mkdir(dir, { recursive: true });

    const meta: UploadMeta = {
      devId,
      fileName,
      fileSize,
      totalChunks,
      receivedChunks: [],
      createdAt: new Date().toISOString(),
    };
    await this.redis.set(this.key(uploadId), JSON.stringify(meta), UPLOAD_TTL);

    this.logger.log(`上传会话创建: uploadId=${uploadId} dev=${devId} chunks=${totalChunks}`);
    return { uploadId, chunkSize: CHUNK_SIZE };
  }

  /**
   * 接收分片
   */
  async receiveChunk(
    uploadId: string,
    devId: string,
    chunkIndex: number,
    chunkData: Buffer,
  ): Promise<{ received: boolean; chunkIndex: number }> {
    const meta = await this.getMeta(uploadId, devId);

    if (chunkIndex < 0 || chunkIndex >= meta.totalChunks) {
      throw new BadRequestException(`chunkIndex 不合法(0-${meta.totalChunks - 1})`);
    }

    // 幂等: 已收到的分片直接返回
    if (meta.receivedChunks.includes(chunkIndex)) {
      return { received: true, chunkIndex };
    }

    // 写分片文件
    const chunkPath = path.join(this.chunksDir(uploadId), `${chunkIndex}.part`);
    await fs.writeFile(chunkPath, chunkData);

    // 更新 Redis
    meta.receivedChunks.push(chunkIndex);
    meta.receivedChunks.sort((a, b) => a - b);
    await this.redis.set(this.key(uploadId), JSON.stringify(meta), UPLOAD_TTL);

    this.logger.log(`分片已收: uploadId=${uploadId} chunk=${chunkIndex} (${meta.receivedChunks.length}/${meta.totalChunks})`);
    return { received: true, chunkIndex };
  }

  /**
   * 检查是否所有分片已收
   */
  async isComplete(uploadId: string, devId: string): Promise<boolean> {
    const meta = await this.getMeta(uploadId, devId);
    return meta.receivedChunks.length === meta.totalChunks;
  }

  /**
   * 拼接分片 + 校验 + 注册 fileId
   */
  async mergeChunks(
    uploadId: string,
    devId: string,
  ): Promise<{ fileId: string; fileName: string; fileSize: number } | { missing: number[] }> {
    const meta = await this.getMeta(uploadId, devId);

    // Bug G: 缺片时返回 missing 列表而非直接 400,前端可补传
    if (meta.receivedChunks.length !== meta.totalChunks) {
      const received = new Set(meta.receivedChunks);
      const missing: number[] = [];
      for (let i = 0; i < meta.totalChunks; i++) {
        if (!received.has(i)) missing.push(i);
      }
      this.logger.warn(`分片未传完: ${meta.receivedChunks.length}/${meta.totalChunks}, missing=${missing.join(',')}`);
      return { missing };
    }

    // 拼接
    const fileId = randomUUID();
    const outDir = path.join(process.cwd(), 'tmp', 'hardening', devId);
    await fs.mkdir(outDir, { recursive: true });
    const outPath = path.join(outDir, `${fileId}_${meta.fileName}`);

    // 逐片追加拼接(用 fs/promises appendFile,可被 jest.mock 拦截)
    try {
      for (let i = 0; i < meta.totalChunks; i++) {
        const chunkPath = path.join(this.chunksDir(uploadId), `${i}.part`);
        const data = await fs.readFile(chunkPath);
        await fs.appendFile(outPath, data);
      }
    } catch (e) {
      await fs.unlink(outPath).catch(() => {});
      throw e;
    }

    // 校验大小
    const stat = await fs.stat(outPath);
    if (stat.size !== meta.fileSize) {
      await fs.unlink(outPath).catch(() => {});
      throw new BadRequestException(
        `拼接后大小不匹配(期望 ${meta.fileSize}, 实际 ${stat.size})`,
      );
    }

    // Magic bytes 校验
    const fd = await fs.open(outPath, 'r');
    const header = Buffer.alloc(4);
    await fd.read(header, 0, 4, 0);
    await fd.close();
    if (!header.equals(APK_MAGIC)) {
      await fs.unlink(outPath).catch(() => {});
      throw new BadRequestException('文件不是有效的 APK(ZIP 格式)');
    }

    // 注册 fileId
    await this.fileStorage.save(fileId, devId, outPath, meta.fileName, meta.fileSize);

    // 清理分片
    await this.cleanup(uploadId);

    this.logger.log(`分片拼接完成: uploadId=${uploadId} → fileId=${fileId} size=${meta.fileSize}`);
    return { fileId, fileName: meta.fileName, fileSize: meta.fileSize };
  }

  /**
   * 取消上传会话(Bug E)
   */
  async cancelUpload(uploadId: string, devId: string): Promise<void> {
    await this.getMeta(uploadId, devId); // 鉴权
    await this.cleanup(uploadId);
    this.logger.log(`上传已取消: uploadId=${uploadId}`);
  }

  /**
   * 清理分片目录 + Redis
   */
  async cleanup(uploadId: string): Promise<void> {
    const dir = this.chunksDir(uploadId);
    await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
    await this.redis.del(this.key(uploadId));
  }

  /**
   * 获取上传元数据(鉴权: devId 必须匹配)
   */
  private async getMeta(uploadId: string, devId: string): Promise<UploadMeta> {
    const raw = await this.redis.get(this.key(uploadId));
    if (!raw) {
      throw new NotFoundException('上传会话不存在或已过期(1 小时自动清理)');
    }
    const meta: UploadMeta = JSON.parse(raw);
    if (meta.devId !== devId) {
      throw new NotFoundException('上传会话不存在或已过期(1 小时自动清理)');
    }
    return meta;
  }
}
