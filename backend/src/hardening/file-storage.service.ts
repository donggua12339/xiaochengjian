import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { RedisService } from '../redis/redis.service';
import * as fs from 'fs/promises';

/** Redis 中存储的文件元数据 */
export interface FileMeta {
  path: string;
  devId: string;
  fileName: string;
  fileSize: number;
  uploadedAt: string;
}

const FILE_KEY_PREFIX = 'hardening:file:';
const FILE_TTL = 1800; // 30 分钟

/**
 * 文件存储服务
 *
 * 管理上传文件的 Redis 元数据 + 磁盘文件生命周期。
 * - save: 上传完成后记录 fileId → 元数据映射
 * - get: 按 fileId + devId 获取文件路径(鉴权: 只能取自己的)
 * - delete: 删除 Redis 记录 + 磁盘文件
 */
@Injectable()
export class FileStorageService {
  private readonly logger = new Logger(FileStorageService.name);

  constructor(private readonly redis: RedisService) {}

  private key(fileId: string): string {
    return `${FILE_KEY_PREFIX}${fileId}`;
  }

  /**
   * 保存文件元数据到 Redis
   */
  async save(
    fileId: string,
    devId: string,
    filePath: string,
    fileName: string,
    fileSize: number,
  ): Promise<void> {
    const meta: FileMeta = {
      path: filePath,
      devId,
      fileName,
      fileSize,
      uploadedAt: new Date().toISOString(),
    };
    await this.redis.set(this.key(fileId), JSON.stringify(meta), FILE_TTL);
    this.logger.log(`文件已注册: fileId=${fileId} dev=${devId} size=${fileSize}`);
  }

  /**
   * 获取文件元数据(鉴权: devId 必须匹配)
   * @throws NotFoundException fileId 不存在或不属于该开发者
   */
  async get(fileId: string, devId: string): Promise<FileMeta> {
    const raw = await this.redis.get(this.key(fileId));
    if (!raw) {
      throw new NotFoundException('文件不存在或已过期(30 分钟自动清理)');
    }
    const meta: FileMeta = JSON.parse(raw);
    if (meta.devId !== devId) {
      throw new NotFoundException('文件不存在或已过期(30 分钟自动清理)');
    }
    return meta;
  }

  /**
   * 删除文件(Redis 记录 + 磁盘文件)
   */
  async delete(fileId: string): Promise<void> {
    const raw = await this.redis.get(this.key(fileId));
    if (raw) {
      const meta: FileMeta = JSON.parse(raw);
      await fs.unlink(meta.path).catch((e: NodeJS.ErrnoException) => {
        if (e.code !== 'ENOENT') {
          this.logger.warn(`删除磁盘文件失败: ${meta.path} - ${e.message}`);
        }
      });
    }
    await this.redis.del(this.key(fileId));
    this.logger.log(`文件已清理: fileId=${fileId}`);
  }
}
