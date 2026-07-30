import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_FILTER } from '@nestjs/core';
import { HardeningController } from './hardening.controller';
import { HardeningService } from './hardening.service';
import { ApkAnalyzerService } from './apk-analyzer.service';
import { FileStorageService } from './file-storage.service';
import { ChunkStorageService } from './chunk-storage.service';
import { MulterExceptionFilter } from './multer-exception.filter';
import { PackerModule } from '../packer/packer.module';
import { RedisModule } from '../redis/redis.module';

@Module({
  imports: [ConfigModule, PackerModule, RedisModule],
  controllers: [HardeningController],
  providers: [
    HardeningService,
    ApkAnalyzerService,
    FileStorageService,
    ChunkStorageService,
    { provide: APP_FILTER, useClass: MulterExceptionFilter },
  ],
  exports: [HardeningService, ApkAnalyzerService, FileStorageService, ChunkStorageService],
})
export class HardeningModule {}
