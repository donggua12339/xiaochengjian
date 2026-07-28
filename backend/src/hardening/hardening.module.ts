import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { HardeningController } from './hardening.controller';
import { HardeningService } from './hardening.service';
import { ApkAnalyzerService } from './apk-analyzer.service';
import { PackerModule } from '../packer/packer.module';

@Module({
  imports: [ConfigModule, PackerModule],
  controllers: [HardeningController],
  providers: [HardeningService, ApkAnalyzerService],
  exports: [HardeningService, ApkAnalyzerService],
})
export class HardeningModule {}
