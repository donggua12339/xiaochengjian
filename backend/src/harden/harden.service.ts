import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

export interface HardenConfigDto {
  encryptStrings?: boolean;
  vmpProtect?: boolean;
  segmentStrings?: boolean;
  soEncrypt?: boolean;
  detectionModules?: Record<string, boolean>;
  killAction?: string;
  weakThreshold?: number;
  delayMinMs?: number;
  delayMaxMs?: number;
  strength?: string;
}

@Injectable()
export class HardenService {
  constructor(private readonly prisma: PrismaService) {}

  async getConfig(developerId: string, appId: string) {
    await this.verifyOwnership(developerId, appId);
    const config = await this.prisma.hardenConfig.findUnique({
      where: { appId },
    });
    if (!config) {
      // 返回默认配置
      return {
        appId,
        encryptStrings: true,
        vmpProtect: true,
        segmentStrings: false,
        soEncrypt: true,
        detectionModules: {
          antiDebug: true,
          antiFrida: true,
          antiDump: true,
          rootDetect: true,
          xposedDetect: true,
          emulatorDetect: false,
          vpnDetect: true,
          dualAppDetect: true,
          fartDetect: false,
          odexDetect: false,
        },
        killAction: 'kill',
        weakThreshold: 70,
        delayMinMs: 0,
        delayMaxMs: 1000,
        strength: 'standard',
      };
    }
    return config;
  }

  async upsertConfig(developerId: string, appId: string, dto: HardenConfigDto) {
    await this.verifyOwnership(developerId, appId);
    return this.prisma.hardenConfig.upsert({
      where: { appId },
      create: {
        appId,
        developerId,
        ...this.mapDto(dto),
      },
      update: this.mapDto(dto),
    });
  }

  async submitReport(
    developerId: string,
    appId: string,
    report: { overallScore: number; grade: string; dimensions: unknown; raw: unknown },
  ) {
    await this.verifyOwnership(developerId, appId);
    const config = await this.prisma.hardenConfig.findUnique({ where: { appId } });
    if (!config) throw new NotFoundException('HARDEN_CONFIG_NOT_FOUND');

    return this.prisma.qualityReport.create({
      data: {
        appId,
        developerId,
        configId: config.id,
        overallScore: report.overallScore,
        grade: report.grade,
        dimensions: report.dimensions as object,
        rawReport: report.raw as object,
      },
    });
  }

  async getReports(developerId: string, appId: string, limit = 10) {
    await this.verifyOwnership(developerId, appId);
    return this.prisma.qualityReport.findMany({
      where: { appId },
      orderBy: { createdAt: 'desc' },
      take: limit,
    });
  }

  private async verifyOwnership(developerId: string, appId: string) {
    const app = await this.prisma.application.findFirst({
      where: { id: appId, developerId },
    });
    if (!app) throw new ForbiddenException('APP_NOT_OWNED');
  }

  private mapDto(dto: HardenConfigDto) {
    const data: Record<string, unknown> = {};
    if (dto.encryptStrings !== undefined) data.encryptStrings = dto.encryptStrings;
    if (dto.vmpProtect !== undefined) data.vmpProtect = dto.vmpProtect;
    if (dto.segmentStrings !== undefined) data.segmentStrings = dto.segmentStrings;
    if (dto.soEncrypt !== undefined) data.soEncrypt = dto.soEncrypt;
    if (dto.detectionModules !== undefined) data.detectionModules = dto.detectionModules;
    if (dto.killAction !== undefined) data.killAction = dto.killAction;
    if (dto.weakThreshold !== undefined) data.weakThreshold = dto.weakThreshold;
    if (dto.delayMinMs !== undefined) data.delayMinMs = dto.delayMinMs;
    if (dto.delayMaxMs !== undefined) data.delayMaxMs = dto.delayMaxMs;
    if (dto.strength !== undefined) data.strength = dto.strength;
    return data;
  }
}
