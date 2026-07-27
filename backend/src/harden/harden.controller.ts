import { Controller, Get, Put, Post, Body, Param, Query, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentDeveloper } from '../common/decorators/current-developer.decorator';
import { HardenService, HardenConfigDto } from './harden.service';

@ApiTags('加固配置')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('v1/apps/:appId/harden')
export class HardenController {
  constructor(private readonly hardenService: HardenService) {}

  @Get('config')
  @ApiOperation({ summary: '获取加固配置' })
  getConfig(@CurrentDeveloper() developerId: string, @Param('appId') appId: string) {
    return this.hardenService.getConfig(developerId, appId);
  }

  @Put('config')
  @ApiOperation({ summary: '保存加固配置' })
  upsertConfig(
    @CurrentDeveloper() developerId: string,
    @Param('appId') appId: string,
    @Body() dto: HardenConfigDto,
  ) {
    return this.hardenService.upsertConfig(developerId, appId, dto);
  }

  @Post('report')
  @ApiOperation({ summary: '提交质量报告' })
  submitReport(
    @CurrentDeveloper() developerId: string,
    @Param('appId') appId: string,
    @Body() body: { overallScore: number; grade: string; dimensions: unknown; raw: unknown },
  ) {
    return this.hardenService.submitReport(developerId, appId, body);
  }

  @Get('reports')
  @ApiOperation({ summary: '获取质量报告历史' })
  getReports(
    @CurrentDeveloper() developerId: string,
    @Param('appId') appId: string,
    @Query('limit') limit?: string,
  ) {
    return this.hardenService.getReports(developerId, appId, limit ? parseInt(limit, 10) : 10);
  }
}
