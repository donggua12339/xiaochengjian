import { Controller, Get, Param, Query, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { IsInt, Min, Max, IsOptional } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';
import { StatsService } from './stats.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentDeveloper } from '../common/decorators/current-developer.decorator';

class TrendQueryDto {
  @ApiProperty({ description: '天数(1-90)', required: false, default: 7 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(90)
  days?: number = 7;
}

@ApiTags('统计')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller()
export class StatsController {
  constructor(private readonly statsService: StatsService) {}

  @Get('apps/:appId/stats/overview')
  @ApiOperation({ summary: '应用概览(卡密/设备/验证统计)' })
  async appOverview(@CurrentDeveloper() developerId: string, @Param('appId') appId: string) {
    return this.statsService.appOverview(developerId, appId);
  }

  @Get('apps/:appId/stats/validations')
  @ApiOperation({ summary: '验证趋势(按天聚合)' })
  async validationTrend(
    @CurrentDeveloper() developerId: string,
    @Param('appId') appId: string,
    @Query() query: TrendQueryDto,
  ) {
    return this.statsService.validationTrend(developerId, appId, query.days ?? 7);
  }

  @Get('apps/:appId/stats/activations')
  @ApiOperation({ summary: '激活趋势(按天聚合)' })
  async activationTrend(
    @CurrentDeveloper() developerId: string,
    @Param('appId') appId: string,
    @Query() query: TrendQueryDto,
  ) {
    return this.statsService.activationTrend(developerId, appId, query.days ?? 7);
  }

  @Get('developer/stats/overview')
  @ApiOperation({ summary: '开发者全局概览(应用/卡密/设备总数 + 最近7天趋势)' })
  async developerOverview(@CurrentDeveloper() developerId: string) {
    return this.statsService.developerOverview(developerId);
  }
}
