import { Body, Controller, Delete, Get, Param, Post, Query, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { CardKeyService } from './card-key.service';
import { GenerateCardsDto, CreateCardTemplateDto, UnbindDeviceDto } from './dto/card-key.dto';
import { PaginationDto } from '../common/dto/pagination.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { DeveloperRateLimitGuard, DeveloperRateLimit } from '../rate-limit/developer-rate-limit.guard';
import { CurrentDeveloper } from '../common/decorators/current-developer.decorator';
import { Audit } from '../audit/audit.decorator';
import type { CardKeyType } from '@prisma/client';

@ApiTags('卡密')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('apps/:appId/cards')
export class CardKeyController {
  constructor(private readonly cardKeyService: CardKeyService) {}

  @Post('generate')
  @DeveloperRateLimit({ limit: 10, window: 60 }) // 每分钟最多 10 次生成(防滥用)
  @UseGuards(DeveloperRateLimitGuard)
  @Audit('GENERATE_CARDS')
  @ApiOperation({ summary: '批量生成卡密(返回明文,仅此一次)' })
  async generate(
    @CurrentDeveloper() developerId: string,
    @Param('appId') appId: string,
    @Body() dto: GenerateCardsDto,
  ) {
    return this.cardKeyService.generate(developerId, appId, dto);
  }

  @Get()
  @ApiOperation({ summary: '列出卡密(分页/筛选)' })
  async list(
    @CurrentDeveloper() developerId: string,
    @Param('appId') appId: string,
    @Query() pagination: PaginationDto,
    @Query('type') type?: CardKeyType,
    @Query('status') status?: string,
    @Query('batchId') batchId?: string,
  ) {
    return this.cardKeyService.list(developerId, appId, {
      page: pagination.page ?? 1,
      pageSize: pagination.pageSize ?? 20,
      type,
      status,
      batchId,
    });
  }

  @Get(':cardId')
  @ApiOperation({ summary: '获取卡密详情(含绑定设备)' })
  async getById(
    @CurrentDeveloper() developerId: string,
    @Param('appId') appId: string,
    @Param('cardId') cardId: string,
  ) {
    return this.cardKeyService.getById(developerId, appId, cardId);
  }

  @Post(':cardId/disable')
  @Audit('DISABLE_CARD')
  @ApiOperation({ summary: '禁用卡密' })
  async disable(
    @CurrentDeveloper() developerId: string,
    @Param('appId') appId: string,
    @Param('cardId') cardId: string,
  ) {
    return this.cardKeyService.disable(developerId, appId, cardId);
  }

  @Post(':cardId/enable')
  @Audit('ENABLE_CARD')
  @ApiOperation({ summary: '启用卡密(从 DISABLED 恢复)' })
  async enable(
    @CurrentDeveloper() developerId: string,
    @Param('appId') appId: string,
    @Param('cardId') cardId: string,
  ) {
    return this.cardKeyService.enable(developerId, appId, cardId);
  }

  @Post(':cardId/unbind')
  @Audit('UNBIND_DEVICE')
  @ApiOperation({ summary: '解绑设备(开发者后台操作,用于用户换机)' })
  async unbind(
    @CurrentDeveloper() developerId: string,
    @Param('appId') appId: string,
    @Param('cardId') cardId: string,
    @Body() dto: UnbindDeviceDto,
  ) {
    return this.cardKeyService.unbindDevice(developerId, appId, cardId, dto.deviceId);
  }

  // ============= 卡密模板 =============

  @Post('templates')
  @ApiOperation({ summary: '创建卡密模板' })
  async createTemplate(
    @CurrentDeveloper() developerId: string,
    @Param('appId') appId: string,
    @Body() dto: CreateCardTemplateDto,
  ) {
    return this.cardKeyService.createTemplate(developerId, appId, dto);
  }

  @Get('templates/list')
  @ApiOperation({ summary: '列出卡密模板' })
  async listTemplates(@CurrentDeveloper() developerId: string, @Param('appId') appId: string) {
    return this.cardKeyService.listTemplates(developerId, appId);
  }

  @Delete('templates/:templateId')
  @ApiOperation({ summary: '删除卡密模板' })
  async deleteTemplate(
    @CurrentDeveloper() developerId: string,
    @Param('appId') appId: string,
    @Param('templateId') templateId: string,
  ) {
    return this.cardKeyService.deleteTemplate(developerId, appId, templateId);
  }
}
