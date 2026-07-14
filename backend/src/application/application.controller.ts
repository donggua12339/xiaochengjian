import { Body, Controller, Delete, Get, Param, Patch, Post, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { ApplicationService } from './application.service';
import { CreateAppDto, UpdateAppDto } from './dto/app.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentDeveloper } from '../common/decorators/current-developer.decorator';
import { Audit } from '../audit/audit.decorator';

@ApiTags('应用')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('apps')
export class ApplicationController {
  constructor(private readonly appService: ApplicationService) {}

  @Post()
  @Audit('CREATE_APP')
  @ApiOperation({ summary: '创建应用(返回明文 appSecret,仅此一次)' })
  async create(@CurrentDeveloper() developerId: string, @Body() dto: CreateAppDto) {
    return this.appService.create(developerId, dto);
  }

  @Get()
  @ApiOperation({ summary: '列出当前开发者的所有应用' })
  async list(@CurrentDeveloper() developerId: string) {
    return this.appService.list(developerId);
  }

  @Get(':id')
  @ApiOperation({ summary: '获取应用详情' })
  async getById(@CurrentDeveloper() developerId: string, @Param('id') appId: string) {
    return this.appService.getById(developerId, appId);
  }

  @Patch(':id')
  @Audit('UPDATE_APP')
  @ApiOperation({ summary: '更新应用(名称/限流/缓存/签名白名单等)' })
  async update(
    @CurrentDeveloper() developerId: string,
    @Param('id') appId: string,
    @Body() dto: UpdateAppDto,
  ) {
    return this.appService.update(developerId, appId, dto);
  }

  @Delete(':id')
  @Audit('DELETE_APP')
  @ApiOperation({ summary: '删除应用(级联删除卡密/设备等)' })
  async delete(@CurrentDeveloper() developerId: string, @Param('id') appId: string) {
    await this.appService.delete(developerId, appId);
    return { success: true };
  }

  @Post(':id/rotate-secret')
  @Audit('ROTATE_SECRET')
  @ApiOperation({ summary: '重置 appSecret(返回新明文,仅此一次)' })
  async rotateSecret(@CurrentDeveloper() developerId: string, @Param('id') appId: string) {
    return this.appService.rotateSecret(developerId, appId);
  }
}
