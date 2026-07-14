import { Controller, Get, Param, Post, Query, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { DeviceService } from './device.service';
import { PaginationDto } from '../common/dto/pagination.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentDeveloper } from '../common/decorators/current-developer.decorator';

@ApiTags('设备')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('apps/:appId/devices')
export class DeviceController {
  constructor(private readonly deviceService: DeviceService) {}

  @Get()
  @ApiOperation({ summary: '列出设备(分页,按最近活跃排序)' })
  async list(
    @CurrentDeveloper() developerId: string,
    @Param('appId') appId: string,
    @Query() pagination: PaginationDto,
  ) {
    return this.deviceService.list(developerId, appId, {
      page: pagination.page ?? 1,
      pageSize: pagination.pageSize ?? 20,
    });
  }

  @Get(':deviceId')
  @ApiOperation({ summary: '设备详情(含绑定的卡密列表)' })
  async getById(
    @CurrentDeveloper() developerId: string,
    @Param('appId') appId: string,
    @Param('deviceId') deviceId: string,
  ) {
    return this.deviceService.getById(developerId, appId, deviceId);
  }

  @Post(':deviceId/unbind')
  @ApiOperation({ summary: '解绑设备(删除该设备的所有卡密绑定,用于用户换机)' })
  async unbindAll(
    @CurrentDeveloper() developerId: string,
    @Param('appId') appId: string,
    @Param('deviceId') deviceId: string,
  ) {
    return this.deviceService.unbindAll(developerId, appId, deviceId);
  }
}
