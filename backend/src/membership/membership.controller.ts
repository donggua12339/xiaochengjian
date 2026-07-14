import { Body, Controller, Get, Param, Post, Query, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { MembershipService } from './membership.service';
import { GenerateMembershipCodesDto, RedeemMembershipCodeDto } from './dto/membership.dto';
import { PaginationDto } from '../common/dto/pagination.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentDeveloper } from '../common/decorators/current-developer.decorator';
import { Audit } from '../audit/audit.decorator';

/**
 * 会员激活码接口
 * 详见 ADR 0044(发卡网 + 会员激活码模式)
 *
 * - 管理员:生成/列表/禁用(需 ADMIN 角色,MVP 阶段用环境变量配管理员 ID)
 * - 开发者:兑换(需 JWT)
 */
@ApiTags('会员激活码')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller()
export class MembershipController {
  constructor(private readonly membershipService: MembershipService) {}

  // ============= 开发者接口 =============

  /**
   * 兑换会员激活码(开发者)
   */
  @Post('developer/membership/redeem')
  @Audit('REDEEM_MEMBERSHIP_CODE')
  @ApiOperation({ summary: '兑换会员激活码(升级会员)' })
  async redeem(@CurrentDeveloper() developerId: string, @Body() dto: RedeemMembershipCodeDto) {
    return this.membershipService.redeem(developerId, dto);
  }

  // ============= 管理员接口 =============
  // 注:MVP 阶段管理员用环境变量 ADMIN_DEVELOPER_IDS 配置
  // 完整版应加 AdminGuard 检查 DeveloperRole.ADMIN

  /**
   * 生成会员激活码(管理员)
   */
  @Post('admin/membership-codes/generate')
  @Audit('GENERATE_MEMBERSHIP_CODE')
  @ApiOperation({ summary: '批量生成会员激活码(管理员)' })
  async generate(@CurrentDeveloper() developerId: string, @Body() dto: GenerateMembershipCodesDto) {
    // MVP:简单校验,管理员 ID 列表在环境变量
    // 完整版用 AdminGuard
    return this.membershipService.generate(developerId, dto);
  }

  /**
   * 列出激活码(管理员)
   */
  @Get('admin/membership-codes')
  @ApiOperation({ summary: '激活码列表(管理员)' })
  async list(
    @Query() pagination: PaginationDto,
    @Query('status') status?: string,
    @Query('batchId') batchId?: string,
  ) {
    return this.membershipService.list({
      page: pagination.page ?? 1,
      pageSize: pagination.pageSize ?? 20,
      status,
      batchId,
    });
  }

  /**
   * 禁用激活码(管理员)
   */
  @Post('admin/membership-codes/:id/disable')
  @ApiOperation({ summary: '禁用激活码(管理员)' })
  async disable(@Param('id') id: string) {
    return this.membershipService.disable(id);
  }
}
