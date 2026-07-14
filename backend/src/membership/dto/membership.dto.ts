import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { IsEnum, IsInt, IsOptional, IsString, Max, MaxLength, Min } from 'class-validator';
import { VipLevel } from '@prisma/client';

/**
 * 生成会员激活码 DTO(管理员)
 */
export class GenerateMembershipCodesDto {
  @ApiProperty({ description: '会员等级', enum: VipLevel })
  @IsEnum(VipLevel)
  level!: VipLevel;

  @ApiProperty({ description: '时长(天),PERMANENT 用 -1', minimum: -1, maximum: 365 })
  @Type(() => Number)
  @IsInt()
  @Min(-1)
  @Max(365)
  durationDays!: number;

  @ApiProperty({ description: '生成数量', minimum: 1, maximum: 1000 })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(1000)
  count!: number;

  @ApiProperty({ description: '备注(可选)', required: false, maxLength: 200 })
  @IsOptional()
  @IsString()
  @MaxLength(200)
  remark?: string;
}

/**
 * 兑换会员激活码 DTO(开发者)
 */
export class RedeemMembershipCodeDto {
  @ApiProperty({ description: '会员激活码明文' })
  @IsString()
  code!: string;
}

/**
 * 会员激活码响应(管理员列表)
 */
export class MembershipCodeResponseDto {
  @ApiProperty()
  id!: string;

  @ApiProperty({ description: '前 4 位' })
  codePrefix!: string;

  @ApiProperty({ enum: VipLevel })
  level!: VipLevel;

  @ApiProperty()
  durationDays!: number;

  @ApiProperty({ description: 'UNUSED / USED / DISABLED' })
  status!: string;

  @ApiProperty({ required: false })
  redeemedBy?: string | null;

  @ApiProperty({ required: false })
  redeemedAt?: Date | null;

  @ApiProperty()
  batchId!: string;

  @ApiProperty({ required: false })
  remark?: string | null;

  @ApiProperty()
  createdAt!: Date;
}

/**
 * 生成响应(含明文,仅此一次)
 */
export class GenerateMembershipCodesResponseDto {
  @ApiProperty()
  batchId!: string;

  @ApiProperty({ type: [String], description: '激活码明文列表(仅此一次)' })
  codes!: string[];

  @ApiProperty()
  count!: number;
}

/**
 * 兑换响应
 */
export class RedeemResponseDto {
  @ApiProperty({ enum: VipLevel })
  level!: VipLevel;

  @ApiProperty()
  durationDays!: number;

  @ApiProperty({ description: '新会员等级' })
  newVipLevel!: VipLevel;

  @ApiProperty({ description: '新过期时间' })
  newVipExpiresAt!: Date;
}
