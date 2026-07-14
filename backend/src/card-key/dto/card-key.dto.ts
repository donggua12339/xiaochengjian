import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsEnum,
  IsInt,
  IsOptional,
  IsString,
  Min,
  Max,
  MaxLength,
  ArrayMinSize,
  ArrayMaxSize,
} from 'class-validator';
import { CardKeyType, BindingStrategy } from '@prisma/client';

/**
 * 生成卡密 DTO
 */
export class GenerateCardsDto {
  @ApiProperty({ description: '卡密类型', enum: CardKeyType })
  @IsEnum(CardKeyType)
  type!: CardKeyType;

  @ApiProperty({ description: '绑定策略', enum: BindingStrategy })
  @IsEnum(BindingStrategy)
  bindingStrategy!: BindingStrategy;

  @ApiProperty({
    description: '最大设备数(N_DEVICES 策略时有效,上限 5)',
    required: false,
    minimum: 1,
    maximum: 5,
    default: 1,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(5)
  maxDevices?: number = 1;

  @ApiProperty({ description: '生成数量(上限 10000)', minimum: 1, maximum: 10000 })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(10000)
  count!: number;

  @ApiProperty({ description: '备注(可选)', required: false, maxLength: 200 })
  @IsOptional()
  @IsString()
  @MaxLength(200)
  remark?: string;
}

/**
 * 卡密模板 DTO
 */
export class CreateCardTemplateDto {
  @ApiProperty({ description: '模板名称' })
  @IsString()
  @MaxLength(100)
  name!: string;

  @ApiProperty({ description: '卡密类型', enum: CardKeyType })
  @IsEnum(CardKeyType)
  type!: CardKeyType;

  @ApiProperty({ description: '绑定策略', enum: BindingStrategy })
  @IsEnum(BindingStrategy)
  bindingStrategy!: BindingStrategy;

  @ApiProperty({ description: '最大设备数', required: false, minimum: 1, maximum: 5, default: 1 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(5)
  maxDevices?: number = 1;

  @ApiProperty({
    description: '默认生成数量',
    required: false,
    minimum: 1,
    maximum: 10000,
    default: 100,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(10000)
  count?: number = 100;
}

/**
 * 卡密响应 DTO
 */
export class CardKeyResponseDto {
  @ApiProperty()
  id!: string;

  @ApiProperty({ description: '卡密类型', enum: CardKeyType })
  type!: CardKeyType;

  @ApiProperty({ description: '绑定策略', enum: BindingStrategy })
  bindingStrategy!: BindingStrategy;

  @ApiProperty()
  maxDevices!: number;

  @ApiProperty({ description: '卡密状态', enum: ['ACTIVE', 'DISABLED', 'EXPIRED', 'USED_UP'] })
  status!: string;

  @ApiProperty({ description: '卡密前 4 位(用于识别)' })
  cardKeyPrefix!: string;

  @ApiProperty({ required: false })
  remark?: string | null;

  @ApiProperty({ description: '批次 ID' })
  batchId!: string;

  @ApiProperty({ required: false, description: '激活时间' })
  activatedAt?: Date | null;

  @ApiProperty({ required: false, description: '过期时间' })
  expiresAt?: Date | null;

  @ApiProperty({ description: '已绑定设备数' })
  boundDevicesCount!: number;

  @ApiProperty()
  createdAt!: Date;

  @ApiProperty()
  updatedAt!: Date;
}

/**
 * 生成卡密响应(含明文,仅此一次)
 */
export class GenerateCardsResponseDto {
  @ApiProperty({ description: '批次 ID' })
  batchId!: string;

  @ApiProperty({ description: '卡密明文列表(仅此一次,务必保存)', type: [String] })
  cardKeys!: string[];

  @ApiProperty({ description: '生成数量' })
  count!: number;
}

/**
 * 签名 hash 白名单 DTO(用于 unbind 时指定设备)
 */
export class UnbindDeviceDto {
  @ApiProperty({ description: '设备 ID(在卡密详情的 boundDevices 里获取)' })
  @IsString()
  deviceId!: string;
}

/**
 * 批量操作 DTO(禁用/启用多张卡密)
 */
export class BatchCardActionDto {
  @ApiProperty({ description: '卡密 ID 列表', type: [String] })
  @IsString({ each: true })
  @ArrayMinSize(1)
  @ArrayMaxSize(100)
  cardIds!: string[];
}
