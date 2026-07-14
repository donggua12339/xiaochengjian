import { ApiProperty } from '@nestjs/swagger';
import {
  IsString,
  MinLength,
  MaxLength,
  Matches,
  IsOptional,
  IsInt,
  Min,
  Max,
} from 'class-validator';

/**
 * 创建应用 DTO
 */
export class CreateAppDto {
  @ApiProperty({ description: '应用名称', example: '我的工具箱' })
  @IsString()
  @MinLength(1)
  @MaxLength(100)
  name!: string;

  @ApiProperty({ description: '应用包名(Android package)', example: 'com.example.myapp' })
  @IsString()
  @Matches(/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/, {
    message: '包名格式不正确(如 com.example.myapp)',
  })
  @MaxLength(255)
  packageName!: string;
}

/**
 * 更新应用 DTO(所有字段可选)
 */
export class UpdateAppDto {
  @ApiProperty({ description: '应用名称', required: false })
  @IsOptional()
  @IsString()
  @MinLength(1)
  @MaxLength(100)
  name?: string;

  @ApiProperty({ description: '签名 hash 白名单(允许的 APK 签名)', required: false })
  @IsOptional()
  @IsString({ each: true })
  signHashAllowList?: string[];

  @ApiProperty({ description: 'IP 限流(每分钟)', required: false, minimum: 1 })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(1000)
  rateLimitIpPerMinute?: number;

  @ApiProperty({ description: '设备限流(每分钟)', required: false, minimum: 1 })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(500)
  rateLimitDevicePerMinute?: number;

  @ApiProperty({ description: '失败锁定阈值', required: false, minimum: 1 })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(100)
  rateLimitFailLockThreshold?: number;

  @ApiProperty({ description: '失败锁定时长(秒)', required: false, minimum: 60 })
  @IsOptional()
  @IsInt()
  @Min(60)
  @Max(86400)
  rateLimitFailLockTtl?: number;

  @ApiProperty({ description: '离线缓存天数(1-30)', required: false, minimum: 1, maximum: 30 })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(30)
  offlineCacheDays?: number;

  @ApiProperty({ description: 'SDK RSA 公钥指纹(对应客户端 Rust so 内的公钥)', required: false })
  @IsOptional()
  @IsString()
  @MaxLength(128)
  sdkRsaPublicKeyHash?: string;
}

/**
 * 应用响应 DTO(不含敏感字段)
 */
export class AppResponseDto {
  @ApiProperty()
  id!: string;

  @ApiProperty()
  name!: string;

  @ApiProperty()
  packageName!: string;

  @ApiProperty({ description: 'appSecret 前缀(用于识别)' })
  appSecretPrefix!: string;

  @ApiProperty({ description: '是否已配置签名白名单' })
  hasSignHashAllowList!: boolean;

  @ApiProperty({ required: false })
  rateLimitIpPerMinute?: number | null;

  @ApiProperty({ required: false })
  rateLimitDevicePerMinute?: number | null;

  @ApiProperty({ required: false })
  rateLimitFailLockThreshold?: number | null;

  @ApiProperty({ required: false })
  rateLimitFailLockTtl?: number | null;

  @ApiProperty()
  offlineCacheDays!: number;

  @ApiProperty({ required: false })
  sdkRsaPublicKeyHash?: string | null;

  @ApiProperty()
  createdAt!: Date;

  @ApiProperty()
  updatedAt!: Date;
}

/**
 * 创建应用响应(含明文 appSecret,仅此一次)
 */
export class CreateAppResponseDto extends AppResponseDto {
  @ApiProperty({ description: 'appSecret 明文(仅创建/重置时返回,务必保存)' })
  appSecret!: string;
}
