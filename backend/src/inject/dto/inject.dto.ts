import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsString, MaxLength } from 'class-validator';

/**
 * APK 注入请求 DTO
 * 详见 ADR 0028(注入工具架构)/ E1(安卓端注入)
 *
 * 表单字段:
 *  - apk: APK 文件(multipart,必填)
 *  - keystore: keystore 文件(multipart,可选,不填用系统默认)
 *  - ksPass: keystore 密码(可选,用默认 keystore 时可不填)
 *  - ksKeyAlias: key 别名(可选)
 *  - keyPass: key 密码(可选)
 *  - watermarkId: 水印标识(开发者 ID + 时间戳,必填)
 */
export class InjectApkDto {
  @ApiProperty({ description: 'keystore 密码(用默认 keystore 可不填)', required: false })
  @IsOptional()
  @IsString()
  @MaxLength(256)
  ksPass?: string;

  @ApiProperty({ description: 'key 别名(用默认 keystore 可不填)', required: false })
  @IsOptional()
  @IsString()
  @MaxLength(128)
  ksKeyAlias?: string;

  @ApiProperty({ description: 'key 密码(用默认 keystore 可不填)', required: false })
  @IsOptional()
  @IsString()
  @MaxLength(256)
  keyPass?: string;

  @ApiProperty({ description: '水印标识(开发者 ID + 时间戳)' })
  @IsString()
  @MaxLength(256)
  watermarkId!: string;
}

/**
 * 注入结果
 */
export class InjectResultDto {
  @ApiProperty({ description: '下载令牌(用于下载注入后的 APK)' })
  downloadToken!: string;

  @ApiProperty({ description: '原 APK 大小(字节)' })
  originalSize!: number;

  @ApiProperty({ description: '注入后 APK 大小(字节)' })
  injectedSize!: number;

  @ApiProperty({ description: '水印 ID' })
  watermarkId!: string;
}
