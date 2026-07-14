import { ApiProperty } from '@nestjs/swagger';
import { IsString, MaxLength } from 'class-validator';

/**
 * APK 注入请求 DTO
 * 详见 ADR 0028(注入工具架构)/ E1(安卓端注入)
 *
 * 表单字段:
 *  - apk: APK 文件(multipart)
 *  - keystore: keystore 文件(multipart)
 *  - ksPass: keystore 密码
 *  - ksKeyAlias: key 别名
 *  - keyPass: key 密码
 *  - watermarkId: 水印标识(开发者 ID + 时间戳)
 */
export class InjectApkDto {
  @ApiProperty({ description: 'keystore 密码' })
  @IsString()
  @MaxLength(256)
  ksPass!: string;

  @ApiProperty({ description: 'key 别名' })
  @IsString()
  @MaxLength(128)
  ksKeyAlias!: string;

  @ApiProperty({ description: 'key 密码' })
  @IsString()
  @MaxLength(256)
  keyPass!: string;

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
