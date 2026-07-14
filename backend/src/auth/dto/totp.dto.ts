import { ApiProperty } from '@nestjs/swagger';
import { IsString, Length, Matches } from 'class-validator';

/**
 * 2FA 验证码 DTO(用于 verify 和 backup)
 */
export class TotpVerifyDto {
  @ApiProperty({ description: '6 位 TOTP 验证码', example: '123456' })
  @IsString()
  @Length(6, 6)
  @Matches(/^\d{6}$/, { message: '验证码必须是 6 位数字' })
  code!: string;
}

/**
 * 2FA 备份码 DTO
 */
export class TotpBackupDto {
  @ApiProperty({ description: '8 位备份码', example: 'A1B2C3D4' })
  @IsString()
  @Length(8, 8)
  backupCode!: string;
}

/**
 * 2FA 启用 DTO(带 pendingTotpToken 和验证码)
 */
export class TotpSetupVerifyDto {
  @ApiProperty({ description: '注册/登录后返回的 pendingTotpToken' })
  @IsString()
  @Length(1, 512)
  pendingTotpToken!: string;

  @ApiProperty({ description: '6 位 TOTP 验证码', example: '123456' })
  @IsString()
  @Length(6, 6)
  @Matches(/^\d{6}$/, { message: '验证码必须是 6 位数字' })
  code!: string;
}
