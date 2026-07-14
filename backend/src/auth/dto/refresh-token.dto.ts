import { ApiProperty } from '@nestjs/swagger';
import { IsString, MinLength, MaxLength } from 'class-validator';

/**
 * 刷新 Token DTO
 */
export class RefreshTokenDto {
  @ApiProperty({ description: 'refresh token' })
  @IsString()
  @MinLength(1)
  @MaxLength(512)
  refreshToken!: string;
}
