import { ApiProperty } from '@nestjs/swagger';
import { IsString, MinLength, MaxLength, Matches } from 'class-validator';

/**
 * 修改密码 DTO
 */
export class ChangePasswordDto {
  @ApiProperty({ description: '当前密码', example: 'OldPassword123' })
  @IsString()
  @MinLength(8)
  @MaxLength(128)
  currentPassword!: string;

  @ApiProperty({
    description: '新密码(至少 8 位,含字母和数字)',
    example: 'NewPassword456',
    minLength: 8,
  })
  @IsString()
  @MinLength(8)
  @MaxLength(128)
  @Matches(/^(?=.*[a-zA-Z])(?=.*\d).{8,}$/, {
    message: '新密码至少 8 位,且必须包含字母和数字',
  })
  newPassword!: string;
}
