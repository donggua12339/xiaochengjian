import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, MinLength, MaxLength, Matches } from 'class-validator';

/**
 * 注册 DTO
 */
export class RegisterDto {
  @ApiProperty({ description: '邮箱', example: 'developer@example.com' })
  @IsEmail()
  @MaxLength(255)
  email!: string;

  @ApiProperty({
    description: '密码(至少 8 位,含字母和数字)',
    example: 'Password123',
    minLength: 8,
  })
  @IsString()
  @MinLength(8)
  @MaxLength(128)
  @Matches(/^(?=.*[a-zA-Z])(?=.*\d).{8,}$/, {
    message: '密码至少 8 位,且必须包含字母和数字',
  })
  password!: string;
}
