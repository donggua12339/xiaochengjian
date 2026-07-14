import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, MinLength, MaxLength } from 'class-validator';

/**
 * 登录 DTO
 */
export class LoginDto {
  @ApiProperty({ description: '邮箱', example: 'developer@example.com' })
  @IsEmail()
  @MaxLength(255)
  email!: string;

  @ApiProperty({ description: '密码', example: 'Password123' })
  @IsString()
  @MinLength(1)
  @MaxLength(128)
  password!: string;
}
