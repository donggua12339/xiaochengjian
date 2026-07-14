import { Body, Controller, Ip, Post, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { TotpSetupVerifyDto, TotpBackupDto, TotpVerifyDto } from './dto/totp.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { CurrentDeveloper } from '../common/decorators/current-developer.decorator';

@ApiTags('认证')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @ApiOperation({ summary: '注册(邮箱+密码)' })
  async register(@Body() dto: RegisterDto) {
    return this.authService.register(dto.email, dto.password);
  }

  @Post('login')
  @ApiOperation({ summary: '登录(未启用 2FA 返回 token;已启用 2FA 返回 pendingTotpToken)' })
  async login(@Body() dto: LoginDto, @Ip() ip: string, @Body('userAgent') userAgent?: string) {
    return this.authService.login(dto.email, dto.password, { ip, userAgent });
  }

  @Post('refresh')
  @ApiOperation({ summary: '刷新 access token' })
  async refresh(
    @Body() dto: RefreshTokenDto,
    @Ip() ip: string,
    @Body('userAgent') userAgent?: string,
  ) {
    return this.authService.refresh(dto.refreshToken, { ip, userAgent });
  }

  @Post('logout')
  @ApiOperation({ summary: '登出(撤销 refresh token)' })
  async logout(@Body() dto: RefreshTokenDto) {
    await this.authService.logout(dto.refreshToken);
    return { success: true };
  }

  @Post('2fa/setup')
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: '设置 2FA(生成 TOTP secret + QR URL,需已登录)' })
  async setupTotp(@CurrentDeveloper() developerId: string) {
    return this.authService.setupTotp(developerId);
  }

  @Post('2fa/verify')
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: '验证 TOTP 码,启用 2FA,返回备份码(仅此一次)' })
  async verifyTotp(@CurrentDeveloper() developerId: string, @Body() dto: TotpVerifyDto) {
    return this.authService.verifyTotp(developerId, dto.code);
  }

  @Post('2fa/login')
  @ApiOperation({ summary: '用 TOTP 码完成 2FA 登录' })
  async totpLogin(
    @Body() dto: TotpSetupVerifyDto,
    @Ip() ip: string,
    @Body('userAgent') userAgent?: string,
  ) {
    return this.authService.verifyTotpLogin(dto.pendingTotpToken, dto.code, { ip, userAgent });
  }

  @Post('2fa/backup')
  @ApiOperation({ summary: '用备份码完成 2FA 登录(备份码一次性,消耗一个)' })
  async backupLogin(
    @Body() dto: TotpSetupVerifyDto & TotpBackupDto,
    @Ip() ip: string,
    @Body('userAgent') userAgent?: string,
  ) {
    return this.authService.verifyBackup(dto.pendingTotpToken, dto.backupCode, { ip, userAgent });
  }
}
