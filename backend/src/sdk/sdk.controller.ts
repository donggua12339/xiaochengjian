import {
  Body,
  Controller,
  Get,
  Ip,
  NotFoundException,
  Post,
  Query,
  Req,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Request } from 'express';
import { HandshakeService } from './handshake.service';
import { SdkService } from './sdk.service';
import { SdkSignatureGuard } from './signature.guard';
import { CryptoService } from '../crypto/crypto.service';
import { PrismaService } from '../prisma/prisma.service';
import { HandshakeDto } from './dto/sdk.dto';

/**
 * SDK 会话(由 SignatureGuard 挂到 request 上)
 */
interface SdkRequest extends Request {
  _sdkSession: {
    aesKey: Buffer;
    appId: string;
    developerId: string;
  };
}

/**
 * SDK 验证接口(供 Android SDK 调用,非管理后台)
 * 详见 ADR 0020 (通信加密) / 0021 (签名) / 0013 (卡密) / 0015 (绑定)
 *
 * 注意:这些接口不需要 JWT,用 appId + appSecret + 签名校验
 */
@ApiTags('SDK 验证')
@Controller('sdk')
export class SdkController {
  constructor(
    private readonly handshakeService: HandshakeService,
    private readonly sdkService: SdkService,
    private readonly crypto: CryptoService,
    private readonly prisma: PrismaService,
  ) {}

  /**
   * RSA 协商 AES 密钥
   */
  @Post('handshake')
  @ApiOperation({ summary: 'SDK 握手(RSA 协商 AES 密钥,返回 sessionId)' })
  async handshake(@Body() dto: HandshakeDto) {
    return this.handshakeService.handshake(dto.encryptedKey, dto.appId);
  }

  /**
   * 激活卡密(绑定设备)
   * 请求体由 SignatureGuard 解密后挂到 body
   */
  @Post('activate')
  @UseGuards(SdkSignatureGuard)
  @ApiOperation({ summary: '激活卡密(SDK 调用,需签名)' })
  async activate(
    @Req() req: SdkRequest,
    @Body()
    body: { cardKey: string; machineId: string; fingerprintHash: string; deviceInfo?: string },
    @Ip() ip: string,
  ) {
    const { aesKey, appId, developerId } = req._sdkSession;
    const result = await this.sdkService.activate({
      appId,
      developerId,
      cardKey: body.cardKey,
      machineId: body.machineId,
      fingerprintHash: body.fingerprintHash,
      deviceInfo: body.deviceInfo,
      ip,
      userAgent: req.headers['user-agent'],
    });
    return this.encryptResponse(result, aesKey);
  }

  /**
   * 验证卡密(刷新缓存)
   */
  @Post('validate')
  @UseGuards(SdkSignatureGuard)
  @ApiOperation({ summary: '验证卡密(SDK 调用,需签名)' })
  async validate(
    @Req() req: SdkRequest,
    @Body() body: { cardKey: string; machineId: string },
    @Ip() ip: string,
  ) {
    const { aesKey, appId, developerId } = req._sdkSession;
    const result = await this.sdkService.validate({
      appId,
      developerId,
      cardKey: body.cardKey,
      machineId: body.machineId,
      ip,
      userAgent: req.headers['user-agent'],
    });
    return this.encryptResponse(result, aesKey);
  }

  /**
   * 会话保活(刷新 sessionId TTL,纯 Redis 操作不查 DB)
   * 客户端在长时间运行时定期调用,避免会话过期导致重新握手
   * 比 validate 轻量:无数据库查询、无日志写入、无卡密校验
   */
  @Post('heartbeat')
  @UseGuards(SdkSignatureGuard)
  @ApiOperation({ summary: '会话保活(刷新 sessionId TTL,纯 Redis 操作)' })
  async heartbeat(@Req() req: SdkRequest) {
    const sessionId = req.headers['x-session-id'] as string;
    const result = await this.handshakeService.refreshSession(sessionId);
    if (!result) {
      // 会话已过期,客户端需重新握手
      throw new UnauthorizedException('SESSION_EXPIRED');
    }
    return this.encryptResponse(result, req._sdkSession.aesKey);
  }

  /**
   * 服务器时间(用于客户端时间同步)
   */
  @Get('time')
  @ApiOperation({ summary: '服务器时间(用于客户端时间同步)' })
  async time() {
    return {
      timestamp: Math.floor(Date.now() / 1000),
      iso: new Date().toISOString(),
    };
  }

  /**
   * 完整性校验值下发(ADR 0062)
   *
   * 客户端拉取开发者后台配置的预期签名 hash 列表,
   * 与本地 APK 签名对比,不一致则拒绝验证(防重打包)
   */
  @Get('integrity')
  @ApiOperation({ summary: '拉取完整性校验值(签名 hash 白名单)' })
  async integrity(@Query('appId') appId: string) {
    const app = await this.prisma.application.findUnique({
      where: { id: appId },
      select: {
        signHashAllowList: true,
        sdkRsaPublicKeyHash: true,
      },
    });
    if (!app) {
      throw new NotFoundException('APP_NOT_FOUND');
    }
    return {
      signHashAllowList: app.signHashAllowList,
      sdkRsaPublicKeyHash: app.sdkRsaPublicKeyHash,
    };
  }

  /**
   * 加密响应体
   * 返回 { encryptedBody: Base64(iv|ciphertext|tag) }
   */
  private encryptResponse(data: unknown, aesKey: Buffer): { encryptedBody: string } {
    const plaintext = Buffer.from(JSON.stringify(data), 'utf-8');
    const { iv, ciphertext, tag } = this.crypto.aesEncrypt(aesKey, plaintext);
    const combined = Buffer.concat([iv, ciphertext, tag]);
    return { encryptedBody: combined.toString('base64') };
  }
}
