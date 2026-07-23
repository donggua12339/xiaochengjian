import {
  Controller,
  Post,
  Body,
  UseGuards,
  BadRequestException,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiTags,
  ApiBody,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentDeveloper } from '../common/decorators/current-developer.decorator';
import { IntegrityService } from './integrity.service';

/**
 * Integrity Controller(方案 C 服务端 gate)
 *
 * 端点:
 *  - POST /v1/integrity/verify  客户端签名哈希校验 + 颁发 token
 *  - POST /v1/integrity/verify-token  验证 token(供其他服务调用)
 */
@ApiTags('完整性校验(方案 C)')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('integrity')
export class IntegrityController {
  constructor(private readonly integrityService: IntegrityService) {}

  /**
   * POST /v1/integrity/verify
   * 客户端签名哈希校验 + 颁发 token
   */
  @Post('verify')
  @ApiOperation({ summary: '签名哈希校验 + 颁发完整性 token(方案 C 服务端 gate)' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        appId: { type: 'string', description: '应用包名' },
        encryptedHash: { type: 'string', description: '客户端用服务端公钥加密的签名哈希(base64)' },
        nonce: { type: 'string', description: '一次性随机数(防重放)' },
        timestamp: { type: 'number', description: '毫秒时间戳' },
        deviceFingerprint: { type: 'string', description: '设备指纹(可选,绑定 token)' },
      },
      required: ['appId', 'encryptedHash', 'nonce', 'timestamp'],
    },
  })
  async verify(
    @CurrentDeveloper() developerId: string,
    @Body() body: {
      appId: string;
      encryptedHash: string;
      nonce: string;
      timestamp: number;
      deviceFingerprint?: string;
    },
  ) {
    if (!body.appId || !body.encryptedHash || !body.nonce || !body.timestamp) {
      throw new BadRequestException('MISSING_REQUIRED_FIELDS');
    }

    const result = await this.integrityService.verifyAndIssueToken({
      appId: body.appId,
      encryptedHash: body.encryptedHash,
      nonce: body.nonce,
      timestamp: body.timestamp,
      deviceFingerprint: body.deviceFingerprint,
    });

    return {
      ...result,
      developerId,
    };
  }

  /**
   * POST /v1/integrity/verify-token
   * 验证 token(供其他服务调用,如核心功能 API 前置校验)
   */
  @Post('verify-token')
  @ApiOperation({ summary: '验证完整性 token(供其他服务调用)' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        token: { type: 'string', description: 'Integrity token' },
      },
      required: ['token'],
    },
  })
  async verifyToken(@Body() body: { token: string }) {
    if (!body.token) {
      throw new BadRequestException('TOKEN_REQUIRED');
    }
    const result = this.integrityService.verifyToken(body.token);
    return result;
  }
}
