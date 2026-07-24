import {
  Controller,
  Post,
  Body,
  BadRequestException,
  HttpCode,
} from '@nestjs/common';
import { ApiOperation, ApiTags, ApiBody } from '@nestjs/swagger';
import { IntegrityService } from './integrity.service';

/**
 * 客户端完整性校验端点(无需 JWT 认证)
 *
 * 与 integrity.controller.ts 的区别:
 *  - 无 @UseGuards(JwtAuthGuard): App 内客户端无法持有开发者 JWT
 *  - 使用 appId + timestamp + nonce 做基础防滥用
 *  - 速率限制由 NestJS 全局 RateLimit 保障
 *
 * 端点: POST /v1/integrity/client-verify
 */
@ApiTags('客户端完整性校验(方案 C 公开端点)')
@Controller('integrity')
export class IntegrityClientController {
  constructor(private readonly integrityService: IntegrityService) {}

  @Post('client-verify')
  @HttpCode(200)
  @ApiOperation({
    summary: '客户端签名哈希校验 + 颁发完整性 token(无需 JWT)',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        appId: {
          type: 'string',
          description: '应用包名',
        },
        encryptedHash: {
          type: 'string',
          description: 'APK 受保护内容 hash(base64 编码)',
        },
        nonce: {
          type: 'string',
          description: '一次性随机数(32 hex)',
        },
        timestamp: {
          type: 'number',
          description: '毫秒时间戳',
        },
        deviceFingerprint: {
          type: 'string',
          description: '设备指纹(可选)',
        },
      },
      required: ['appId', 'encryptedHash', 'nonce', 'timestamp'],
    },
  })
  async clientVerify(
    @Body()
    body: {
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

    return this.integrityService.verifyAndIssueToken({
      appId: body.appId,
      encryptedHash: body.encryptedHash,
      nonce: body.nonce,
      timestamp: body.timestamp,
      deviceFingerprint: body.deviceFingerprint,
    });
  }
}
