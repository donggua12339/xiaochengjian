import { IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

/**
 * Handshake 请求 DTO
 * 客户端用 RSA 公钥加密 AES 密钥,发送 Base64 编码的密文
 */
export class HandshakeDto {
  @ApiProperty({ description: 'RSA 加密的 AES 密钥(Base64),需包含 appId 用于身份识别' })
  @IsString()
  @MinLength(1)
  encryptedKey!: string;

  @ApiProperty({ description: '应用 ID' })
  @IsString()
  @MinLength(1)
  appId!: string;
}

/**
 * 通用 SDK 请求(加密体)
 * activate / validate 共用
 */
export class SdkEncryptedRequestDto {
  @ApiProperty({ description: 'handshake 返回的 sessionId' })
  @IsString()
  sessionId!: string;

  @ApiProperty({
    description: '请求体 AES-256-GCM 加密后(Base64),格式:iv(12B)|ciphertext|tag(16B)',
  })
  @IsString()
  encryptedBody!: string;

  @ApiProperty({ description: '时间戳(秒),偏差 > 60s 拒绝' })
  @IsString()
  timestamp!: string;

  @ApiProperty({ description: '随机 nonce,5 分钟内不可重复' })
  @IsString()
  nonce!: string;

  @ApiProperty({ description: 'HMAC-SHA256 签名' })
  @IsString()
  signature!: string;
}

/**
 * 激活卡密请求(解密后的明文)
 */
export class ActivatePayloadDto {
  @ApiProperty({ description: '卡密明文(含连字符)' })
  cardKey!: string;

  @ApiProperty({ description: '机器码(Rust so 生成)' })
  machineId!: string;

  @ApiProperty({ description: '设备指纹哈希(辅助校验)' })
  fingerprintHash!: string;

  @ApiProperty({ description: '设备信息(JSON 字符串,可选)' })
  deviceInfo?: string;
}

/**
 * 验证卡密请求(解密后的明文)
 */
export class ValidatePayloadDto {
  @ApiProperty({ description: '卡密明文(含连字符)' })
  cardKey!: string;

  @ApiProperty({ description: '机器码' })
  machineId!: string;
}
