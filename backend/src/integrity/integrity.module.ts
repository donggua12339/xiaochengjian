import { Module } from '@nestjs/common';
import { IntegrityController } from './integrity.controller';
import { IntegrityService } from './integrity.service';

/**
 * Integrity 模块(方案 C 服务端 gate)
 *
 * 端点:
 *  - POST /v1/integrity/verify  客户端签名哈希校验 + 颁发 token
 *  - POST /v1/integrity/verify-token  验证 token(供其他服务调用)
 *
 * 详见 xcj_blue_demo_v2.1.1_prompt.md §方案 C
 */
@Module({
  controllers: [IntegrityController],
  providers: [IntegrityService],
  exports: [IntegrityService],
})
export class IntegrityModule {}
