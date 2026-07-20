import { Module } from '@nestjs/common';
import { AuditOwnController } from './audit-own.controller';
import { AuditOwnService } from './audit-own.service';
import { AuditOwnValidators } from './audit-own-validators';
import { AuditLogOwnService } from './audit-log-own.service';
import { WatermarkService } from './watermark.service';
import { WatermarkController } from './watermark.controller';
import { HardenerDetector } from './hardener/hardener-detector';
import { BangcleAdapter } from './hardener/bangcle.adapter';
import { HardenerEulaService } from './hardener/hardener-eula.service';
import { CryptoModule } from '../crypto/crypto.module';

/**
 * 自有 APK 诊断模块(ADR 0077)+ 水印防滥用(ADR 0030 §c)+ 梆梆加固自检(ADR 0078)
 *
 * 提供:
 *  - POST /v1/audit/analyze           诊断(只读,支持 ?hardener=bangcle 触发梆梆自检)
 *  - POST /v1/audit/resign            签名回填(例外 A)
 *  - GET  /v1/audit/logs              诊断历史
 *  - GET  /v1/audit/logs/export       导出 CSV
 *  - GET  /v1/audit/eula              获取梆梆自检 EULA(锁 B 前置)
 *  - POST /v1/audit/eula/accept       接受 EULA(锁 B)
 *  - POST /v1/watermark/generate      生成加密水印(ADR 0030 §c)
 *  - POST /v1/watermark/trace         追溯水印(ADMIN only,ADR 0030 §c 追溯闭环)
 *
 * 三重校验强制(包名白名单 + 签名 hash 比对 + 目录隔离)。
 * 梆梆适配器 3 把锁:锁 A(仅梆梆)+ 锁 B(EULA 前置)+ 锁 C(仅完整性报告)。
 */
@Module({
  imports: [CryptoModule],
  controllers: [AuditOwnController, WatermarkController],
  providers: [
    AuditOwnService,
    AuditOwnValidators,
    AuditLogOwnService,
    WatermarkService,
    HardenerDetector,
    BangcleAdapter,
    HardenerEulaService,
  ],
  exports: [AuditOwnService, AuditLogOwnService, WatermarkService, HardenerEulaService],
})
export class AuditOwnModule {}
