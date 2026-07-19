import { Module } from '@nestjs/common';
import { AuditOwnController } from './audit-own.controller';
import { AuditOwnService } from './audit-own.service';
import { AuditOwnValidators } from './audit-own-validators';
import { AuditLogOwnService } from './audit-log-own.service';

/**
 * 自有 APK 诊断模块(ADR 0077)
 *
 * 提供:
 *  - POST /v1/audit/analyze  诊断(只读)
 *  - POST /v1/audit/resign   签名回填(例外 A)
 *  - GET  /v1/audit/logs     诊断历史
 *
 * 三重校验强制(包名白名单 + 签名 hash 比对 + 目录隔离)。
 * 例外 B(梆梆适配器)待 ADR 0078 律师意见落地,本模块不涉及。
 */
@Module({
  controllers: [AuditOwnController],
  providers: [AuditOwnService, AuditOwnValidators, AuditLogOwnService],
  exports: [AuditOwnService, AuditLogOwnService],
})
export class AuditOwnModule {}
