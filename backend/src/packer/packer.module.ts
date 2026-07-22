import { Module } from '@nestjs/common';
import { PackerController } from './packer.controller';
import { PackerService } from './packer.service';
import { PackerValidators } from './packer-validators';
import { PackerLogService } from './packer-log.service';
import { DexInjector } from './dex-injector';
import { SoInjector } from './so-injector';
import { DefenderConfigGenerator } from './defender-config-generator';

/**
 * Packer 模块(ADR 0081)
 *
 * 提供:
 *  - POST /v1/packer/pack   自有 APK SDK 封装(七锁校验)
 *  - GET  /v1/packer/logs   封装历史
 *
 * 七锁架构(律师预审 2026-07-21 通过):
 *  锁 1 对象锁定(三重校验)
 *  锁 2 内容锁定(固定 dex SHA-256 白名单)
 *  锁 3 入口锁定(Manifest 修改范围)
 *  锁 4 签名锁定(自备 Keystore V1+V2+V3)
 *  锁 5 权限锁定(JWT 开发者自身)
 *  锁 6 数据锁定(OAID + 包信息,无敏感隐私)
 *  锁 7 客户端签名自检(PACKAGE_TAMPERED 拒启)
 */
@Module({
  controllers: [PackerController],
  providers: [
    PackerService,
    PackerValidators,
    PackerLogService,
    DexInjector,
    SoInjector,
    DefenderConfigGenerator,
  ],
  exports: [PackerService, PackerLogService],
})
export class PackerModule {}
